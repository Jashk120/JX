use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use crypto::MembershipRegistry;
use ed25519_dalek::SigningKey;
use primitives::NodeId;
use tokio::net::{
    TcpListener,
    TcpStream,
};
use tokio::sync::Mutex;

use crate::error::{
    GossipError,
    Result,
};
use crate::frontier::delta_events;
use crate::peer::PeerInfo;
use crate::peer_manager::PeerManager;
use crate::proto::{
    Frame,
    SyncResponse,
};
use crate::sync::{
    insert_verified,
    run_sync,
};
use crate::tls::TlsIdentity;
use crate::transport::{
    SyncTransport,
    TcpTransport,
};

/// A JKain node: owns a hashgraph, a TLS identity, the known-peer table,
/// and the async machinery that runs gossip syncs on a fixed interval.
pub struct GossipNode {
    pub node_id: NodeId,
    pub hashgraph: Arc<Mutex<consensus::Hashgraph>>,
    signing_key: SigningKey,
    registry: MembershipRegistry,
    identity: TlsIdentity,
    peers: Mutex<PeerManager>,
    sync_interval: Duration,
    sync_timeout: Duration,
}

impl GossipNode {
    /// `peers` must not include this node itself; any self-entry is
    /// dropped. All members (including this node) must be registered in
    /// `registry` so their events can be verified and inserted.
    ///
    /// `sync_timeout` bounds how long a single sync round may block waiting
    /// for a peer that has gone silent, so a dead persistent connection is
    /// dropped and retried instead of stalling the driver forever.
    pub fn new(
        node_id: NodeId,
        signing_key: SigningKey,
        registry: MembershipRegistry,
        identity: TlsIdentity,
        peers: Vec<PeerInfo>,
        sync_interval: Duration,
        sync_timeout: Duration,
    ) -> Self {
        let peers: Vec<PeerInfo> =
            peers.into_iter().filter(|peer| peer.node_id != node_id).collect();
        let hashgraph = consensus::Hashgraph::new(&registry);
        Self {
            node_id,
            hashgraph: Arc::new(Mutex::new(hashgraph)),
            signing_key,
            registry,
            identity,
            peers: Mutex::new(PeerManager::new(peers)),
            sync_interval,
            sync_timeout,
        }
    }

    /// Runs the node: accepts inbound gossip connections and, every
    /// `sync_interval`, syncs with a uniform-random peer. Runs until the
    /// surrounding task is aborted.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.run_until_stopped(listener, Arc::new(AtomicBool::new(false))).await
    }

    /// Like [`Self::run`], but the sync driver stops once `stop` is set.
    /// The flag is polled at each loop boundary (never racing a
    /// notification), and an in-flight sync round is allowed to complete
    /// first — so after a short settle the node's hashgraph is quiescent,
    /// which lets tests compare exact state across nodes.
    pub async fn run_until_stopped(
        self: Arc<Self>,
        listener: TcpListener,
        stop: Arc<AtomicBool>,
    ) -> Result<()> {
        let _accept_task = tokio::spawn(self.clone().accept_loop(listener));

        let mut outbound: HashMap<NodeId, TcpTransport> = HashMap::new();
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(self.sync_interval).await;
            if stop.load(Ordering::Acquire) {
                break;
            }

            let peer = self.peers.lock().await.random_peer();
            let Some(peer) = peer else { continue };

            let transport = match outbound.entry(peer.node_id) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let mut transport = TcpTransport::new(self.identity.clone());
                    if transport.connect(&peer).await.is_err() {
                        continue;
                    }
                    entry.insert(transport)
                }
            };

            let round = tokio::time::timeout(
                self.sync_timeout,
                run_sync(
                    transport,
                    &self.hashgraph,
                    &self.registry,
                    self.node_id,
                    &self.signing_key,
                    peer.node_id,
                ),
            )
            .await;

            let round = match round {
                Ok(result) => result,
                Err(_) => Err(GossipError::Sync(format!(
                    "sync round with peer {peer:?} timed out after {:?}",
                    self.sync_timeout
                ))),
            };

            if round.is_err() {
                outbound.remove(&peer.node_id);
            }
        }
        Ok(())
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => continue,
            };
            tokio::spawn(self.clone().handle_inbound(stream));
        }
    }

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream) {
        let transport = TcpTransport::new(self.identity.clone());
        let acceptor = match transport.acceptor() {
            Ok(acceptor) => acceptor,
            Err(_) => return,
        };
        let tls = match acceptor.accept(stream).await {
            Ok(tls) => tls,
            Err(_) => return,
        };
        let mut transport = TcpTransport::from_tls_stream(self.identity.clone(), tls);

        loop {
            let frame = match transport.recv_frame().await {
                Ok(frame) => frame,
                Err(_) => return,
            };
            match frame {
                Frame::SyncRequest(request) => {
                    let events = {
                        let hashgraph = self.hashgraph.lock().await;
                        match delta_events(&hashgraph, &request.known) {
                            Ok(events) => events,
                            Err(_) => return,
                        }
                    };
                    let response = Frame::SyncResponse(SyncResponse { events });
                    if transport.send_frame(&response).await.is_err() {
                        return;
                    }
                }
                Frame::Event(event) => {
                    if insert_verified(&self.hashgraph, &self.registry, event).await.is_err() {
                        return;
                    }
                }
                Frame::SyncResponse(_) => return,
            }
        }
    }
}
