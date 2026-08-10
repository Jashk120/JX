use std::collections::hash_map::Entry;
use std::collections::{
    BTreeMap,
    HashMap,
};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use crypto::{
    Hashable,
    MembershipOp,
    MembershipRegistry,
};
use ed25519_dalek::{
    SigningKey,
    VerifyingKey,
};
use primitives::{
    Event,
    NodeId,
};
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

/// The membership-op activation queue plus the processed-event watermark.
///
/// Both live under one `Mutex` so the watermark and the pending queue advance
/// together atomically: a concurrent `process_finalized_rounds` can never
/// skip events whose ops have not been bucketed yet.
#[derive(Default)]
struct ActivationState {
    pending: BTreeMap<u64, Vec<MembershipOp>>,
    processed_through_round: u64,
}

/// A JKain node: owns a hashgraph, a TLS identity, the known-peer table,
/// and the async machinery that runs gossip syncs on a fixed interval.
pub struct GossipNode {
    pub node_id: NodeId,
    pub hashgraph: Arc<Mutex<consensus::Hashgraph>>,
    signing_key: SigningKey,
    registry: Mutex<MembershipRegistry>,
    identity: TlsIdentity,
    peers: Mutex<PeerManager>,
    sync_interval: Duration,
    sync_timeout: Duration,
    executor: Mutex<state::Executor>,
    activation: Mutex<ActivationState>,
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
            registry: Mutex::new(registry),
            identity,
            peers: Mutex::new(PeerManager::new(peers)),
            sync_interval,
            sync_timeout,
            executor: Mutex::new(state::Executor::new()),
            activation: Mutex::new(ActivationState::default()),
        }
    }

    /// Whether `node` is a registered member of this node's hashgraph.
    pub async fn is_consensus_member(&self, node: NodeId) -> bool {
        let hg = self.hashgraph.lock().await;
        hg.is_member(&node)
    }

    /// The number of known peers (observability helper).
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
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

            let registry = self.registry.lock().await.clone();
            let round = tokio::time::timeout(
                self.sync_timeout,
                run_sync(
                    transport,
                    &self.hashgraph,
                    &registry,
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

            // Decode newly finalized events and drive any membership
            // activations that are now safe to apply.
            self.process_finalized_rounds().await;
        }
        Ok(())
    }

    /// Decodes every newly finalized event's payload, buckets membership ops
    /// by `roundReceived`, and activates any whose activation round is now
    /// fully decided. Called after each sync round, regardless of whether the
    /// sync itself succeeded.
    ///
    /// Activation round = `roundReceived + 1`, and activation fires only once
    /// that round is fully decided — the same finality notion `order.rs` uses
    /// to produce finalized order — so node 4 is never admitted into a
    /// round whose fame elections are still running under the old roster.
    /// The new roster first applies to `activation_round + 1`.
    ///
    /// Lock discipline: Phase A collects all needed data under the hashgraph
    /// lock alone; Phase B holds only the executor + activation locks; Phase C
    /// touches each store with its own short lock and never holds two at
    /// once. This eliminates the deadlock hazard of acquiring `hg`,
    /// `registry`, and `peers` in nested order.
    pub async fn process_finalized_rounds(&self) {
        // Phase A: collect (event, round_received) pairs under the hg lock only.
        let finalized: Vec<(Event, u64)> = {
            let hg = self.hashgraph.lock().await;
            state::finalized_events(&hg)
                .into_iter()
                .filter_map(|event| {
                    let hash = event.hash();
                    hg.round_received(&hash).map(|rr| (event, rr))
                })
                .collect()
        };
        if finalized.is_empty() {
            return;
        }

        // Phase B: decode ops and bucket by roundReceived; advance the
        // watermark so the next call over the same batch is a no-op.
        {
            let mut activation = self.activation.lock().await;
            let ActivationState { pending, processed_through_round } = &mut *activation;
            let mut executor = self.executor.lock().await;
            executor.bucket_finalized(pending, processed_through_round, &finalized);
        }

        // Phase C: activate ops whose activation round is now fully decided.
        let candidate_rrs: Vec<u64> = {
            let activation = self.activation.lock().await;
            activation.pending.keys().copied().collect()
        };

        for rr in candidate_rrs {
            let activation_round = rr + 1;
            let is_decided = {
                let hg = self.hashgraph.lock().await;
                hg.is_round_decided(activation_round)
            };
            if !is_decided {
                continue;
            }

            let ops = {
                let mut activation = self.activation.lock().await;
                activation.pending.remove(&rr).unwrap_or_default()
            };

            for op in ops {
                if let MembershipOp::Add { node, key, addr } = op {
                    let already_member = {
                        let hg = self.hashgraph.lock().await;
                        hg.is_member(&node)
                    };
                    if already_member {
                        continue;
                    }

                    let key: VerifyingKey = *key;
                    // Build the post-join registry from the roster active at
                    // the activation round (which still excludes the new node).
                    let mut new_registry = {
                        let hg = self.hashgraph.lock().await;
                        hg.registry_at_round(activation_round)
                    };
                    new_registry.register(node, key);

                    // Atomic: structural growth + roster schedule in one call.
                    {
                        let mut hg = self.hashgraph.lock().await;
                        hg.add_member(node, activation_round, new_registry);
                    }

                    // Keep the event-verification registry in sync so the new
                    // node's events can be verified and inserted.
                    {
                        let mut registry = self.registry.lock().await;
                        registry.register(node, key);
                    }

                    // TLS-pin the new peer, deriving the fingerprint from its
                    // Ed25519 key (same derivation as boot-time peers).
                    {
                        let mut pm = self.peers.lock().await;
                        pm.add_peer_from_key(node, &key, addr);
                    }
                }
            }
        }
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
                    let registry = self.registry.lock().await.clone();
                    if insert_verified(&self.hashgraph, &registry, event).await.is_err() {
                        return;
                    }
                }
                Frame::SyncResponse(_) => return,
            }
        }
    }
}
