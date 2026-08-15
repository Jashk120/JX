//! Shared helpers for the `node` crate's end-to-end tests: a two-node local
//! cluster with reconnect servers, plus wait helpers over executor state.
//!
//! Shared by several test binaries that do not all use every helper, hence
//! the crate-level `dead_code` allowance (same pattern as `gossip`'s
//! `tests/common`).
#![allow(dead_code)]

use std::net::{
    IpAddr,
    Ipv4Addr,
    SocketAddr,
};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use crypto::MembershipRegistry;
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    PeerInfo,
    SyncTiming,
    TlsIdentity,
};
use primitives::NodeId;
use state::StateDb;
use tokio::net::TcpListener;
use tokio::time::{
    sleep,
    timeout,
};

pub const SYNC_INTERVAL: Duration = Duration::from_millis(25);
pub const SYNC_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEADLINE: Duration = Duration::from_secs(30);

/// A fresh `StateDb` in a tempdir — the test stand-in for `<data>/statedb/`.
pub fn temp_state_db() -> Arc<StateDb> {
    let dir = tempfile::tempdir().expect("temp dir");
    Arc::new(StateDb::open(dir.path()).expect("state db opens"))
}

pub fn consensus_seed(id: u64) -> [u8; 32] {
    [id as u8; 32]
}

pub fn tls_seed(id: u64) -> [u8; 32] {
    [0x40 + id as u8; 32]
}

pub fn registry_for(ids: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in ids {
        registry
            .register(NodeId::new(id), SigningKey::from_bytes(&consensus_seed(id)).verifying_key());
    }
    registry
}

pub struct TestNode {
    pub node: Arc<GossipNode>,
    pub stop: Arc<AtomicBool>,
    pub handle: tokio::task::JoinHandle<()>,
}

impl TestNode {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Bound listeners plus derived addresses/identities for a cluster, so a
/// test can spawn (and later re-spawn) nodes on the same addresses.
pub struct ClusterNet {
    pub ids: Vec<u64>,
    pub gossip_listeners: Vec<TcpListener>,
    pub reconnect_listeners: Vec<TcpListener>,
    pub gossip_addrs: Vec<SocketAddr>,
    pub reconnect_addrs: Vec<SocketAddr>,
    pub identities: Vec<TlsIdentity>,
    pub state_dbs: Vec<Arc<StateDb>>,
}

impl ClusterNet {
    /// The `PeerInfo` list for the node at `index`, excluding itself.
    pub fn peers_for(&self, index: usize) -> Vec<PeerInfo> {
        self.ids
            .iter()
            .enumerate()
            .filter(|&(j, _)| j != index)
            .map(|(j, &peer_id)| {
                PeerInfo::new(
                    NodeId::new(peer_id),
                    self.gossip_addrs[j],
                    self.identities[j].spki_fingerprint(),
                )
                .with_reconnect(self.reconnect_addrs[j])
            })
            .collect()
    }
}

/// Binds ephemeral gossip + reconnect listeners for every id and derives the
/// network description (addresses, identities).
pub async fn net_for(ids: &[u64]) -> ClusterNet {
    let mut gossip_listeners = Vec::new();
    let mut reconnect_listeners = Vec::new();
    for _ in ids {
        gossip_listeners.push(bind_ephemeral().await);
        reconnect_listeners.push(bind_ephemeral().await);
    }
    let gossip_addrs: Vec<SocketAddr> =
        gossip_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let reconnect_addrs: Vec<SocketAddr> =
        reconnect_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let identities: Vec<TlsIdentity> =
        ids.iter().map(|&id| TlsIdentity::from_seed(tls_seed(id), id).expect("identity")).collect();
    let state_dbs: Vec<Arc<StateDb>> = ids.iter().map(|_| temp_state_db()).collect();
    ClusterNet {
        ids: ids.to_vec(),
        gossip_listeners,
        reconnect_listeners,
        gossip_addrs,
        reconnect_addrs,
        identities,
        state_dbs,
    }
}

/// Builds a `GossipNode` for `id` at `net` index `index` (fresh genesis).
pub fn fresh_node(net: &ClusterNet, index: usize) -> Arc<GossipNode> {
    let id = net.ids[index];
    Arc::new(GossipNode::new(
        NodeId::new(id),
        SigningKey::from_bytes(&consensus_seed(id)),
        registry_for(&net.ids),
        net.identities[index].clone(),
        net.peers_for(index),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        net.state_dbs[index].clone(),
    ))
}

/// Spawns a cluster of `ids`, each with its own gossip + reconnect listeners,
/// running with the reconnect server enabled. Returns the nodes and the
/// network info used to spawn them.
pub async fn spawn_cluster(ids: &[u64]) -> (Vec<TestNode>, ClusterNet) {
    let mut net = net_for(ids).await;
    let mut nodes = Vec::new();
    for index in 0..ids.len() {
        let node = fresh_node(&net, index);
        let gossip_listener = net.gossip_listeners.remove(0);
        let reconnect_listener = net.reconnect_listeners.remove(0);
        let stop = Arc::new(AtomicBool::new(false));
        let spawn_node = node.clone();
        let stop_handle = stop.clone();
        let handle = tokio::spawn(async move {
            let _ = spawn_node
                .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
                .await;
        });
        nodes.push(TestNode { node, stop, handle });
    }
    (nodes, net)
}

pub async fn bind_ephemeral() -> TcpListener {
    TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.expect("bind")
}

/// Waits until `node`'s executor state has `key`, returning its value.
pub async fn wait_for_state(node: &GossipNode, key: &[u8], deadline: Duration) -> Option<Vec<u8>> {
    timeout(deadline, async {
        loop {
            let state = node.executor_state().await;
            if let Some(value) = state.get(key) {
                return Some(value);
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("executor state reaches the submitted key")
}

/// Waits until `node` has accepted a checkpoint (quorum-signed) at round
/// `min_round`, returning that round.
pub async fn wait_for_checkpoint(node: &GossipNode, min_round: u64, deadline: Duration) -> u64 {
    timeout(deadline, async {
        loop {
            if let Some(round) = node.latest_accepted_checkpoint_round().await
                && round >= min_round
            {
                return round;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("node accepts a checkpoint")
}

pub fn drop_nodes(nodes: Vec<TestNode>) {
    for node in nodes {
        node.handle.abort();
    }
}
