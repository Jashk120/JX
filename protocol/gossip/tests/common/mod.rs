//! Shared helpers for the gossip integration and end-to-end test suites.

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

use crypto::{
    Hashable,
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    PeerInfo,
    TlsIdentity,
};
use primitives::{
    Event,
    EventHash,
    NodeId,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use tokio::net::TcpListener;
use tokio::time::{
    sleep,
    timeout,
};

pub const SYNC_INTERVAL: Duration = Duration::from_millis(25);
pub const SYNC_TIMEOUT: Duration = Duration::from_millis(500);
pub const DEADLINE: Duration = Duration::from_secs(15);

pub fn consensus_seed(id: u64) -> [u8; 32] {
    [id as u8; 32]
}

pub fn tls_seed(id: u64) -> [u8; 32] {
    [0x40 + id as u8; 32]
}

pub async fn bind_ephemeral() -> TcpListener {
    TcpListener::bind((IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await.expect("bind")
}

pub fn registry_for(keys: &[(u64, SigningKey)]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &(id, ref key) in keys {
        registry.register(NodeId::new(id), key.verifying_key());
    }
    registry
}

pub struct TestNode {
    pub key: SigningKey,
    pub node: Arc<GossipNode>,
    pub stop: Arc<AtomicBool>,
    pub handle: tokio::task::JoinHandle<()>,
}

impl TestNode {
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// Spawns `ids.len()` nodes, each listening on its own ephemeral port, and
/// returns them. The registry is shared so every node can verify any
/// member's events.
pub async fn spawn_cluster(ids: &[u64]) -> Vec<TestNode> {
    let keys: Vec<(u64, SigningKey)> =
        ids.iter().map(|&id| (id, SigningKey::from_bytes(&consensus_seed(id)))).collect();

    let mut listeners = Vec::new();
    for _ in 0..ids.len() {
        listeners.push(bind_ephemeral().await);
    }
    let addrs: Vec<SocketAddr> =
        listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let identities: Vec<TlsIdentity> =
        ids.iter().map(|&id| TlsIdentity::from_seed(tls_seed(id), id).expect("identity")).collect();

    let mut nodes = Vec::new();
    for (index, (listener, &id)) in listeners.into_iter().zip(ids).enumerate() {
        let key = SigningKey::from_bytes(&consensus_seed(id));
        let peers: Vec<PeerInfo> = (0..ids.len())
            .filter(|&j| j != index)
            .map(|j| PeerInfo::new(NodeId::new(ids[j]), addrs[j], identities[j].spki_fingerprint()))
            .collect();

        let node = Arc::new(GossipNode::new(
            NodeId::new(id),
            key.clone(),
            registry_for(&keys),
            identities[index].clone(),
            peers,
            SYNC_INTERVAL,
            SYNC_TIMEOUT,
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let spawn_node = node.clone();
        let stop_handle = stop.clone();
        let handle = tokio::spawn(async move {
            let _ = spawn_node.run_until_stopped(listener, stop_handle).await;
        });
        nodes.push(TestNode { key, node, stop, handle });
    }
    nodes
}

/// Lets the cluster gossip for `warmup`, stops every node's sync driver,
/// and waits for in-flight syncs to settle. Returns per-node event counts
/// and per-node latest seq per creator.
///
/// Note: because a node creates a new event every sync interval, a live
/// cluster's snapshots are never momentarily identical — there is always an
/// in-flight window of the newest few events. So convergence is asserted as
/// "no islands" (every node holds events from every creator) plus a small,
/// bounded count gap, rather than exact set equality.
pub async fn stop_and_settle(
    nodes: &[&TestNode],
    warmup: Duration,
) -> (Vec<usize>, Vec<Vec<Option<u64>>>) {
    sleep(warmup).await;
    for node in nodes {
        node.stop();
    }
    timeout(DEADLINE, async {
        let mut last_counts = Vec::new();
        loop {
            let mut counts = Vec::new();
            let mut lates = Vec::new();
            for node in nodes {
                let hashgraph = node.node.hashgraph.lock().await;
                counts.push(hashgraph.all_event_hashes().len());
                let per_creator: Vec<Option<u64>> = (1..=nodes.len() as u64)
                    .map(|id| {
                        hashgraph
                            .latest_event_by(&NodeId::new(id))
                            .and_then(|h| hashgraph.get(h))
                            .map(|record| record.seq())
                    })
                    .collect();
                lates.push(per_creator);
            }
            if counts == last_counts {
                return (counts, lates);
            }
            last_counts = counts;
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("nodes quiesce")
}

pub fn assert_converged(counts: &[usize], lates: &[Vec<Option<u64>>], label: &str) {
    let no_island = lates
        .iter()
        .all(|per_creator| per_creator.iter().all(|seq| seq.is_some_and(|value| value > 0)));
    let min = counts.iter().copied().min().unwrap_or(0);
    let max = counts.iter().copied().max().unwrap_or(0);
    let bound = 2 * (counts.len().saturating_sub(1));
    let gap_ok = max.saturating_sub(min) <= bound;
    eprintln!(
        "[{label}] counts={counts:?} latest_per_creator={lates:?} no_island={no_island} gap={}/{bound}",
        max.saturating_sub(min)
    );
    assert!(no_island, "[{label}] a node is missing an entire creator's events");
    assert!(gap_ok, "[{label}] nodes are too far apart ({min}..{max}, bound {bound})");
}

pub fn drop_nodes(nodes: Vec<TestNode>) {
    for node in nodes {
        node.handle.abort();
    }
}

/// Builds a signed event carrying `payload` for the given creator.
pub fn make_event_with_payload(
    key: &SigningKey,
    creator_id: u64,
    self_parent: Option<EventHash>,
    other_parent: Option<EventHash>,
    payload: Vec<Transaction>,
) -> Event {
    UnsignedEvent::new(
        NodeId::new(creator_id),
        self_parent,
        other_parent,
        Timestamp::new(now_millis()),
        payload,
    )
    .sign(key)
}

/// Inserts an already-signed event directly into one node's hashgraph,
/// simulating state the node holds that its peers have never seen
/// (partition). Returns the event's hash.
pub async fn insert_event(
    node: &TestNode,
    registry: &MembershipRegistry,
    event: Event,
) -> EventHash {
    let hash = event.hash();
    let verified = event.verify(registry).expect("valid signature");
    let mut hashgraph = node.node.hashgraph.lock().await;
    hashgraph.insert(verified).expect("insert");
    hash
}

pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
