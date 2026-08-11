//! End-to-end tests spanning the whole stack: event creation (primitives +
//! crypto), gossip propagation (network + TLS), consensus ordering, and the
//! negative cases at each layer.
//!
//! These build on the same live localhost nodes as `gossip_integration.rs`,
//! but go further: they verify transaction payloads survive gossip, that
//! live clusters derive an identical finalized consensus order, and that
//! every failure mode (wrong TLS pin, forged event, malformed frame,
//! unreachable peer, protocol violations) is rejected or skipped without
//! taking a node down.

mod common;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use common::*;
use crypto::{
    Hashable,
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use gossip::{
    Frame,
    GossipError,
    GossipNode,
    PeerInfo,
    Result,
    SyncTransport,
    TcpTransport,
    TlsIdentity,
    run_sync,
};
use primitives::{
    EventHash,
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tokio::time::{
    sleep,
    timeout,
};

/// Upper bound on the rounds a live 4-node test can be expected to reach;
/// `consensus_order` is O(events), so scanning this window is cheap.
const MAX_ORDERED_ROUND: u64 = 32;

// --- E2E-specific helpers -------------------------------------------------------

/// Builds the shared member registry from the deterministic per-id seeds,
/// matching the registry `spawn_cluster` constructs internally.
fn registry_for_ids(ids: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in ids {
        let key = SigningKey::from_bytes(&consensus_seed(id));
        registry.register(NodeId::new(id), key.verifying_key());
    }
    registry
}

/// Waits (bounded) until `hash` appears in `node`'s hashgraph. The gossip
/// protocol sends an `Event` frame and returns without an acknowledgement, so
/// the receiving node may not have processed it yet when the sender's
/// `run_sync` completes — any assertion right after must poll instead.
async fn wait_for_event(node: &Arc<GossipNode>, hash: EventHash, deadline: Duration) {
    timeout(deadline, async {
        loop {
            if node.hashgraph.lock().await.get(&hash).is_some() {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("event appears in the node's hashgraph");
}

/// Establishes a raw (non-`TcpTransport`) TLS stream to `addr`, pinned to
/// `pin`, so a test can inject arbitrary bytes at the wire level.
async fn raw_tls_client(
    identity: TlsIdentity,
    addr: SocketAddr,
    pin: [u8; 32],
) -> Result<tokio_rustls::client::TlsStream<tokio::net::TcpStream>> {
    let config = identity.client_config(pin)?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let server_name =
        rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::from(addr.ip()));
    let stream = tokio::net::TcpStream::connect(addr).await?;
    Ok(connector.connect(server_name, stream).await?)
}

// --- Positive: the full stack -------------------------------------------------

#[tokio::test]
async fn transaction_events_propagate_with_payloads() {
    // Event creation → gossip → convergence, with payloads intact.
    let nodes = spawn_cluster(&[1, 2]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();
    let registry = registry_for_ids(&[1, 2]);

    // Let the cluster establish a self-parent chain, then insert the payload
    // events as the latest event of each creator so they are recent (and
    // hence retained) when we verify them.
    sleep(Duration::from_millis(300)).await;
    let payload = b"hello ledger".to_vec();
    let a1_latest = {
        let hashgraph = nodes[0].node.hashgraph.lock().await;
        hashgraph.latest_event_by(&NodeId::new(1)).copied()
    };
    let b1_latest = {
        let hashgraph = nodes[1].node.hashgraph.lock().await;
        hashgraph.latest_event_by(&NodeId::new(2)).copied()
    };
    let a1 = make_event_with_payload(
        &nodes[0].key,
        1,
        a1_latest,
        None,
        vec![Transaction::from_bytes(payload.clone())],
    );
    let a1_hash = insert_event(&nodes[0], &registry, a1).await;
    let b1 = make_event_with_payload(
        &nodes[1].key,
        2,
        b1_latest,
        None,
        vec![Transaction::from_bytes(payload.clone())],
    );
    let b1_hash = insert_event(&nodes[1], &registry, b1).await;

    // Verify the payloads as soon as they propagate to every node — pruning
    // only reaches these events once checkpoints are several rounds past
    // them, so the poll below always reads them before that happens.
    timeout(Duration::from_secs(10), async {
        loop {
            let mut all_present = true;
            for node in &refs {
                let hashgraph = node.node.hashgraph.lock().await;
                if hashgraph.get(&a1_hash).is_none() || hashgraph.get(&b1_hash).is_none() {
                    all_present = false;
                    break;
                }
            }
            if all_present {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("payload events propagate to every node");

    for node in &refs {
        let hashgraph = node.node.hashgraph.lock().await;
        for hash in [a1_hash, b1_hash] {
            let record = hashgraph.get(&hash).expect("injected event is present");
            let txs = record.event().payload();
            assert_eq!(txs.len(), 1, "payload must survive gossip byte-for-byte");
            assert_eq!(txs[0].payload(), payload.as_slice());
        }
    }
    drop_nodes(nodes);
}

#[tokio::test]
async fn live_cluster_finalizes_identical_consensus_order() {
    // Gossip → consensus ordering: every node must finalize the same
    // consensus order for the rounds it has decided, and that order must
    // respect parent/child roundReceived monotonicity.
    let nodes = spawn_cluster(&[1, 2, 3, 4]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();
    let (counts, lates) = stop_and_settle(&refs, Duration::from_secs(2)).await;
    assert_converged(&counts, &lates, "ordering");

    let mut rounds_by_node: Vec<Vec<Vec<EventHash>>> = Vec::new();
    let mut ordered_by_node: Vec<u64> = Vec::new();
    for node in &refs {
        let hashgraph = node.node.hashgraph.lock().await;
        // Rounds are not guaranteed to be populated contiguously from 1: a
        // round is processed as soon as its fame election is decided, but
        // may legitimately assign zero events (e.g. round 1, when no event
        // is a common descendant of all its famous witnesses). So collect
        // every non-empty round rather than stopping at the first empty one.
        let mut rounds = Vec::new();
        for round in 1..=MAX_ORDERED_ROUND {
            let events = hashgraph.consensus_order(round);
            if !events.is_empty() {
                rounds.push(events);
            }
        }
        ordered_by_node.push(rounds.iter().map(|r| r.len() as u64).sum());
        rounds_by_node.push(rounds);
    }

    let min_finalized = rounds_by_node.iter().map(Vec::len).min().expect("at least one node");
    assert!(min_finalized >= 1, "no node ordered a single event: ordered={ordered_by_node:?}");

    for round in 0..min_finalized {
        let baseline = &rounds_by_node[0][round];
        for node_rounds in &rounds_by_node[1..] {
            assert_eq!(
                node_rounds[round],
                *baseline,
                "consensus order for round {} differs across nodes",
                round + 1
            );
        }
    }

    // Per-node ordering invariants: every ordered event reports its round,
    // and a parent is never ordered after its child.
    for node in &refs {
        let hashgraph = node.node.hashgraph.lock().await;
        for round in 1..=MAX_ORDERED_ROUND {
            let events = hashgraph.consensus_order(round);
            if events.is_empty() {
                continue;
            }
            for hash in events {
                let record = hashgraph.get(&hash).expect("ordered event is present");
                assert_eq!(
                    record.round_received(),
                    Some(round),
                    "event reports its ordering round"
                );
                for parent in [record.event().self_parent(), record.event().other_parent()]
                    .into_iter()
                    .flatten()
                {
                    let parent_record = hashgraph.get(parent).expect("parent is present");
                    if let Some(parent_round) = parent_record.round_received() {
                        assert!(
                            parent_round <= round,
                            "parent {parent:?} ordered after child {hash:?}"
                        );
                    }
                }
            }
        }
    }
    drop_nodes(nodes);
}

// --- Negative: transport and protocol -----------------------------------------

#[tokio::test]
async fn wrong_spki_fingerprint_blocks_sync() {
    // A node pinned to the wrong SPKI fingerprint must not complete the TLS
    // handshake, while the correct pin still connects.
    let registry = registry_for_ids(&[1, 2]);

    let listener = bind_ephemeral().await;
    let addr = listener.local_addr().expect("local addr");
    let identity2 = TlsIdentity::from_seed(tls_seed(2), 2).expect("identity");
    let node = Arc::new(GossipNode::new(
        NodeId::new(2),
        SigningKey::from_bytes(&consensus_seed(2)),
        registry,
        identity2.clone(),
        Vec::new(),
        SYNC_INTERVAL,
        SYNC_TIMEOUT,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let spawn = node.clone();
    let stop_handle = stop.clone();
    let handle = tokio::spawn(async move {
        let _ = spawn.run_until_stopped(listener, stop_handle).await;
    });

    let identity1 = TlsIdentity::from_seed(tls_seed(1), 1).expect("identity");
    let mut transport = TcpTransport::new(identity1);
    let wrong_pin = [0u8; 32];
    let peer = PeerInfo::new(NodeId::new(2), addr, wrong_pin);
    assert!(transport.connect(&peer).await.is_err(), "mispinned handshake must fail");

    let mut transport =
        TcpTransport::new(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"));
    let peer = PeerInfo::new(NodeId::new(2), addr, identity2.spki_fingerprint());
    assert!(transport.connect(&peer).await.is_ok(), "correctly pinned handshake must succeed");

    stop.store(true, Ordering::Release);
    let _ = handle.await;
}

#[tokio::test]
async fn malformed_frame_over_wire_does_not_crash_node() {
    // Unknown message tags and truncated frames must be rejected at the
    // frame layer, drop that connection, and leave the node able to serve a
    // normal sync afterward.
    let registry = registry_for_ids(&[1, 2]);

    let listener = bind_ephemeral().await;
    let addr = listener.local_addr().expect("local addr");
    let identity2 = TlsIdentity::from_seed(tls_seed(2), 2).expect("identity");
    let node = Arc::new(GossipNode::new(
        NodeId::new(2),
        SigningKey::from_bytes(&consensus_seed(2)),
        registry_for_ids(&[1, 2]),
        identity2.clone(),
        Vec::new(),
        SYNC_INTERVAL,
        SYNC_TIMEOUT,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let spawn = node.clone();
    let stop_handle = stop.clone();
    let handle = tokio::spawn(async move {
        let _ = spawn.run_until_stopped(listener, stop_handle).await;
    });
    let pin = identity2.spki_fingerprint();

    // Unknown message tag (0xFF).
    let mut raw =
        raw_tls_client(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"), addr, pin)
            .await
            .expect("raw TLS");
    raw.write_all(&[0xFF, 0x00, 0x00, 0x00, 0x00]).await.expect("write");
    raw.shutdown().await.expect("shutdown");

    // Truncated frame: a valid header promising 64 payload bytes, then EOF.
    let mut raw =
        raw_tls_client(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"), addr, pin)
            .await
            .expect("raw TLS");
    raw.write_all(&[0x02, 0x00, 0x00, 0x00, 0x40]).await.expect("write");
    raw.shutdown().await.expect("shutdown");

    // A well-behaved sync on a fresh connection must still succeed and
    // propagate the honest client's event.
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let client_hashgraph = Arc::new(Mutex::new(consensus::Hashgraph::new(&registry)));
    let mut client = TcpTransport::new(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"));
    let peer = PeerInfo::new(NodeId::new(2), addr, pin);
    client.connect(&peer).await.expect("connect");
    run_sync(&mut client, &client_hashgraph, &registry, NodeId::new(1), &key1, NodeId::new(2))
        .await
        .expect("sync after malformed input");

    let client_latest = client_hashgraph
        .lock()
        .await
        .latest_event_by(&NodeId::new(1))
        .copied()
        .expect("client created an event");
    wait_for_event(&node, client_latest, Duration::from_secs(5)).await;

    stop.store(true, Ordering::Release);
    let _ = handle.await;
}

// --- Negative: event verification and consensus gates --------------------------

#[tokio::test]
async fn tampered_signature_event_rejected_over_wire() {
    // A well-framed Event whose signature does not match its content must
    // be dropped by the receiving node (which also drops the connection),
    // never stored, and must not take the node down.
    let registry = registry_for_ids(&[1, 2]);

    let listener = bind_ephemeral().await;
    let addr = listener.local_addr().expect("local addr");
    let identity2 = TlsIdentity::from_seed(tls_seed(2), 2).expect("identity");
    let node = Arc::new(GossipNode::new(
        NodeId::new(2),
        SigningKey::from_bytes(&consensus_seed(2)),
        registry_for_ids(&[1, 2]),
        identity2.clone(),
        Vec::new(),
        SYNC_INTERVAL,
        SYNC_TIMEOUT,
    ));
    let stop = Arc::new(AtomicBool::new(false));
    let spawn = node.clone();
    let stop_handle = stop.clone();
    let handle = tokio::spawn(async move {
        let _ = spawn.run_until_stopped(listener, stop_handle).await;
    });

    let unsigned = UnsignedEvent::new(
        NodeId::new(1),
        None,
        None,
        Timestamp::new(now_millis()),
        vec![Transaction::from_bytes(b"forged".to_vec())],
    );
    let forged = unsigned.finalize(Signature::new([0x42; 64]));
    let forged_hash = forged.hash();

    let mut attacker = TcpTransport::new(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"));
    let peer = PeerInfo::new(NodeId::new(2), addr, identity2.spki_fingerprint());
    attacker.connect(&peer).await.expect("connect");
    attacker.send_frame(&Frame::Event(forged)).await.expect("send forged event");
    drop(attacker);

    // The node survived and still serves a well-behaved sync.
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let client_hashgraph = Arc::new(Mutex::new(consensus::Hashgraph::new(&registry)));
    let mut client = TcpTransport::new(TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"));
    let peer = PeerInfo::new(NodeId::new(2), addr, identity2.spki_fingerprint());
    client.connect(&peer).await.expect("connect");
    run_sync(&mut client, &client_hashgraph, &registry, NodeId::new(1), &key1, NodeId::new(2))
        .await
        .expect("sync after forged event");

    let hashgraph = node.hashgraph.lock().await;
    assert!(hashgraph.get(&forged_hash).is_none(), "forged event must never be stored");
    drop(hashgraph);
    let client_latest = client_hashgraph
        .lock()
        .await
        .latest_event_by(&NodeId::new(1))
        .copied()
        .expect("client created an event");
    wait_for_event(&node, client_latest, Duration::from_secs(5)).await;

    stop.store(true, Ordering::Release);
    let _ = handle.await;
}

#[tokio::test]
async fn unknown_creator_event_rejected() {
    // An event signed by a key that is not in the membership registry must
    // fail verification and therefore can never enter a hashgraph.
    let registry = registry_for_ids(&[1]);
    let rogue = SigningKey::from_bytes(&[0x99; 32]);
    let event =
        UnsignedEvent::new(NodeId::new(99), None, None, Timestamp::new(now_millis()), Vec::new())
            .sign(&rogue);
    assert!(event.verify(&registry).is_err(), "unregistered creator must not verify");
}

#[tokio::test]
async fn missing_parent_event_rejected() {
    // A correctly signed event whose parent is not in the graph is rejected
    // by the consensus insert gate: no event can ever dangle.
    let registry = registry_for_ids(&[1]);
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let missing = EventHash::new([9; 32]);
    let event = UnsignedEvent::new(
        NodeId::new(1),
        Some(missing),
        None,
        Timestamp::new(now_millis()),
        Vec::new(),
    )
    .sign(&key1);
    let verified = event.verify(&registry).expect("signature is valid");
    let mut hashgraph = consensus::Hashgraph::new(&registry);
    assert_eq!(hashgraph.insert(verified), Err(consensus::ConsensusError::MissingParent(missing)));
}

#[tokio::test]
async fn duplicate_event_insert_is_noop() {
    // The consensus layer treats a second insert of the same event as
    // AlreadyPresent (the gossip layer maps that to a benign no-op), so
    // redundant syncs and concurrent deliveries are safe.
    let registry = registry_for_ids(&[1]);
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let event =
        UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(now_millis()), Vec::new())
            .sign(&key1);
    let hash = event.hash();
    let verified = event.verify(&registry).expect("signature is valid");
    let mut hashgraph = consensus::Hashgraph::new(&registry);
    hashgraph.insert(verified.clone()).expect("first insert");
    assert_eq!(hashgraph.insert(verified), Err(consensus::ConsensusError::AlreadyPresent(hash)));
}

#[tokio::test]
async fn unexpected_frame_type_fails_run_sync() {
    // A peer that answers a SyncRequest with anything but a SyncResponse is
    // a protocol violation; the initiator must surface it as an error rather
    // than mis-parse the exchange.
    let registry = registry_for_ids(&[1, 2]);
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let hashgraph = Arc::new(Mutex::new(consensus::Hashgraph::new(&registry)));
    let rogue = Frame::Event(
        UnsignedEvent::new(NodeId::new(2), None, None, Timestamp::new(now_millis()), Vec::new())
            .sign(&SigningKey::from_bytes(&consensus_seed(2))),
    );

    let mut transport = ResponseForbidden { frames: VecDeque::from([rogue]) };
    let result =
        run_sync(&mut transport, &hashgraph, &registry, NodeId::new(1), &key1, NodeId::new(2))
            .await;
    assert!(matches!(
        result,
        Err(GossipError::UnexpectedFrame { expected: "SyncResponse", got: "Event" })
    ));
}

// --- Negative: peer selection ---------------------------------------------------

#[tokio::test]
async fn unreachable_peer_is_skipped_gracefully() {
    // A dead peer in the address book must be skipped each round (not hang
    // the driver or crash the node), and the remaining peers still gossip to
    // convergence.
    let dead_listener = bind_ephemeral().await;
    let dead_addr = dead_listener.local_addr().expect("local addr");
    drop(dead_listener); // nothing listens on this address anymore

    let keys = vec![
        (1, SigningKey::from_bytes(&consensus_seed(1))),
        (2, SigningKey::from_bytes(&consensus_seed(2))),
    ];

    let listener_a = bind_ephemeral().await;
    let listener_b = bind_ephemeral().await;
    let addrs = [
        listener_a.local_addr().expect("local addr"),
        listener_b.local_addr().expect("local addr"),
    ];
    let identities = [
        TlsIdentity::from_seed(tls_seed(1), 1).expect("identity"),
        TlsIdentity::from_seed(tls_seed(2), 2).expect("identity"),
    ];

    let peers_a = vec![
        PeerInfo::new(NodeId::new(2), addrs[1], identities[1].spki_fingerprint()),
        PeerInfo::new(NodeId::new(3), dead_addr, [0u8; 32]),
    ];
    let peers_b = vec![PeerInfo::new(NodeId::new(1), addrs[0], identities[0].spki_fingerprint())];

    let node_a = Arc::new(GossipNode::new(
        NodeId::new(1),
        keys[0].1.clone(),
        registry_for(&keys),
        identities[0].clone(),
        peers_a,
        SYNC_INTERVAL,
        SYNC_TIMEOUT,
    ));
    let node_b = Arc::new(GossipNode::new(
        NodeId::new(2),
        keys[1].1.clone(),
        registry_for(&keys),
        identities[1].clone(),
        peers_b,
        SYNC_INTERVAL,
        SYNC_TIMEOUT,
    ));

    let stop_a = Arc::new(AtomicBool::new(false));
    let stop_b = Arc::new(AtomicBool::new(false));
    let a = TestNode {
        key: keys[0].1.clone(),
        node: node_a.clone(),
        stop: stop_a.clone(),
        handle: tokio::spawn(async move {
            let _ = node_a.clone().run_until_stopped(listener_a, stop_a).await;
        }),
    };
    let b = TestNode {
        key: keys[1].1.clone(),
        node: node_b.clone(),
        stop: stop_b.clone(),
        handle: tokio::spawn(async move {
            let _ = node_b.clone().run_until_stopped(listener_b, stop_b).await;
        }),
    };

    let (counts, lates) = stop_and_settle(&[&a, &b], Duration::from_millis(800)).await;
    assert_converged(&counts, &lates, "with unreachable peer");
    drop_nodes(vec![a, b]);
}

// --- Stub transport for protocol-violation tests --------------------------------

/// A `SyncTransport` that answers `run_sync`'s request with a fixed queue of
/// frames, so a test can feed protocol violations without a real network.
struct ResponseForbidden {
    frames: VecDeque<Frame>,
}

impl SyncTransport for ResponseForbidden {
    async fn connect(&mut self, _peer: &PeerInfo) -> Result<()> {
        Ok(())
    }

    async fn send_frame(&mut self, _frame: &Frame) -> Result<()> {
        Ok(())
    }

    async fn recv_frame(&mut self) -> Result<Frame> {
        self.frames.pop_front().ok_or(GossipError::Closed)
    }

    fn is_connected(&self) -> bool {
        true
    }
}
