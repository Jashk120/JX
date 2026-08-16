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

use std::collections::{
    HashMap,
    HashSet,
    VecDeque,
};
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
use ed25519_dalek::{
    Signer,
    SigningKey,
};
use gossip::{
    Frame,
    GossipError,
    GossipNode,
    PeerInfo,
    Result,
    SyncTiming,
    SyncTransport,
    TcpTransport,
    TlsIdentity,
    fetch_checkpoint,
    run_sync,
};
use primitives::{
    Event,
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

    // Each node accepts checkpoints at its own pace and prunes history
    // below its own latest checkpoint, so the surviving round vectors are
    // NOT index-aligned across nodes: index 0 on one node may be round 2
    // while another still holds round 1. Align on the round number rather
    // than the vector position, and only compare rounds a node still holds.
    let baseline_by_round: Vec<(u64, Vec<EventHash>)> = {
        let hashgraph = nodes[0].node.hashgraph.lock().await;
        (1..=MAX_ORDERED_ROUND)
            .map(|round| (round, hashgraph.consensus_order(round)))
            .filter(|(_, order)| !order.is_empty())
            .collect()
    };
    for (round, baseline) in &baseline_by_round {
        for node in &refs[1..] {
            let this_node_round = {
                let hashgraph = node.node.hashgraph.lock().await;
                hashgraph.consensus_order(*round)
            };
            if this_node_round.is_empty() {
                continue; // this node pruned the round; nothing to compare
            }
            assert_eq!(
                this_node_round, *baseline,
                "consensus order for round {round} differs across nodes"
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
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
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
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
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
    run_sync(
        &mut client,
        &client_hashgraph,
        &registry,
        NodeId::new(1),
        &key1,
        NodeId::new(2),
        Vec::new(),
    )
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
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
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
    run_sync(
        &mut client,
        &client_hashgraph,
        &registry,
        NodeId::new(1),
        &key1,
        NodeId::new(2),
        Vec::new(),
    )
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
    let result = run_sync(
        &mut transport,
        &hashgraph,
        &registry,
        NodeId::new(1),
        &key1,
        NodeId::new(2),
        Vec::new(),
    )
    .await;
    assert!(matches!(
        result,
        Err(GossipError::UnexpectedFrame { expected: "SyncResponse", got: "Event" })
    ));
}

#[tokio::test]
async fn behind_frame_surfaces_as_reconnect_error() {
    // Phase 4: a peer that has pruned the history this node needs answers a
    // SyncRequest with `Behind`. run_sync must surface it as a reconnect
    // error, which is what drives `needs_reconnect`.
    let registry = registry_for_ids(&[1, 2]);
    let key1 = SigningKey::from_bytes(&consensus_seed(1));
    let hashgraph = Arc::new(Mutex::new(consensus::Hashgraph::new(&registry)));

    let mut transport = ResponseForbidden { frames: VecDeque::from([Frame::Behind]) };
    let result = run_sync(
        &mut transport,
        &hashgraph,
        &registry,
        NodeId::new(1),
        &key1,
        NodeId::new(2),
        Vec::new(),
    )
    .await;
    assert!(
        matches!(result, Err(GossipError::Reconnect(_))),
        "Behind must surface as a reconnect error, got {result:?}"
    );
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
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));
    let node_b = Arc::new(GossipNode::new(
        NodeId::new(2),
        keys[1].1.clone(),
        registry_for(&keys),
        identities[1].clone(),
        peers_b,
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
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

/// Waits until `node` has created an event of its own that is not in
/// `excluded` (the pre-freeze event set), bounded by `deadline`. Used by the
/// reconnect tests to observe a learner resuming event production after
/// loading a checkpoint, without depending on new rounds being *decided*
/// (a pre-existing cluster-liveness limitation: long-running random-gossip
/// clusters stop finalizing rounds past ~round 7).
async fn wait_for_new_own_event(
    node: &Arc<GossipNode>,
    node_id: NodeId,
    excluded: &HashSet<EventHash>,
    deadline: Duration,
) {
    timeout(deadline, async {
        loop {
            let created = {
                let hashgraph = node.hashgraph.lock().await;
                hashgraph.latest_event_by(&node_id).is_some_and(|h| !excluded.contains(h))
            };
            if created {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("node creates a new event of its own in time");
}

// --- Phase 4: reconnect ----------------------------------------------------

#[tokio::test]
async fn reconnect_joining_node_skips_full_replay() {
    // A 4-node genesis registry; nodes 1-3 run a normal cluster, node 4 is
    // brought up late from a checkpoint served by node 1's reconnect port
    // instead of replaying history from genesis.
    let keys: Vec<(u64, SigningKey)> =
        (1..=4).map(|id| (id, SigningKey::from_bytes(&consensus_seed(id)))).collect();
    let registry = registry_for(&keys);

    let mut gossip_listeners = Vec::new();
    let mut reconnect_listeners = Vec::new();
    for _ in 0..3 {
        gossip_listeners.push(bind_ephemeral().await);
        reconnect_listeners.push(bind_ephemeral().await);
    }
    let gossip_addrs: Vec<SocketAddr> =
        gossip_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let reconnect_addrs: Vec<SocketAddr> =
        reconnect_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let identities: Vec<TlsIdentity> = (0..3)
        .map(|i| TlsIdentity::from_seed(tls_seed(i as u64 + 1), i as u64 + 1).expect("identity"))
        .collect();

    let mut nodes = Vec::new();
    for (i, (gossip_listener, reconnect_listener)) in
        gossip_listeners.into_iter().zip(reconnect_listeners).enumerate()
    {
        let node_id = NodeId::new(i as u64 + 1);
        let peers: Vec<PeerInfo> = (0..3)
            .filter(|&j| j != i)
            .map(|j| {
                PeerInfo::new(
                    NodeId::new(j as u64 + 1),
                    gossip_addrs[j],
                    identities[j].spki_fingerprint(),
                )
                .with_reconnect(reconnect_addrs[j])
            })
            .collect();
        let node = Arc::new(GossipNode::new(
            node_id,
            keys[i].1.clone(),
            registry.clone(),
            identities[i].clone(),
            peers,
            SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
            temp_state_db(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let spawn = node.clone();
        let stop_handle = stop.clone();
        let handle = tokio::spawn(async move {
            let _ = spawn
                .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
                .await;
        });
        nodes.push(TestNode { key: keys[i].1.clone(), node, stop, handle });
    }

    // Let the cluster run until node 1 has accepted a checkpoint (and, by
    // round >= 4, pruned some history).
    let t_genesis = std::time::Instant::now();
    let cp_round = wait_for_pruned_checkpoint(&nodes[0].node, 4, Duration::from_secs(25)).await;
    let genesis_elapsed = t_genesis.elapsed();

    // Bring up node 4 from a checkpoint served by node 1's reconnect port.
    let node4_id = NodeId::new(4);
    let identity4 = TlsIdentity::from_seed(tls_seed(4), 4).expect("identity");
    let peer1 = PeerInfo::new(NodeId::new(1), gossip_addrs[0], identities[0].spki_fingerprint())
        .with_reconnect(reconnect_addrs[0]);
    let t0 = std::time::Instant::now();
    let response = fetch_checkpoint(&identity4, &peer1, reconnect_addrs[0], node4_id)
        .await
        .expect("fetch checkpoint from node 1");
    assert!(gossip::verify_signed_checkpoint(&response.signed_checkpoint));
    let retained_count = response.retained.len();
    let decided_round = response.decided_round;

    let peers4: Vec<PeerInfo> = (0..3)
        .map(|j| {
            PeerInfo::new(
                NodeId::new(j as u64 + 1),
                gossip_addrs[j],
                identities[j].spki_fingerprint(),
            )
            .with_reconnect(reconnect_addrs[j])
        })
        .collect();
    let node4 = Arc::new(
        GossipNode::from_checkpoint(
            node4_id,
            keys[3].1.clone(),
            identity4,
            peers4,
            SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
            response,
            temp_state_db(),
        )
        .await
        .expect("node built from checkpoint"),
    );

    // The scaffold is correctly sized and holds exactly the teacher's
    // retained graph — full chains, not per-creator heads — so node 4's
    // known-summary is honest and no history was replayed.
    {
        let hashgraph = node4.hashgraph.lock().await;
        assert_eq!(hashgraph.member_count(), 4, "roster from the checkpoint snapshot");
        assert_eq!(
            hashgraph.all_event_hashes().len(),
            retained_count,
            "node 4 holds exactly the transferred retained graph, nothing replayed"
        );
        // Rounds the teacher had already decided stay decided on the learner.
        assert!(hashgraph.is_round_decided(decided_round), "decided round is seeded");
        // The full chains anchor the known-summary; node 4 itself has no
        // events yet.
        for creator in 1..=3 {
            assert!(
                hashgraph.latest_event_by(&NodeId::new(creator)).is_some(),
                "creator {creator} chain must be anchored"
            );
        }
        assert!(hashgraph.latest_event_by(&node4_id).is_none(), "node 4 has no own events yet");
    }

    let listener4 = bind_ephemeral().await;
    let reconnect4 = bind_ephemeral().await;
    let stop4 = Arc::new(AtomicBool::new(false));
    let spawn4 = node4.clone();
    let stop_handle4 = stop4.clone();
    let handle4 = tokio::spawn(async move {
        let _ = spawn4.run_until_stopped_with_reconnect(listener4, reconnect4, stop_handle4).await;
    });

    // Node 4 must resume event production from the checkpoint within a
    // bounded wall-clock window — a small multiple of the sync interval, not
    // proportional to cluster age (`genesis_elapsed`).
    let excluded = HashSet::new();
    wait_for_new_own_event(&node4, node4_id, &excluded, Duration::from_secs(25)).await;
    let t1 = t0.elapsed();
    eprintln!(
        "joining node: cluster age {genesis_elapsed:?}, checkpoint-to-first-event {t1:?} \
         (cp_round={cp_round})"
    );

    // Node 4's first event is a new chain head: self_parent None.
    let first = {
        let hashgraph = node4.hashgraph.lock().await;
        let mut own: Vec<EventHash> = hashgraph
            .all_event_hashes()
            .into_iter()
            .filter(|h| hashgraph.get(h).is_some_and(|r| r.event().creator() == &node4_id))
            .collect();
        own.sort_by_key(|h| hashgraph.get(h).expect("present").seq());
        own.first().map(|h| hashgraph.get(h).expect("present").event().clone())
    }
    .expect("node 4 created at least one event");
    assert_eq!(first.self_parent(), None, "first event starts a new chain");
    assert!(first.other_parent().is_some(), "first event references the sync partner");

    // Nodes 1-3 verify and insert node 4's events.
    let first_hash = first.hash();
    for node in &nodes {
        wait_for_event(&node.node, first_hash, Duration::from_secs(10)).await;
    }

    stop4.store(true, Ordering::Release);
    let _ = handle4.await;
    drop_nodes(nodes);
}

#[tokio::test]
async fn reconnect_existing_node_catches_up() {
    // A 4-node genesis registry. Teachers 1-3 form a dense gossip clique and
    // deliberately do NOT list node 4 as a peer, so their round advancement
    // is not degraded when node 4 is later frozen. Node 4's peers are the
    // teachers. Node 4 is frozen immediately (before creating events, so it
    // is maximally behind once the teachers prune), resumes later, detects it
    // is behind, reconnects from a checkpoint, and resumes producing events.
    let keys: Vec<(u64, SigningKey)> =
        (1..=4).map(|id| (id, SigningKey::from_bytes(&consensus_seed(id)))).collect();
    let registry = registry_for(&keys);

    let mut gossip_listeners = Vec::new();
    let mut reconnect_listeners = Vec::new();
    for _ in 0..4 {
        gossip_listeners.push(bind_ephemeral().await);
        reconnect_listeners.push(bind_ephemeral().await);
    }
    let gossip_addrs: Vec<SocketAddr> =
        gossip_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let reconnect_addrs: Vec<SocketAddr> =
        reconnect_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let identities: Vec<TlsIdentity> = (0..4)
        .map(|i| TlsIdentity::from_seed(tls_seed(i as u64 + 1), i as u64 + 1).expect("identity"))
        .collect();

    // Teachers 1-3: peers are the other teachers only.
    let teacher_pairs: Vec<(tokio::net::TcpListener, tokio::net::TcpListener)> =
        gossip_listeners.drain(0..3).zip(reconnect_listeners.drain(0..3)).collect();
    let mut teachers = Vec::new();
    for (i, (gossip_listener, reconnect_listener)) in teacher_pairs.into_iter().enumerate() {
        let node_id = NodeId::new(i as u64 + 1);
        let peers: Vec<PeerInfo> = (0..3)
            .filter(|&j| j != i)
            .map(|j| {
                PeerInfo::new(
                    NodeId::new(j as u64 + 1),
                    gossip_addrs[j],
                    identities[j].spki_fingerprint(),
                )
                .with_reconnect(reconnect_addrs[j])
            })
            .collect();
        let node = Arc::new(GossipNode::new(
            node_id,
            keys[i].1.clone(),
            registry.clone(),
            identities[i].clone(),
            peers,
            SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
            temp_state_db(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let spawn = node.clone();
        let stop_handle = stop.clone();
        let handle = tokio::spawn(async move {
            let _ = spawn
                .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
                .await;
        });
        teachers.push(TestNode { key: keys[i].1.clone(), node, stop, handle });
    }

    // Node 4: peers are the teachers.
    let node4_id = NodeId::new(4);
    let identity4 = identities[3].clone();
    let peers4: Vec<PeerInfo> = (0..3)
        .map(|j| {
            PeerInfo::new(
                NodeId::new(j as u64 + 1),
                gossip_addrs[j],
                identities[j].spki_fingerprint(),
            )
            .with_reconnect(reconnect_addrs[j])
        })
        .collect();
    let node4 = Arc::new(GossipNode::new(
        node4_id,
        keys[3].1.clone(),
        registry.clone(),
        identity4,
        peers4,
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));
    let stop4 = Arc::new(AtomicBool::new(false));
    let spawn4 = node4.clone();
    let stop_handle4 = stop4.clone();
    let gossip_listener4 = gossip_listeners.into_iter().next().expect("one listener left");
    let reconnect_listener4 = reconnect_listeners.into_iter().next().expect("one listener left");
    let handle4 = tokio::spawn(async move {
        let _ = spawn4
            .run_until_stopped_with_reconnect(gossip_listener4, reconnect_listener4, stop_handle4)
            .await;
    });
    let node4_ = TestNode {
        key: keys[3].1.clone(),
        node: node4.clone(),
        stop: stop4.clone(),

        handle: handle4,
    };

    // Freeze node 4 immediately, before its sync driver can create any events:
    // with an empty (seq-0) frontier it is deterministically below the
    // teachers' retained window once they prune, so the reconnect path is
    // guaranteed to trigger.
    node4_.stop();
    sleep(Duration::from_millis(200)).await;

    // Record node 4's frozen position: the highest checkpoint it holds and
    // every hash in its graph (both empty — it never participated).
    let frozen_cp = node4.latest_accepted_checkpoint_round().await;
    let frozen_hashes: HashSet<EventHash> = {
        let hashgraph = node4.hashgraph.lock().await;
        hashgraph.all_event_hashes().into_iter().collect()
    };

    // Let the teachers accept a checkpoint at round >= 5 and prune well past
    // node 4's frozen position. The cluster's round progression is variable
    // (a pre-existing liveness stall around rounds 5-10), so poll all three
    // teachers with a generous timeout. Once accepted round >= 5, the
    // retained window (border anchors end at round floor-1 = 3) is strictly
    // above node 4's round-1 frontier, so its first delta-sync after
    // resuming cannot succeed — it must reconnect.
    let cp_round = timeout(Duration::from_secs(60), async {
        loop {
            for teacher in &teachers {
                if let Some(round) = teacher.node.latest_accepted_checkpoint_round().await
                    && round >= 5
                {
                    return round;
                }
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("teachers accept a round-5 checkpoint and prune");
    eprintln!("teachers reached checkpoint round {cp_round}");

    // Force node 4 to be genuinely beyond the teachers' retained history: a
    // dense clique's border-anchor protection keeps chains contiguous down to
    // genesis, so natural pruning never leaves a delta gap. Pruning the
    // teachers down to round 4 guarantees node 4's empty frontier is below
    // the retained window.
    for teacher in &teachers {
        teacher.node.hashgraph.lock().await.prune_before_round(4);
    }

    // Resume node 4 on a fresh listener (its original task ended when
    // stopped). Its peers still point at the teachers' live addresses.
    let listener4 = bind_ephemeral().await;
    let reconnect4 = bind_ephemeral().await;
    let stop4b = Arc::new(AtomicBool::new(false));
    let spawn4b = node4.clone();
    let stop_handle4b = stop4b.clone();
    let handle4b = tokio::spawn(async move {
        let _ =
            spawn4b.run_until_stopped_with_reconnect(listener4, reconnect4, stop_handle4b).await;
    });

    // Node 4 must detect it is behind, reconnect, load a checkpoint, and
    // resume producing events (a new own event not in the pre-freeze set)
    // within a bounded number of sync intervals.
    wait_for_new_own_event(&node4, node4_id, &frozen_hashes, Duration::from_secs(25)).await;

    // The reconnect's apply_checkpoint pushed the served checkpoint, which is
    // beyond anything node 4 held pre-freeze — and which it could never reach
    // by clean catch-up, since its frontier is below the peers' retained
    // window (every delta-sync to a caught-up peer gaps).
    let applied = node4.latest_accepted_checkpoint_round().await;
    assert!(
        applied.is_some_and(|round| round > frozen_cp.unwrap_or(0)),
        "node 4 must have applied a checkpoint beyond its frozen position \
         (frozen_cp={frozen_cp:?}, applied={applied:?})"
    );

    stop4b.store(true, Ordering::Release);
    let _ = handle4b.await;
    drop_nodes(teachers);
    drop_nodes(vec![node4_]);
}

// --- Phase 4: reconnect with a non-empty state ------------------------------

/// The `state_hash` field (bytes 8..40) of a checkpoint's 72-byte signing
/// bytes.
fn state_hash_of(signing_bytes: &[u8; 72]) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&signing_bytes[8..40]);
    hash
}

/// Signs the node's checkpoint signing bytes for `round` with `signer`'s key.
fn checkpoint_sig_for(
    signer: u64,
    round: u64,
    signing_bytes: &[u8; 72],
) -> consensus::CheckpointSig {
    let key = SigningKey::from_bytes(&consensus_seed(signer));
    let signature = key.sign(signing_bytes);
    consensus::CheckpointSig {
        round,
        signer: NodeId::new(signer),
        sig: primitives::Signature::new(signature.to_bytes()),
    }
}

/// A node's committed state hash for `round`: from an accepted checkpoint if
/// one exists, else from a produced-but-not-yet-accepted one.
async fn state_hash_at(node: &Arc<GossipNode>, round: u64) -> Option<[u8; 32]> {
    if let Some(checkpoint) = node.signed_checkpoint_for(round).await {
        return Some(checkpoint.payload.state_hash);
    }
    node.checkpoint_signing_bytes(round).await.map(|bytes| state_hash_of(&bytes))
}

/// Deterministic 4-member deep clique (same shape as `state`'s
/// `deterministic.rs` `build_clique`) whose events carry payload transactions
/// in the later finalized rounds, so the state differs between the
/// checkpoint round and the tip.
fn build_stateful_clique() -> Vec<Event> {
    let mut events = HashMap::new();
    let mut out = Vec::new();
    let mut ts = 100u64;
    let mut step = |label: &'static str,
                    author: u64,
                    self_parent: Option<&'static str>,
                    other_parent: Option<&'static str>,
                    payload: Vec<Transaction>| {
        let self_parent = self_parent.map(|label| events[label]);
        let other_parent = other_parent.map(|label| events[label]);
        let event = UnsignedEvent::new(
            NodeId::new(author),
            self_parent,
            other_parent,
            Timestamp::new(ts),
            payload,
        )
        .sign(&SigningKey::from_bytes(&consensus_seed(author)));
        ts += 1;
        events.insert(label, event.hash());
        out.push(event);
    };
    let put = |key: &[u8], value: &[u8]| {
        Transaction::from_bytes(
            state::Op::Put { key: key.to_vec(), value: value.to_vec() }.encode(),
        )
    };
    let delete =
        |key: &[u8]| Transaction::from_bytes(state::Op::Delete { key: key.to_vec() }.encode());
    step("a1", 1, None, None, Vec::new());
    step("b1", 2, None, None, Vec::new());
    step("c1", 3, None, None, Vec::new());
    step("d1", 4, None, None, Vec::new());
    step("a2", 1, Some("a1"), Some("d1"), vec![put(b"alpha", b"a2")]);
    step("b2", 2, Some("b1"), Some("a2"), Vec::new());
    step("a3", 1, Some("a2"), Some("b2"), vec![put(b"beta", b"a3")]);
    step("b3", 2, Some("b2"), Some("c1"), Vec::new());
    step("a4", 1, Some("a3"), Some("b3"), Vec::new());
    step("d2", 4, Some("d1"), Some("a4"), Vec::new());
    step("c2", 3, Some("c1"), Some("d2"), Vec::new());
    step("a5", 1, Some("a4"), Some("c2"), vec![delete(b"alpha")]);
    step("b4", 2, Some("b3"), Some("a5"), Vec::new());
    step("c3", 3, Some("c2"), Some("b4"), Vec::new());
    step("d3", 4, Some("d2"), Some("c3"), Vec::new());
    step("a6", 1, Some("a5"), Some("d3"), Vec::new());
    step("b5", 2, Some("b4"), Some("a6"), Vec::new());
    step("c4", 3, Some("c3"), Some("b5"), vec![put(b"gamma", b"c4")]);
    step("d4", 4, Some("d3"), Some("c4"), vec![put(b"delta", b"d4")]);
    step("a7", 1, Some("a6"), Some("d4"), Vec::new());
    step("b6", 2, Some("b5"), Some("a7"), Vec::new());
    out
}

#[tokio::test]
async fn reconnect_serves_state_at_checkpoint_round() {
    // Regression for two reconnect bugs. Before this fix the teacher served
    // its LIVE state while the checkpoint's `state_hash` committed the state
    // at the checkpoint round, so any finalized transaction in
    // `(cp_round, tip]` made the rebuilt root diverge from `state_hash` and
    // every reconnect failed; even with that check weakened, the learner
    // replayed the retained window onto a state that already contained it
    // (double execution). The earlier reconnect tests never exercised either
    // path because their clusters only ever produced empty-payload events, so
    // the state never changed. This test uses a decided graph whose
    // transactions land in a later round than the checkpoint, and asserts (a)
    // the served state rebuilds to the committed `state_hash`, and (b) after
    // the learner loads the checkpoint and replays the retained window, its
    // state at the replay-window top matches the teacher's.
    let registry = registry_for_ids(&[1, 2, 3, 4]);

    // Node 1 holds the decided clique and serves reconnects.
    let identity1 = TlsIdentity::from_seed(tls_seed(1), 1).expect("identity");
    let gossip_listener = bind_ephemeral().await;
    let reconnect_listener = bind_ephemeral().await;
    let gossip_addr = gossip_listener.local_addr().expect("local addr");
    let reconnect_addr = reconnect_listener.local_addr().expect("local addr");
    let node1 = Arc::new(GossipNode::new(
        NodeId::new(1),
        SigningKey::from_bytes(&consensus_seed(1)),
        registry.clone(),
        identity1.clone(),
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));

    for event in build_stateful_clique() {
        let verified = event.clone().verify(&registry).expect("valid signature");
        let mut hg = node1.hashgraph.lock().await;
        hg.insert(verified).expect("insert");
    }
    node1.process_finalized_rounds().await;

    // Rounds 1-2 are decided, with transactions in round 2, so the state at
    // the checkpoint round (1) differs from the state at the tip — the exact
    // condition that used to break reconnect.
    let cp_round = 1u64;
    let signing_bytes_1 =
        node1.checkpoint_signing_bytes(cp_round).await.expect("checkpoint produced for round 1");

    // Accept the round-1 checkpoint with 2/3 signatures so it is servable.
    node1.submit_checkpoint_sig(checkpoint_sig_for(2, cp_round, &signing_bytes_1)).await;
    node1.submit_checkpoint_sig(checkpoint_sig_for(3, cp_round, &signing_bytes_1)).await;
    assert!(node1.signed_checkpoint_for(cp_round).await.is_some(), "round 1 reaches quorum");

    // Serve reconnects on the dedicated port.
    let stop1 = Arc::new(AtomicBool::new(false));
    let spawn1 = node1.clone();
    let stop_handle1 = stop1.clone();
    let handle1 = tokio::spawn(async move {
        let _ = spawn1
            .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle1)
            .await;
    });

    // Fetch the checkpoint. The served state must rebuild to the committed
    // state_hash — the direct regression for the "reconnect always fails" bug.
    let node4_id = NodeId::new(4);
    let identity4 = TlsIdentity::from_seed(tls_seed(4), 4).expect("identity");
    let peer1 = PeerInfo::new(NodeId::new(1), gossip_addr, identity1.spki_fingerprint())
        .with_reconnect(reconnect_addr);
    let response = fetch_checkpoint(&identity4, &peer1, reconnect_addr, node4_id)
        .await
        .expect("fetch checkpoint from node 1");
    assert!(gossip::verify_signed_checkpoint(&response.signed_checkpoint));
    let rebuilt = state::State::from_bytes(temp_state_db().state_keyspace(), &response.state_bytes)
        .expect("state decodes");
    assert_eq!(
        rebuilt.root(),
        response.signed_checkpoint.payload.state_hash,
        "served state must be the state at the checkpoint round"
    );
    assert_eq!(response.signed_checkpoint.payload.round, cp_round);
    let decided_round = response.decided_round;
    assert!(decided_round > cp_round, "learner has a non-empty replay window");
    // The state at the checkpoint round differs from the teacher's state at
    // the tip of the replay window, so the served snapshot is not trivially
    // the live state.
    assert_ne!(
        state_hash_of(&signing_bytes_1),
        state_hash_at(&node1, decided_round)
            .await
            .expect("teacher checkpoint at the decided round"),
        "state must differ between the checkpoint round and the tip"
    );

    // The learner restores the snapshot and replays the retained window on
    // its first finalized-rounds pass.
    let node4 = Arc::new(
        GossipNode::from_checkpoint(
            node4_id,
            SigningKey::from_bytes(&consensus_seed(4)),
            identity4,
            Vec::new(),
            SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
            response,
            temp_state_db(),
        )
        .await
        .expect("node built from checkpoint"),
    );
    node4.process_finalized_rounds().await;

    // The learner's produced checkpoints for the replayed rounds must match
    // the teacher's — exactly-once replay; a double- or missing-event replay
    // would diverge the state hashes.
    for round in cp_round + 1..=decided_round {
        let learner_hash = node4.checkpoint_signing_bytes(round).await.map(|b| state_hash_of(&b));
        let teacher_hash = state_hash_at(&node1, round).await;
        assert_eq!(
            learner_hash, teacher_hash,
            "learner replay must reproduce the teacher's state at round {round}"
        );
    }

    stop1.store(true, Ordering::Release);
    let _ = handle1.await;
}

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
