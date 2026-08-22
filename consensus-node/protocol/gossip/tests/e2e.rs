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
    MembershipOp,
    RosterHistory,
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

/// Waits until `node`'s hashgraph registers `id` as a structural member
/// (i.e. the `MembershipOp::Add` ordering it has activated).
async fn wait_for_member(node: &Arc<GossipNode>, id: NodeId, deadline: Duration) {
    timeout(deadline, async {
        loop {
            if node.is_consensus_member(id).await {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("membership activates on the node");
}

/// The transaction payload encoding for a `MembershipOp::Add`: the `0x02`
/// executor tag followed by the op's own encoding (same bytes the daemon's
/// control socket produces via `node::control::membership_op_payload`).
fn membership_add_payload(op: &MembershipOp) -> Vec<u8> {
    let mut payload = vec![0x02u8];
    payload.extend_from_slice(&op.encode());
    payload
}

/// Spawns `ids` nodes on ephemeral gossip + reconnect listeners, returning the
/// nodes plus the gossip addresses, TLS identities, and reconnect addresses so
/// a test can construct a membership op / peer list for a node added later.
async fn spawn_cluster_with_reconnect(
    ids: &[u64],
) -> (Vec<TestNode>, Vec<SocketAddr>, Vec<TlsIdentity>, Vec<SocketAddr>) {
    let keys: Vec<(u64, SigningKey)> =
        ids.iter().map(|&id| (id, SigningKey::from_bytes(&consensus_seed(id)))).collect();
    let mut gossip_listeners = Vec::new();
    let mut reconnect_listeners = Vec::new();
    for _ in 0..ids.len() {
        gossip_listeners.push(bind_ephemeral().await);
        reconnect_listeners.push(bind_ephemeral().await);
    }
    let gossip_addrs: Vec<SocketAddr> =
        gossip_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let reconnect_addrs: Vec<SocketAddr> =
        reconnect_listeners.iter().map(|l| l.local_addr().expect("local addr")).collect();
    let identities: Vec<TlsIdentity> =
        ids.iter().map(|&id| TlsIdentity::from_seed(tls_seed(id), id).expect("identity")).collect();

    let mut nodes = Vec::new();
    for (index, (gossip_listener, reconnect_listener)) in
        gossip_listeners.into_iter().zip(reconnect_listeners).enumerate()
    {
        let node_id = NodeId::new(ids[index]);
        let peers: Vec<PeerInfo> = (0..ids.len())
            .filter(|&j| j != index)
            .map(|j| {
                PeerInfo::new(
                    NodeId::new(ids[j]),
                    gossip_addrs[j],
                    identities[j].spki_fingerprint(),
                )
                .with_reconnect(reconnect_addrs[j])
            })
            .collect();
        let node = Arc::new(GossipNode::new(
            node_id,
            keys[index].1.clone(),
            registry_for(&keys),
            identities[index].clone(),
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
        nodes.push(TestNode { key: keys[index].1.clone(), node, stop, handle });
    }
    (nodes, gossip_addrs, identities, reconnect_addrs)
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

    // Wait until both creators hold an event of their own, then insert the
    // payload events as the latest event of each creator so they are recent
    // (and hence retained) when we verify them. A fixed warmup silently
    // degrades into genesis inserts on a slow node, so poll for the chain.
    timeout(DEADLINE, async {
        loop {
            let a_established = {
                let hashgraph = nodes[0].node.hashgraph.lock().await;
                hashgraph.latest_event_by(&NodeId::new(1)).is_some()
            };
            let b_established = {
                let hashgraph = nodes[1].node.hashgraph.lock().await;
                hashgraph.latest_event_by(&NodeId::new(2)).is_some()
            };
            if a_established && b_established {
                break;
            }
            sleep(POLL_INTERVAL).await;
        }
    })
    .await
    .expect("both nodes create their first own event");
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
    timeout(DEADLINE, async {
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

    // Ordering is insert-driven and the round-completeness gate only opens
    // once every member's frontier has passed a round, so a fixed warmup can
    // return before any order exists under CI load. Wait for the first ordered
    // round while the cluster is still gossiping, then settle.
    wait_for_ordered_round(&nodes[0].node, MAX_ORDERED_ROUND, DEADLINE).await;

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

    // Each node accepts checkpoints at its own pace and prunes every event
    // with round_received < accepted - RETENTION_ROUNDS, keeping only border
    // anchors of older rounds. So a round that one node still holds in full
    // may be down to a subset on another, even though both nodes ordered the
    // identical set. Only rounds at or above every node's prune floor are
    // comparable: for those, no node has pruned any of the round's events, so
    // `consensus_order(round)` is complete on every node that decided it.
    let mut compare_from = 0u64;
    for node in &refs {
        let floor = node
            .node
            .latest_accepted_checkpoint_round()
            .await
            .unwrap_or(0)
            .saturating_sub(consensus::RETENTION_ROUNDS);
        compare_from = compare_from.max(floor);
    }
    let compare_from = compare_from.max(1);
    let baseline_by_round: Vec<(u64, Vec<EventHash>)> = {
        let hashgraph = nodes[0].node.hashgraph.lock().await;
        (compare_from..=MAX_ORDERED_ROUND)
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
                continue; // this node has not decided the round; nothing to compare
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
                    // A retained event may be a border anchor whose own parent
                    // was pruned below the node's checkpoint floor; a pruned
                    // parent was necessarily ordered earlier, so skip it.
                    let Some(parent_record) = hashgraph.get(parent) else { continue };
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
        Timestamp::new(now_millis()),
    )
    .await
    .expect("sync after malformed input");

    let client_latest = client_hashgraph
        .lock()
        .await
        .latest_event_by(&NodeId::new(1))
        .copied()
        .expect("client created an event");
    wait_for_event(&node, client_latest, DEADLINE).await;

    stop.store(true, Ordering::Release);
    let _ = handle.await;
}

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
        Timestamp::new(now_millis()),
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
    wait_for_event(&node, client_latest, DEADLINE).await;

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
        Timestamp::new(now_millis()),
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
        Timestamp::new(now_millis()),
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
async fn membership_added_node_joins_live_cluster() {
    // A 3-node genesis cluster (no phantom 4th member). Node 4 is admitted via
    // a `MembershipOp::Add` — a real activation round, not silent preloading —
    // and joins as a live member once its membership activates, catching up
    // and participating in consensus.
    let (nodes, gossip_addrs, identities, _) = spawn_cluster_with_reconnect(&[1, 2, 3]).await;
    let refs: Vec<&TestNode> = nodes.iter().collect();

    // Node 4's consensus key and TLS identity derive from the SAME seed, so
    // the SPKI pin the teachers derive from its consensus key (in
    // `add_peer_from_key`) matches the certificate its identity produces.
    let node4_id = NodeId::new(4);
    let key4 = SigningKey::from_bytes(&consensus_seed(4));
    let identity4 = TlsIdentity::from_seed(consensus_seed(4), 4).expect("identity");

    // Bind node 4's listener before the op, so the op carries a real address.
    let listener4 = bind_ephemeral().await;
    let addr4 = listener4.local_addr().expect("local addr");

    // Admit node 4 through consensus. Submitted on every teacher so the op
    // enters the first events regardless of which sync partner is picked —
    // the earlier it orders, the sooner it activates and the safer node 4's
    // first delta-sync is (before the teachers have accepted any checkpoint).
    let op = MembershipOp::Add {
        node: node4_id,
        key: Box::new(key4.verifying_key()),
        addr: addr4,
        reconnect_addr: None,
    };
    let payload = membership_add_payload(&op);
    for node in &refs {
        node.node.submit_transaction(payload.clone()).await;
    }
    for node in &refs {
        wait_for_member(&node.node, node4_id, DEADLINE).await;
    }

    // Start node 4 as a live member: its registry includes itself (it knows
    // its own membership is active), so its events verify everywhere. The
    // n=3 -> n=4 quorum thresholds coincide (both need >= 3 of the witnesses
    // it can see), so its round/witness/fame bookkeeping stays consistent with
    // the teachers' for the pre-activation history it catches up on.
    let registry4 = registry_for_ids(&[1, 2, 3, 4]);
    let peers4: Vec<PeerInfo> = (0..3)
        .map(|j| {
            PeerInfo::new(
                NodeId::new(j as u64 + 1),
                gossip_addrs[j],
                identities[j].spki_fingerprint(),
            )
        })
        .collect();
    let node4 = Arc::new(GossipNode::new(
        node4_id,
        key4,
        registry4,
        identity4,
        peers4,
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));
    let stop4 = Arc::new(AtomicBool::new(false));
    let spawn4 = node4.clone();
    let stop_handle4 = stop4.clone();
    let handle4 = tokio::spawn(async move {
        let _ = spawn4.run_until_stopped(listener4, stop_handle4).await;
    });

    // Node 4 catches up on the pre-join history and creates its first event —
    // a new chain head whose self-parent is None.
    wait_for_new_own_event(&node4, node4_id, &HashSet::new(), DEADLINE).await;
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

    // Every teacher verifies and inserts node 4's events.
    let first_hash = first.hash();
    for node in &refs {
        wait_for_event(&node.node, first_hash, DEADLINE).await;
    }

    // Node 4 has caught up on the shared history from every pre-existing
    // creator, so it participates on equal footing.
    timeout(DEADLINE, async {
        loop {
            let hashgraph = node4.hashgraph.lock().await;
            let caught_up = (1..=3).all(|id| hashgraph.latest_event_by(&NodeId::new(id)).is_some());
            drop(hashgraph);
            if caught_up {
                return;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("node 4 catches up on the shared history");

    // The 4-member cluster continues to converge after node 4 joins. Await
    // node 4's actual shutdown rather than assuming a fixed wind-down window,
    // then settle on the teachers.
    stop4.store(true, Ordering::Release);
    let _ = handle4.await;
    let (counts, lates) = stop_and_settle(&refs, Duration::from_secs(1)).await;
    assert_converged(&counts, &lates, "membership-added node");
    drop_nodes(nodes);
}

#[tokio::test]
async fn reconnect_existing_node_catches_up() {
    // A 4th member is admitted via a `MembershipOp::Add` and participates until
    // the teachers accept a checkpoint and prune. It then loses its local graph
    // (the restart-from-nothing case: a node rebuilt from a lost/stale
    // checkpoint holds only the checkpointed state and must fetch the live
    // event window). Its frontier is below the teachers' retained window, so
    // its first delta-sync gaps and the driver reconnects from a checkpoint,
    // then resumes producing events.
    let (teachers, gossip_addrs, identities, reconnect_addrs) =
        spawn_cluster_with_reconnect(&[1, 2, 3]).await;
    let refs: Vec<&TestNode> = teachers.iter().collect();

    // Node 4's consensus key and TLS identity share one seed, so the SPKI pin
    // the teachers derive from its consensus key matches its certificate.
    let node4_id = NodeId::new(4);
    let key4 = SigningKey::from_bytes(&consensus_seed(4));
    let identity4 = TlsIdentity::from_seed(consensus_seed(4), 4).expect("identity");
    let listener4 = bind_ephemeral().await;
    let reconnect4 = bind_ephemeral().await;
    let addr4 = listener4.local_addr().expect("local addr");

    // Admit node 4 through consensus; it orders and activates on every teacher.
    let op = MembershipOp::Add {
        node: node4_id,
        key: Box::new(key4.verifying_key()),
        addr: addr4,
        reconnect_addr: Some(reconnect4.local_addr().expect("local addr")),
    };
    let payload = membership_add_payload(&op);
    for node in &refs {
        node.node.submit_transaction(payload.clone()).await;
    }
    for node in &refs {
        wait_for_member(&node.node, node4_id, DEADLINE).await;
    }

    // Node 4 joins live and participates, so the cluster (now 4 members) can
    // advance past its activation round and accept checkpoints that carry it
    // in the roster.
    let registry4 = registry_for_ids(&[1, 2, 3, 4]);
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
        key4,
        registry4.clone(),
        identity4,
        peers4,
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));
    let stop4 = Arc::new(AtomicBool::new(false));
    let spawn4 = node4.clone();
    let stop_handle4 = stop4.clone();
    let handle4 = tokio::spawn(async move {
        let _ = spawn4.run_until_stopped_with_reconnect(listener4, reconnect4, stop_handle4).await;
    });

    // Every teacher accepts a checkpoint at round >= 4, so each has pruned
    // history and can serve node 4 a checkpoint whose roster includes it.
    timeout(Duration::from_secs(60), async {
        loop {
            let mut all = true;
            for teacher in &refs {
                if teacher.node.latest_accepted_checkpoint_round().await.unwrap_or(0) < 4 {
                    all = false;
                    break;
                }
            }
            if all {
                return;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("teachers accept a round-4 checkpoint and prune");

    // Freeze node 4 and record its position. Its own early events sit below
    // the teachers' retained floor, so once its graph is gone it cannot
    // cleanly catch up.
    let frozen_cp = node4.latest_accepted_checkpoint_round().await;
    let frozen_own: HashSet<EventHash> = {
        let hashgraph = node4.hashgraph.lock().await;
        hashgraph
            .all_event_hashes()
            .into_iter()
            .filter(|h| hashgraph.get(h).is_some_and(|r| r.event().creator() == &node4_id))
            .collect()
    };
    stop4.store(true, Ordering::Release);
    let _ = handle4.await;

    // Node 4 loses its graph (restart from nothing). The scaffold is empty but
    // correctly sized; identity and key are unchanged.
    {
        let mut hashgraph = node4.hashgraph.lock().await;
        *hashgraph = consensus::Hashgraph::from_checkpoint(
            &consensus::CheckpointPayload::new(0, [0u8; 32], registry4.clone()),
            RosterHistory::new(registry4.clone()),
        );
    }

    // Backstop: force every teacher's retained window strictly above node 4's
    // empty frontier, so the delta-gap is deterministic no matter how far past
    // round 4 the cluster actually got before node 4 froze.
    for teacher in &refs {
        let mut hg = teacher.node.hashgraph.lock().await;
        if hg.next_round_to_order() > 4 {
            hg.prune_before_round(4);
        }
    }

    // Resume node 4 on fresh listeners (its original task ended when stopped).
    // Its peers still point at the teachers' live addresses. The first
    // delta-sync gaps, the driver reconnects from a checkpoint, and node 4
    // resumes producing events.
    let listener4b = bind_ephemeral().await;
    let reconnect4b = bind_ephemeral().await;
    let stop4b = Arc::new(AtomicBool::new(false));
    let spawn4b = node4.clone();
    let stop_handle4b = stop4b.clone();
    let handle4b = tokio::spawn(async move {
        let _ =
            spawn4b.run_until_stopped_with_reconnect(listener4b, reconnect4b, stop_handle4b).await;
    });

    wait_for_new_own_event(&node4, node4_id, &frozen_own, DEADLINE).await;

    // The reconnect's apply_checkpoint restored node 4 from a served
    // checkpoint at or beyond the teachers' accepted floor. Node 4 had wiped
    // its graph empty, so the new event it produced just now is only reachable
    // by having applied that checkpoint — a clean catch-up always gaps against
    // the pruned retained window.
    let applied = node4.latest_accepted_checkpoint_round().await;
    assert!(
        applied.is_some_and(|round| round >= 4),
        "node 4 must have reconnected and applied a checkpoint at or beyond the \
         teachers' accepted floor (frozen_cp={frozen_cp:?}, applied={applied:?})"
    );
    let restored = node4.hashgraph.lock().await.all_event_hashes().len();
    assert!(restored > 0, "node 4's graph was restored from the transferred retained graph");

    stop4b.store(true, Ordering::Release);
    let _ = handle4b.await;
    drop_nodes(teachers);
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
    let trusted_hash = registry.hash();
    let response = fetch_checkpoint(&identity4, &peer1, reconnect_addr, node4_id, trusted_hash)
        .await
        .expect("fetch checkpoint from node 1");
    assert!(gossip::verify_signed_checkpoint(&response.signed_checkpoint, trusted_hash));
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

/// End-to-end test that a peer serving a checkpoint whose roster the caller
/// does not trust gets rejected through the actual `fetch_checkpoint` code
/// path (commit 3ec6744). This exercises the same scenario as the unit-level
/// `fabricated_roster_with_attacker_quorum_rejected_by_trusted_hash` test,
/// but through the real network + TLS + reconnect path.
#[tokio::test]
async fn fetch_checkpoint_rejects_untrusted_roster_over_network() {
    // Server: a 4-node cluster with registry_A = {1, 2, 3, 4}.
    let server_registry = registry_for_ids(&[1, 2, 3, 4]);
    let identity1 = TlsIdentity::from_seed(tls_seed(1), 1).expect("identity");
    let gossip_listener = bind_ephemeral().await;
    let reconnect_listener = bind_ephemeral().await;
    let gossip_addr = gossip_listener.local_addr().expect("local addr");
    let reconnect_addr = reconnect_listener.local_addr().expect("local addr");

    let server = Arc::new(GossipNode::new(
        NodeId::new(1),
        SigningKey::from_bytes(&consensus_seed(1)),
        server_registry.clone(),
        identity1.clone(),
        Vec::new(),
        SyncTiming::new(SYNC_INTERVAL, SYNC_TIMEOUT),
        temp_state_db(),
    ));

    // Seed with a decided clique so round 1 is ordered.
    for event in build_stateful_clique() {
        let verified = event.clone().verify(&server_registry).expect("valid signature");
        let mut hg = server.hashgraph.lock().await;
        hg.insert(verified).expect("insert");
    }
    server.process_finalized_rounds().await;

    let cp_round = 1u64;
    let signing_bytes_1 =
        server.checkpoint_signing_bytes(cp_round).await.expect("checkpoint produced");
    server.submit_checkpoint_sig(checkpoint_sig_for(2, cp_round, &signing_bytes_1)).await;
    server.submit_checkpoint_sig(checkpoint_sig_for(3, cp_round, &signing_bytes_1)).await;
    assert!(server.signed_checkpoint_for(cp_round).await.is_some(), "round 1 reaches quorum");

    // Start the server's reconnect listener.
    let stop = Arc::new(AtomicBool::new(false));
    let spawn = server.clone();
    let stop_handle = stop.clone();
    let handle = tokio::spawn(async move {
        let _ = spawn
            .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop_handle)
            .await;
    });

    // Client: trusts a DIFFERENT roster (registry_B = {97, 98, 99}).
    let client_trusted_registry = registry_for_ids(&[97, 98, 99]);
    let client_trusted_hash = client_trusted_registry.hash();

    let client_identity = TlsIdentity::from_seed(tls_seed(4), 4).expect("identity");
    let peer1 = PeerInfo::new(NodeId::new(1), gossip_addr, identity1.spki_fingerprint())
        .with_reconnect(reconnect_addr);

    // The client calls fetch_checkpoint with a trusted roster hash that does
    // NOT match the server's roster. The roster_hash check at the top of
    // verify_signed_checkpoint must reject this before any signature
    // verification runs.
    let result = fetch_checkpoint(
        &client_identity,
        &peer1,
        reconnect_addr,
        NodeId::new(4),
        client_trusted_hash,
    )
    .await;
    assert!(
        result.is_err(),
        "fetch_checkpoint must reject a checkpoint whose roster the caller does not trust"
    );
    match result.unwrap_err() {
        GossipError::Reconnect(msg) => {
            assert!(
                msg.contains("quorum verification"),
                "error must mention quorum verification, got: {msg}"
            );
        }
        other => panic!("expected Reconnect error, got: {other:?}"),
    }

    stop.store(true, Ordering::Release);
    let _ = handle.await;
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
