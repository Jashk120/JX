//! Determinism tests for the Phase 8 executor.
//!
//! The core property: given the same finalized event order and the same
//! starting state, execution produces bit-identical resulting state on every
//! node. The tests run one order through two independently-constructed
//! `Executor` instances (each with its own fresh `State`) and assert the
//! resulting states are equal — both by `PartialEq` and by the canonical
//! byte serialization `State::to_bytes`.
//!
//! `build_clique` mirrors the deterministic 4-member deep clique used by
//! `consensus`'s `order.rs` tests: rounds 1–4 produce finalized order, and
//! several events carry payload transactions, so the finalized-order path
//! actually exercises state writes.

use std::collections::HashMap;

use consensus::Hashgraph;
use crypto::{
    Hashable,
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use primitives::{
    Event,
    EventHash,
    NodeId,
    Signature,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use state::{
    Executor,
    ExecutorError,
    Op,
    finalized_events,
};

fn key_for(id: u64) -> SigningKey {
    SigningKey::from_bytes(&[id as u8; 32])
}

fn registry_for(ids: &[u64]) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    for &id in ids {
        registry.register(NodeId::new(id), key_for(id).verifying_key());
    }
    registry
}

fn put(key: &[u8], value: &[u8]) -> Transaction {
    Transaction::from_bytes(Op::Put { key: key.to_vec(), value: value.to_vec() }.encode())
}

fn delete(key: &[u8]) -> Transaction {
    Transaction::from_bytes(Op::Delete { key: key.to_vec() }.encode())
}

fn event_with(payload: Vec<Transaction>) -> Event {
    UnsignedEvent::new(NodeId::new(1), None, None, Timestamp::new(1), payload)
        .finalize(Signature::default())
}

/// Deterministic 4-member deep clique builder. Fixed keys (per-id seeds), a
/// fixed timestamp sequence, and the same insertion order as `order.rs`'s
/// `build_deep_clique`, so the finalized consensus order is fully
/// deterministic. Some events carry payload transactions.
struct Clique {
    hg: Hashgraph,
    keys: Vec<SigningKey>,
    registry: MembershipRegistry,
    events: HashMap<&'static str, EventHash>,
    ts: u64,
}

impl Clique {
    fn new() -> Self {
        let registry = registry_for(&[1, 2, 3, 4]);
        let keys = [1u64, 2, 3, 4].map(key_for).to_vec();
        let hg = Hashgraph::new(&registry);
        Self { hg, keys, registry, events: HashMap::new(), ts: 100 }
    }

    fn step(
        &mut self,
        label: &'static str,
        author: u64,
        self_parent: Option<&'static str>,
        other_parent: Option<&'static str>,
        payload: Vec<Transaction>,
    ) {
        let unsigned = UnsignedEvent::new(
            NodeId::new(author),
            self_parent.map(|label| self.events[label]),
            other_parent.map(|label| self.events[label]),
            Timestamp::new(self.ts),
            payload,
        );
        self.ts += 1;
        let key = &self.keys[author as usize - 1];
        let verified = unsigned.sign(key).verify(&self.registry).expect("test event verifies");
        let hash = self.hg.insert(verified).expect("test insert succeeds");
        self.events.insert(label, hash);
    }
}

fn build_clique() -> Clique {
    let mut g = Clique::new();
    g.step("a1", 1, None, None, Vec::new());
    g.step("b1", 2, None, None, Vec::new());
    g.step("c1", 3, None, None, Vec::new());
    g.step("d1", 4, None, None, Vec::new());
    g.step("a2", 1, Some("a1"), Some("d1"), vec![put(b"alpha", b"a2")]);
    g.step("b2", 2, Some("b1"), Some("a2"), Vec::new());
    g.step("a3", 1, Some("a2"), Some("b2"), vec![put(b"beta", b"a3")]);
    g.step("b3", 2, Some("b2"), Some("c1"), Vec::new());
    g.step("a4", 1, Some("a3"), Some("b3"), Vec::new());
    g.step("d2", 4, Some("d1"), Some("a4"), Vec::new());
    g.step("c2", 3, Some("c1"), Some("d2"), Vec::new());
    g.step("a5", 1, Some("a4"), Some("c2"), vec![delete(b"alpha")]);
    g.step("b4", 2, Some("b3"), Some("a5"), Vec::new());
    g.step("c3", 3, Some("c2"), Some("b4"), Vec::new());
    g.step("d3", 4, Some("d2"), Some("c3"), Vec::new());
    g.step("a6", 1, Some("a5"), Some("d3"), Vec::new());
    g.step("b5", 2, Some("b4"), Some("a6"), Vec::new());
    g.step("c4", 3, Some("c3"), Some("b5"), vec![put(b"gamma", b"c4")]);
    g.step("d4", 4, Some("d3"), Some("c4"), vec![put(b"delta", b"d4")]);
    g.step("a7", 1, Some("a6"), Some("d4"), Vec::new());
    g.step("b6", 2, Some("b5"), Some("a7"), Vec::new());
    g
}

/// The literal Phase 8 determinism property: the same transaction order run
/// through two independently-constructed `State` instances yields identical
/// state (by `PartialEq` and by canonical bytes).
#[test]
fn same_transaction_order_yields_bit_identical_state() {
    let order = vec![
        put(b"alice", b"100"),
        put(b"bob", b"200"),
        delete(b"alice"),
        put(b"alice", b"300"),
        put(b"carol", b"50"),
    ];

    let mut left = Executor::new();
    let mut right = Executor::new();
    for tx in &order {
        let event = event_with(vec![tx.clone()]);
        assert!(left.execute_event(&event).0.is_empty());
        assert!(right.execute_event(&event).0.is_empty());
    }

    assert_eq!(left.state(), right.state());
    assert_eq!(left.state().to_bytes(), right.state().to_bytes());

    assert_eq!(left.state().get(b"alice"), Some(&b"300"[..]));
    assert_eq!(left.state().get(b"bob"), Some(&b"200"[..]));
    assert_eq!(left.state().get(b"carol"), Some(&b"50"[..]));
    assert_eq!(left.state().len(), 3);
}

/// The consensus-integrated determinism property: the finalized order from a
/// real `Hashgraph` run through two independent `Executor` instances yields
/// identical state, and payload transactions actually reached the state.
#[test]
fn same_finalized_order_yields_bit_identical_state() {
    let clique = build_clique();
    let events = finalized_events(&clique.hg);
    assert!(!events.is_empty(), "the clique must produce finalized order");

    let mut left = Executor::new();
    let mut right = Executor::new();
    for event in &events {
        left.execute_event(event);
        right.execute_event(event);
    }

    assert_eq!(left.state(), right.state());
    assert_eq!(left.state().to_bytes(), right.state().to_bytes());
    assert!(!left.state().is_empty(), "payload transactions must reach the state");
}

/// `finalized_events` must reuse `consensus`'s ordering, not invent one:
/// rounds are visited in increasing order and `roundReceived` is
/// non-decreasing along the returned sequence.
#[test]
fn finalized_events_follow_consensus_order() {
    let clique = build_clique();
    let events = finalized_events(&clique.hg);

    let mut prev_round = 0u64;
    for event in &events {
        let hash = event.hash();
        let round = clique.hg.round_received(&hash).expect("finalized events are ordered");
        assert!(round >= prev_round, "roundReceived must be non-decreasing along the order");
        prev_round = round;
    }
}

/// Malformed payloads fail deterministically: the same malformed order
/// through two independent executors produces the identical error sequence
/// and the identical (post-skip) state.
#[test]
fn malformed_payloads_fail_deterministically() {
    let order = [
        Transaction::from_bytes(vec![0x7f]),
        put(b"ok", b"1"),
        Transaction::from_bytes(Vec::new()),
        // A Put with a key but no room for the value length.
        Transaction::from_bytes(vec![0x00, 0, 0, 0, 1, b'k']),
    ];

    let mut left = Executor::new();
    let mut right = Executor::new();
    let left_errors: Vec<ExecutorError> = order
        .iter()
        .map(|tx| event_with(vec![tx.clone()]))
        .flat_map(|event| left.execute_event(&event).0)
        .collect();
    let right_errors: Vec<ExecutorError> = order
        .iter()
        .map(|tx| event_with(vec![tx.clone()]))
        .flat_map(|event| right.execute_event(&event).0)
        .collect();

    assert_eq!(left_errors, right_errors);
    assert_eq!(left.state(), right.state());
    assert_eq!(
        left_errors,
        vec![
            ExecutorError::UnknownOpcode(0x7f),
            ExecutorError::EmptyPayload,
            ExecutorError::Truncated,
        ]
    );
    assert_eq!(left.state().get(b"ok"), Some(&b"1"[..]));
}
