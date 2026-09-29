//! Crypto microbenchmark: isolates the per-op costs that make up an event's
//! consensus footprint — canonical encoding, SHA-256 event hashing, Ed25519
//! signing, and Ed25519 `verify_strict` authentication.
//!
//! Ignored by default so it never runs in the normal test sweep; it is an
//! on-demand measurement tool, not an assertion. Run it in release with:
//!
//! ```bash
//! cd consensus-node
//! cargo test -p crypto --release --test bench_crypto -- --ignored --nocapture
//! ```
//!
//! The point is to answer empirically whether hashing or signature
//! verification dominates per-event CPU, instead of trusting a prose claim.
//! Event sizes cover the empty genesis case and the gossip batch cap
//! (`TX_PER_SYNC = 64`).

use std::hint::black_box;
use std::time::{
    Duration,
    Instant,
};

use crypto::{
    BlsIdentity,
    CanonicalEncode,
    Hashable,
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use primitives::{
    Event,
    NodeId,
    Timestamp,
    Transaction,
    UnsignedEvent,
};
use rand::rngs::OsRng;

fn registry_with(node: NodeId, key: &SigningKey) -> MembershipRegistry {
    let mut registry = MembershipRegistry::new();
    registry.register(
        node,
        key.verifying_key(),
        BlsIdentity::from_ikm(&[0u8; 32]).expect("bls").public.to_bytes(),
    );
    registry
}

fn unsigned_with(txs: usize, tx_len: usize) -> UnsignedEvent {
    let payload: Vec<Transaction> =
        (0..txs).map(|_| Transaction::from_bytes(vec![0xAB; tx_len])).collect();
    UnsignedEvent::new(
        NodeId::new(1),
        None,
        None,
        Timestamp::new(1_700_000_000_000_000_000),
        payload,
    )
}

/// Runs `f` `iters` times after a 10% warmup and returns the elapsed wall time.
fn bench(iters: u32, mut f: impl FnMut()) -> Duration {
    for _ in 0..(iters / 10).max(1) {
        f();
    }
    let start = Instant::now();
    for _ in 0..iters {
        f();
    }
    start.elapsed()
}

fn report(label: &str, total: Duration, iters: u32) {
    let ns = total.as_nanos() as f64 / f64::from(iters);
    println!("  {label:<44} {ns:>12.1} ns/op  ({iters} iters)");
}

#[test]
#[ignore = "microbenchmark; run with --release --ignored --nocapture"]
fn crypto_microbenchmark() {
    let key = SigningKey::generate(&mut OsRng);
    let node = NodeId::new(1);
    let registry = registry_with(node, &key);

    println!("\n=== crypto microbenchmark (release only) ===");
    println!("host: sha2 0.10 / ed25519-dalek 2.2 (verify_strict)\n");

    // (txs, bytes-per-tx): genesis, small batch, full gossip batch.
    let cases = [(0usize, 0usize), (16, 64), (64, 256)];

    for (txs, tx_len) in cases {
        let unsigned = unsigned_with(txs, tx_len);
        let event = unsigned.clone().sign(&key).expect("sign");
        let canonical_len = unsigned.canonical_bytes().expect("encode").len();
        println!("[{txs} tx x {tx_len} B  ->  {canonical_len} canonical bytes + 64 B signature]");

        // Canonical encoding alone (the only hashed input).
        let encode_iters = 200_000;
        let t = bench(encode_iters, || {
            black_box(unsigned.canonical_bytes().expect("encode"));
        });
        report("canonical_bytes (unsigned)", t, encode_iters);

        // SHA-256 event hash = canonical encode + Sha256::digest.
        let t = bench(encode_iters, || {
            black_box(event.hash().expect("hash"));
        });
        report("Event::hash (SHA-256)", t, encode_iters);

        // Ed25519 sign (own-event creation), isolated input set.
        let sign_iters = 5_000;
        let unsigneds: Vec<UnsignedEvent> =
            (0..sign_iters).map(|_| unsigned_with(txs, tx_len)).collect();
        let start = Instant::now();
        for u in unsigneds {
            black_box(u.sign(&key).expect("sign"));
        }
        report("UnsignedEvent::sign (Ed25519)", start.elapsed(), sign_iters);

        // Ed25519 verify_strict (inbound event authentication), isolated input
        // set so cloning is NOT inside the timed region.
        let verify_iters = 5_000;
        let events: Vec<Event> = (0..verify_iters).map(|_| event.clone()).collect();
        let start = Instant::now();
        for e in events {
            black_box(e.verify(&registry).expect("verify"));
        }
        report("Event::verify (verify_strict)", start.elapsed(), verify_iters);

        println!();
    }
}
