//! State Merkle microbenchmark: quantifies the per-operation SHA-256 cost of
//! the sparse Merkle tree that commits execution state (`state_hash`).
//!
//! Unlike the event hash (one SHA-256 over a small buffer), every KV
//! `insert`/`delete` walks `DEPTH = 256` levels, so this is the one place in
//! the node where hashing is genuinely heavy. Ignored by default; run with:
//!
//! ```bash
//! cd consensus-node
//! cargo test -p state --release --test bench_merkle -- --ignored --nocapture
//! ```

use std::collections::HashMap;
use std::hint::black_box;
use std::time::{
    Duration,
    Instant,
};

use sha2::{
    Digest,
    Sha256,
};
use state::SparseMerkleTree;

fn report(label: &str, total: Duration, iters: u32) {
    let ns = total.as_nanos() as f64 / f64::from(iters);
    println!("  {label:<34} {ns:>12.1} ns/op  ({iters} iters)");
}

#[test]
#[ignore = "microbenchmark; run with --release --ignored --nocapture"]
fn merkle_microbenchmark() {
    const N: u32 = 5_000;
    let keys: Vec<[u8; 32]> = (0..N)
        .map(|i| {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_be_bytes());
            k
        })
        .collect();
    let value = [0xABu8; 32];

    println!("\n=== state SparseMerkleTree microbenchmark (release only) ===");
    println!("DEPTH = 256 (one SHA-256 per level per mutation)\n");

    let mut tree = SparseMerkleTree::new();

    let start = Instant::now();
    for k in &keys {
        tree.insert(black_box(k.as_slice()), black_box(value.as_slice()));
    }
    report("SparseMerkleTree::insert", start.elapsed(), N);

    let root_iters = 500_000;
    let start = Instant::now();
    for _ in 0..root_iters {
        black_box(tree.root());
    }
    report("SparseMerkleTree::root", start.elapsed(), root_iters);

    let start = Instant::now();
    for k in &keys {
        black_box(tree.delete(black_box(k.as_slice())));
    }
    report("SparseMerkleTree::delete", start.elapsed(), N);
}

/// Cost budget for one `insert`: 256 levels, each a `singleton` SHA-256 plus a
/// pair of `HashMap<(u16, [u8; 32]), [u8; 32]>` probes. Isolating the two
/// halves shows whether an optimization must attack the hash or the map.
#[test]
#[ignore = "microbenchmark; run with --release --ignored --nocapture"]
fn merkle_insert_cost_budget() {
    const LEVELS: u32 = 256;
    const ITERS: u32 = 20_000;

    println!("\n=== SparseMerkleTree per-insert cost budget (release only) ===");

    let mut sink = 0u8;
    let start = Instant::now();
    for _ in 0..ITERS {
        let mut cur = [0x5Au8; 32];
        for _ in 0..LEVELS {
            let mut h = Sha256::new();
            h.update([0x01u8]);
            h.update(cur);
            cur = h.finalize().into();
        }
        sink ^= cur[0];
    }
    black_box(sink);
    report("256x singleton SHA-256 (33 B)", start.elapsed(), ITERS);

    let mut map: HashMap<(u16, [u8; 32]), [u8; 32]> = HashMap::new();
    let map_iters: u32 = 2_000;
    let start = Instant::now();
    for it in 0..map_iters {
        for depth in 0..LEVELS {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&it.to_be_bytes());
            k[4] = depth as u8;
            let sibling = map.get(&(depth as u16, [0xFFu8; 32])).copied().unwrap_or([0u8; 32]);
            map.insert((depth as u16, k), sibling);
        }
    }
    report("256x map get+insert, growing map", start.elapsed(), map_iters);
    println!("    (map entries at end: {})", map.len());
}
