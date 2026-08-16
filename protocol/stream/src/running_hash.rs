//! The running-hash chain shared by both stream types (Phase 8, §5).
//!
//! Hiero-style domain-separated SHA-256 chaining:
//!
//! ```text
//! item_hash     = SHA256( 0x6a6b2d6b, "item",  serialized_item )
//! running_hash' = SHA256( 0x6a6b2d6b, "chain", running_hash, item_hash )
//! ```
//!
//! - The seed for the first file of a stream is the all-zero hash.
//! - The hash is computed incrementally as items/events are appended —
//!   O(item size) per item, no rehash of history.
//! - The reader recomputes the chain and rejects any discontinuity.
//!
//! The 4-byte domain `0x6a6b2d6b` is the ASCII bytes of `jk-k`; the `item`/
//! `chain` labels keep the two hash kinds distinct.

use sha2::{
    Digest,
    Sha256,
};

/// The domain separator prefix common to both hash kinds.
const DOMAIN: [u8; 4] = [0x6a, 0x6b, 0x2d, 0x6b];

/// The running hash of a stream before any item: the all-zero hash (§5).
pub const CHAIN_SEED: [u8; 32] = [0u8; 32];

/// The first step: the hash of one serialized item (a serialized `Event`
/// proto for the event stream, a serialized `RecordItem` proto for the record
/// stream).
pub fn item_hash(serialized_item: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(b"item");
    hasher.update(serialized_item);
    hasher.finalize().into()
}

/// The second step: folds `item_hash` into the chain, advancing
/// `running_hash`.
pub fn chain_hash(running_hash: &[u8; 32], item_hash: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(b"chain");
    hasher.update(running_hash);
    hasher.update(item_hash);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_is_deterministic_and_order_dependent() {
        let a = item_hash(b"alpha");
        let b = item_hash(b"beta");
        let ab = chain_hash(&CHAIN_SEED, &a);
        let ab2 = chain_hash(&CHAIN_SEED, &a);
        let ba = chain_hash(&CHAIN_SEED, &b);
        assert_eq!(ab, ab2);
        assert_ne!(ab, ba, "order of items must matter");
        let forward = chain_hash(&ab, &b);
        let backward = chain_hash(&ba, &a);
        assert_ne!(forward, backward);
    }

    #[test]
    fn item_and_chain_kinds_are_domain_separated() {
        assert_ne!(item_hash(b"x"), item_hash(b"y"));
        // The same payload under the two labels must differ.
        assert_ne!(item_hash(b"payload"), chain_hash(&CHAIN_SEED, &item_hash(b"payload")));
    }

    #[test]
    fn running_hash_lengths_are_32_bytes() {
        assert_eq!(item_hash(&[]).len(), 32);
        assert_eq!(chain_hash(&CHAIN_SEED, &item_hash(&[])).len(), 32);
    }
}
