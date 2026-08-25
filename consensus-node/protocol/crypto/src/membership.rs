use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use primitives::NodeId;

use crate::error::{
    CryptoError,
    Result,
};

/// Maps each consensus member's `NodeId` to the Ed25519 key used to verify
/// events it creates. Lives in `crypto`, not `primitives`, so that
/// `primitives` stays free of any cryptography dependency — `NodeId` itself
/// remains a plain index with no knowledge that keys exist at all.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembershipRegistry {
    keys: HashMap<NodeId, (VerifyingKey, [u8; 48])>,
}

impl MembershipRegistry {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    pub fn register(&mut self, node: NodeId, key: VerifyingKey, bls_key: [u8; 48]) {
        self.keys.insert(node, (key, bls_key));
    }

    pub fn key_for(&self, node: &NodeId) -> Result<&VerifyingKey> {
        self.keys.get(node).map(|(k, _)| k).ok_or(CryptoError::UnknownSigner { node_id: *node })
    }

    pub fn bls_key_for(&self, node: &NodeId) -> Option<&[u8; 48]> {
        self.keys.get(node).map(|(_, b)| b)
    }

    pub fn contains(&self, node: &NodeId) -> bool {
        self.keys.contains_key(node)
    }
    /// Deterministic iteration order over registered members, sorted by
    /// `NodeId`. `consensus` uses this to assign each member a stable
    /// array index for ancestor bit-vectors — every honest node computes
    /// the same indexing independently, since it's derived purely from
    /// `NodeId` ordering.
    pub fn member_ids(&self) -> Vec<NodeId> {
        let mut ids: Vec<NodeId> = self.keys.keys().copied().collect();
        ids.sort();
        ids
    }

    pub fn len(&self) -> usize {
        self.keys.len()
    }

    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Canonical byte serialization of the roster: the sorted `(NodeId,
    /// VerifyingKey, bls_key)` triples in [`MembershipRegistry::member_ids`] order.
    /// Deterministic on every node — the same roster always produces the
    /// same bytes — so a SHA-256 of this value anchors a checkpoint message
    /// (Phase 3). Each member occupies 88 bytes: 8 (id) + 32 (ed25519) + 48 (bls).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut members: Vec<(&NodeId, &(VerifyingKey, [u8; 48]))> = self.keys.iter().collect();
        members.sort_by_key(|(id, _)| **id);
        let mut buf = Vec::with_capacity(members.len() * 88);
        for (id, (key, bls_key)) in members {
            buf.extend_from_slice(&id.get().to_be_bytes());
            buf.extend_from_slice(&key.to_bytes());
            buf.extend_from_slice(bls_key);
        }
        buf
    }

    /// The inverse of [`MembershipRegistry::to_bytes`]: parses the sorted
    /// `(NodeId, VerifyingKey, bls_key)` triples. Returns `None` on truncation
    /// or an invalid compressed Edwards point. Used by the reconnect codec to
    /// rebuild the roster snapshot embedded in a signed checkpoint. The
    /// proof-of-possession is NOT persisted — only the BLS public key is.
    pub fn from_bytes(mut bytes: &[u8]) -> Option<Self> {
        let mut registry = Self::new();
        while !bytes.is_empty() {
            let head = bytes.get(..88)?;
            let node = NodeId::new(u64::from_be_bytes(head[..8].try_into().ok()?));
            let key = VerifyingKey::from_bytes(head[8..40].try_into().ok()?).ok()?;
            let bls_key: [u8; 48] = head[40..88].try_into().ok()?;
            registry.register(node, key, bls_key);
            bytes = &bytes[88..];
        }
        Some(registry)
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;
    use crate::hash::Hashable;

    #[test]
    fn registers_and_resolves_a_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut registry = MembershipRegistry::new();
        registry.register(
            NodeId::new(1),
            verifying_key,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );

        assert_eq!(registry.key_for(&NodeId::new(1)), Ok(&verifying_key));
    }

    #[test]
    fn unknown_node_returns_unknown_signer_error() {
        let registry = MembershipRegistry::new();
        assert_eq!(
            registry.key_for(&NodeId::new(99)),
            Err(CryptoError::UnknownSigner { node_id: NodeId::new(99) })
        );
    }

    #[test]
    fn contains_returns_true_for_registered_node() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut registry = MembershipRegistry::new();
        registry.register(
            NodeId::new(1),
            verifying_key,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );

        assert!(registry.contains(&NodeId::new(1)));
    }

    #[test]
    fn contains_returns_false_for_unknown_node() {
        let registry = MembershipRegistry::new();
        assert!(!registry.contains(&NodeId::new(99)));
    }

    #[test]
    fn to_bytes_is_canonical_and_order_independent() {
        let mut registry = MembershipRegistry::new();
        for id in [3u64, 1, 2] {
            registry.register(
                NodeId::new(id),
                SigningKey::generate(&mut OsRng).verifying_key(),
                [0u8; 48],
            );
        }

        let bytes = registry.to_bytes();
        // 3 members, each serialized as 8-byte id + 32-byte key + 48-byte bls.
        assert_eq!(bytes.len(), 3 * 88);
        // The first entry is the smallest NodeId (1), regardless of the
        // insertion order above.
        assert_eq!(u64::from_be_bytes(bytes[0..8].try_into().unwrap()), 1);

        // Identical rosters serialize identically.
        let mut clone = MembershipRegistry::new();
        for id in [1u64, 2, 3] {
            clone.register(
                NodeId::new(id),
                registry.key_for(&NodeId::new(id)).unwrap().to_owned(),
                [0u8; 48],
            );
        }
        assert_eq!(clone.to_bytes(), bytes);
    }

    #[test]
    fn from_bytes_round_trips() {
        let mut registry = MembershipRegistry::new();
        for id in [3u64, 1, 2] {
            registry.register(
                NodeId::new(id),
                SigningKey::generate(&mut OsRng).verifying_key(),
                [0u8; 48],
            );
        }
        assert_eq!(MembershipRegistry::from_bytes(&registry.to_bytes()), Some(registry.clone()));

        // The rebuilt roster resolves the same keys.
        let rebuilt = MembershipRegistry::from_bytes(&registry.to_bytes()).expect("rebuild");
        for id in registry.member_ids() {
            assert_eq!(rebuilt.key_for(&id), registry.key_for(&id));
        }
    }

    #[test]
    fn from_bytes_empty_is_empty_registry() {
        assert_eq!(MembershipRegistry::from_bytes(&[]), Some(MembershipRegistry::new()));
    }

    #[test]
    fn from_bytes_rejects_truncation_and_invalid_keys() {
        let mut registry = MembershipRegistry::new();
        registry.register(
            NodeId::new(1),
            SigningKey::generate(&mut OsRng).verifying_key(),
            [0u8; 48],
        );
        let bytes = registry.to_bytes();

        assert_eq!(MembershipRegistry::from_bytes(&bytes[..bytes.len() - 1]), None);
        assert_eq!(MembershipRegistry::from_bytes(&bytes[..7]), None);

        // A y-coordinate of 2 encodes no valid Edwards point.
        let mut bad = Vec::new();
        bad.extend_from_slice(&1u64.to_be_bytes());
        bad.extend_from_slice(&[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        bad.extend_from_slice(&[0u8; 48]);
        assert_eq!(MembershipRegistry::from_bytes(&bad), None);
    }

    #[test]
    fn registering_duplicate_node_overwrites_key() {
        let key1 = SigningKey::generate(&mut OsRng).verifying_key();
        let key2 = SigningKey::generate(&mut OsRng).verifying_key();

        let mut registry = MembershipRegistry::new();
        registry.register(
            NodeId::new(1),
            key1,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );
        assert_eq!(registry.key_for(&NodeId::new(1)), Ok(&key1));

        registry.register(
            NodeId::new(1),
            key2,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );
        assert_eq!(registry.key_for(&NodeId::new(1)), Ok(&key2));
        assert_eq!(registry.len(), 1, "duplicate register should not increase member count");
    }

    #[test]
    fn member_ids_returns_sorted_order() {
        let mut registry = MembershipRegistry::new();
        for id in [5, 1, 3, 2, 4] {
            registry.register(
                NodeId::new(id),
                SigningKey::generate(&mut OsRng).verifying_key(),
                [0u8; 48],
            );
        }
        let ids = registry.member_ids();
        assert_eq!(
            ids,
            vec![NodeId::new(1), NodeId::new(2), NodeId::new(3), NodeId::new(4), NodeId::new(5)]
        );
    }

    #[test]
    fn len_and_is_empty_reflect_actual_members() {
        let mut registry = MembershipRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);

        registry.register(
            NodeId::new(1),
            SigningKey::generate(&mut OsRng).verifying_key(),
            [0u8; 48],
        );
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);

        registry.register(
            NodeId::new(2),
            SigningKey::generate(&mut OsRng).verifying_key(),
            [0u8; 48],
        );
        assert_eq!(registry.len(), 2);
    }

    #[test]
    fn from_bytes_rejects_non_aligned_input() {
        // 89 bytes is not a multiple of 88 (the per-member record size).
        let bytes = vec![0u8; 89];
        assert_eq!(MembershipRegistry::from_bytes(&bytes), None);
    }

    #[test]
    fn from_bytes_with_duplicate_node_ids_uses_last_key() {
        // Manually construct bytes with two records for the same NodeId.
        let key1 = SigningKey::generate(&mut OsRng).verifying_key();
        let key2 = SigningKey::generate(&mut OsRng).verifying_key();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&key1.to_bytes());
        bytes.extend_from_slice(&[0x11u8; 48]);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.extend_from_slice(&key2.to_bytes());
        bytes.extend_from_slice(&[0x22u8; 48]);

        let registry = MembershipRegistry::from_bytes(&bytes).expect("valid bytes");
        assert_eq!(registry.len(), 1, "duplicate NodeId should produce single member");
        assert_eq!(registry.key_for(&NodeId::new(1)), Ok(&key2));
    }

    #[test]
    fn lookup_after_clear_and_re_register() {
        let mut registry = MembershipRegistry::new();
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        registry.register(
            NodeId::new(1),
            key,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );
        assert!(registry.contains(&NodeId::new(1)));

        // Remove the entry and re-register with a new key.
        registry.keys.remove(&NodeId::new(1));
        assert!(!registry.contains(&NodeId::new(1)));

        let new_key = SigningKey::generate(&mut OsRng).verifying_key();
        registry.register(
            NodeId::new(1),
            new_key,
            crate::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls").public.to_bytes(),
        );
        assert_eq!(registry.key_for(&NodeId::new(1)), Ok(&new_key));
    }

    #[test]
    fn registry_to_bytes_is_88_per_member_and_sorted() {
        let mut registry = MembershipRegistry::new();
        for id in [3u64, 1, 2] {
            let key = SigningKey::generate(&mut OsRng).verifying_key();
            let bls = [id as u8; 48];
            registry.register(NodeId::new(id), key, bls);
        }
        let bytes = registry.to_bytes();
        assert_eq!(bytes.len(), 3 * 88, "each member must be 88 bytes");
        assert_eq!(u64::from_be_bytes(bytes[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_be_bytes(bytes[88..96].try_into().unwrap()), 2);
        assert_eq!(u64::from_be_bytes(bytes[176..184].try_into().unwrap()), 3);
        let rebuilt = MembershipRegistry::from_bytes(&bytes).expect("roundtrip");
        assert_eq!(rebuilt, registry);
        for id in [1u64, 2, 3] {
            let expected = [id as u8; 48];
            assert_eq!(rebuilt.bls_key_for(&NodeId::new(id)), Some(&expected));
        }
    }

    #[test]
    fn old_40_byte_layout_is_rejected() {
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        let mut old_bytes = Vec::new();
        old_bytes.extend_from_slice(&1u64.to_be_bytes());
        old_bytes.extend_from_slice(&key.to_bytes());
        assert_eq!(old_bytes.len(), 40, "old layout is 40 bytes per member");
        assert_eq!(
            MembershipRegistry::from_bytes(&old_bytes),
            None,
            "old 40-byte member layout must fail to parse as 88-byte triples"
        );
        let key2 = SigningKey::generate(&mut OsRng).verifying_key();
        let mut old_two = Vec::new();
        old_two.extend_from_slice(&1u64.to_be_bytes());
        old_two.extend_from_slice(&key.to_bytes());
        old_two.extend_from_slice(&2u64.to_be_bytes());
        old_two.extend_from_slice(&key2.to_bytes());
        assert_eq!(old_two.len(), 80);
        assert_eq!(MembershipRegistry::from_bytes(&old_two), None);
    }

    #[test]
    fn registry_partial_eq_covers_both_keys() {
        let k1 = SigningKey::generate(&mut OsRng).verifying_key();
        let k2 = k1;
        let mut r1 = MembershipRegistry::new();
        r1.register(NodeId::new(1), k1, [0xAAu8; 48]);
        let mut r2 = MembershipRegistry::new();
        r2.register(NodeId::new(1), k2, [0xBBu8; 48]);
        assert_ne!(r1, r2, "different bls keys must make registries unequal");
        assert_ne!(r1.to_bytes(), r2.to_bytes());
        assert_ne!(r1.hash(), r2.hash());
    }

    #[test]
    fn bls_key_for_returns_none_for_unknown() {
        let registry = MembershipRegistry::new();
        assert_eq!(registry.bls_key_for(&NodeId::new(99)), None);
    }

    #[test]
    fn registry_hash_changes_with_bls_key() {
        let key = SigningKey::generate(&mut OsRng).verifying_key();
        let mut r1 = MembershipRegistry::new();
        r1.register(NodeId::new(1), key, [0x11u8; 48]);
        let mut r2 = MembershipRegistry::new();
        r2.register(NodeId::new(1), key, [0x22u8; 48]);
        assert_ne!(r1.hash(), r2.hash(), "bls difference must change roster hash");
    }
}
