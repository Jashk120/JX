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
#[derive(Clone, Debug, Default)]
pub struct MembershipRegistry {
    keys: HashMap<NodeId, VerifyingKey>,
}

impl MembershipRegistry {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    pub fn register(&mut self, node: NodeId, key: VerifyingKey) {
        self.keys.insert(node, key);
    }

    pub fn key_for(&self, node: &NodeId) -> Result<&VerifyingKey> {
        self.keys.get(node).ok_or(CryptoError::UnknownSigner { node_id: *node })
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
    /// VerifyingKey)` pairs in [`MembershipRegistry::member_ids`] order.
    /// Deterministic on every node — the same roster always produces the
    /// same bytes — so a SHA-256 of this value anchors a checkpoint message
    /// (Phase 3).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut members: Vec<(&NodeId, &VerifyingKey)> = self.keys.iter().collect();
        members.sort_by_key(|(id, _)| **id);
        let mut buf = Vec::with_capacity(members.len() * 40);
        for (id, key) in members {
            buf.extend_from_slice(&id.get().to_be_bytes());
            buf.extend_from_slice(&key.to_bytes());
        }
        buf
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn registers_and_resolves_a_key() {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        let mut registry = MembershipRegistry::new();
        registry.register(NodeId::new(1), verifying_key);

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
        registry.register(NodeId::new(1), verifying_key);

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
            registry.register(NodeId::new(id), SigningKey::generate(&mut OsRng).verifying_key());
        }

        let bytes = registry.to_bytes();
        // 3 members, each serialized as 8-byte id + 32-byte key.
        assert_eq!(bytes.len(), 3 * 40);
        // The first entry is the smallest NodeId (1), regardless of the
        // insertion order above.
        assert_eq!(u64::from_be_bytes(bytes[0..8].try_into().unwrap()), 1);

        // Identical rosters serialize identically.
        let mut clone = MembershipRegistry::new();
        for id in [1u64, 2, 3] {
            clone.register(NodeId::new(id), registry.key_for(&NodeId::new(id)).unwrap().to_owned());
        }
        assert_eq!(clone.to_bytes(), bytes);
    }
}
