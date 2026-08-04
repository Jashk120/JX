use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use primitives::NodeId;

use crate::error::{CryptoError, Result};

/// Maps each consensus member's `NodeId` to the Ed25519 key used to verify
/// events it creates. Lives in `crypto`, not `primitives`, so that
/// `primitives` stays free of any cryptography dependency — `NodeId` itself
/// remains a plain index with no knowledge that keys exist at all.
#[derive(Debug, Default)]
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
}
