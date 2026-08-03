use std::collections::HashMap;

use ed25519_dalek::VerifyingKey;
use primitives::NodeId;

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

    pub fn key_for(&self, node: &NodeId) -> Option<&VerifyingKey> {
        self.keys.get(node)
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

        assert_eq!(registry.key_for(&NodeId::new(1)), Some(&verifying_key));
    }

    #[test]
    fn unknown_node_resolves_to_none() {
        let registry = MembershipRegistry::new();
        assert_eq!(registry.key_for(&NodeId::new(99)), None);
    }
}
