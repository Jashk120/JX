use std::net::SocketAddr;

use crypto::MembershipRegistry;
use ed25519_dalek::VerifyingKey;
use primitives::NodeId;

use crate::peer::PeerInfo;

/// Complete, static description of a JKain consensus cluster.
///
/// All nodes in the cluster must be constructed from the same `ClusterConfig`
/// so their `MembershipRegistry` and initial peer lists are guaranteed
/// consistent. This is the single source of truth for cluster membership
/// during the static-membership era (pre-Phase 8).
///
/// Adding a member at runtime is handled by submitting a `MembershipOp::Add`
/// transaction through consensus. The membership change propagates through
/// `RosterHistory` and `Hashgraph::add_member` at the activation round
/// (roundReceived + 1), without requiring a cluster restart or rebuilding
/// this config.
#[derive(Clone, Debug)]
pub struct ClusterConfig {
    members: Vec<MemberEntry>,
}

/// One consensus member: its `NodeId`, gossip endpoint, event-verification
/// key, and TLS pin.
#[derive(Clone, Debug)]
pub struct MemberEntry {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub verifying_key: VerifyingKey,
    pub spki_fingerprint: [u8; 32],
}

impl ClusterConfig {
    /// Builds a config from the complete member list.
    pub fn new(members: Vec<MemberEntry>) -> Self {
        Self { members }
    }

    /// Builds the `MembershipRegistry` used to verify events, from every
    /// member's verifying key.
    pub fn registry(&self) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for member in &self.members {
            registry.register(member.node_id, member.verifying_key);
        }
        registry
    }

    /// Builds the peer list for `node_id` — every member except itself — so
    /// each node can be constructed from the same config.
    pub fn peers_for(&self, node_id: NodeId) -> Vec<PeerInfo> {
        self.members
            .iter()
            .filter(|member| member.node_id != node_id)
            .map(|member| PeerInfo::new(member.node_id, member.addr, member.spki_fingerprint))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key_for(id: u64) -> SigningKey {
        SigningKey::from_bytes(&[id as u8; 32])
    }

    fn entry(node_id: u64, key: &SigningKey, spki_fingerprint: u8) -> MemberEntry {
        MemberEntry {
            node_id: NodeId::new(node_id),
            addr: "10.0.0.1:7000".parse().expect("valid addr"),
            verifying_key: key.verifying_key(),
            spki_fingerprint: [spki_fingerprint; 32],
        }
    }

    #[test]
    fn cluster_config_registry_matches_manual_construction() {
        let keys: Vec<(u64, SigningKey)> = (1..=3).map(|id| (id, key_for(id))).collect();
        let config = ClusterConfig::new(
            keys.iter().map(|&(id, ref key)| entry(id, key, id as u8)).collect(),
        );

        let mut manual = MembershipRegistry::new();
        for &(id, ref key) in &keys {
            manual.register(NodeId::new(id), key.verifying_key());
        }

        let derived = config.registry();
        assert_eq!(derived.member_ids(), manual.member_ids());
        for id in derived.member_ids() {
            assert_eq!(derived.key_for(&id), manual.key_for(&id));
        }
    }

    #[test]
    fn cluster_config_peers_excludes_self() {
        let ids = [1u64, 2, 3, 4];
        let config =
            ClusterConfig::new(ids.iter().map(|&id| entry(id, &key_for(id), id as u8)).collect());

        for &id in &ids {
            let peers = config.peers_for(NodeId::new(id));
            assert_eq!(peers.len(), ids.len() - 1);
            for peer in &peers {
                assert_ne!(peer.node_id, NodeId::new(id), "peer list must exclude self");
            }
        }
    }
}
