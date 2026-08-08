use rand::rngs::StdRng;
use rand::{
    Rng,
    SeedableRng,
};

use crate::peer::PeerInfo;

/// The set of known peers plus uniform-random selection for the gossip
/// sync target (Consensus Spec §5). Peer selection is deliberately
/// unweighted — matching Hedera's behavior — until real multi-node data
/// (Phase 6) justifies weighting as an optimization.
pub struct PeerManager {
    peers: Vec<PeerInfo>,
    rng: StdRng,
}

impl PeerManager {
    /// Builds a peer manager with an OS-entropy rng.
    pub fn new(peers: Vec<PeerInfo>) -> Self {
        Self { peers, rng: StdRng::from_entropy() }
    }

    /// Builds a peer manager with a fixed seed, for deterministic tests.
    pub fn with_seed(peers: Vec<PeerInfo>, seed: u64) -> Self {
        Self { peers, rng: StdRng::seed_from_u64(seed) }
    }

    /// Uniform-random selection of the next sync partner, if any are known.
    pub fn random_peer(&mut self) -> Option<PeerInfo> {
        if self.peers.is_empty() {
            return None;
        }
        let idx = self.rng.gen_range(0..self.peers.len());
        Some(self.peers[idx].clone())
    }

    pub fn peer(&self, node_id: primitives::NodeId) -> Option<&PeerInfo> {
        self.peers.iter().find(|p| p.node_id == node_id)
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    };

    use primitives::NodeId;

    use super::*;

    fn peer(node_id: u64) -> PeerInfo {
        PeerInfo::new(
            NodeId::new(node_id),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            [0u8; 32],
        )
    }

    #[test]
    fn random_peer_returns_none_when_empty() {
        let mut manager = PeerManager::with_seed(Vec::new(), 42);
        assert_eq!(manager.random_peer(), None);
    }

    #[test]
    fn random_peer_only_returns_known_peers() {
        let peers = vec![peer(1), peer(2), peer(3), peer(4)];
        let mut manager = PeerManager::with_seed(peers.clone(), 7);
        for _ in 0..100 {
            let chosen = manager.random_peer().expect("peer present");
            assert!(peers.contains(&chosen));
        }
    }

    #[test]
    fn selection_uses_all_peers_across_many_draws() {
        let peers = vec![peer(1), peer(2), peer(3), peer(4)];
        let mut manager = PeerManager::with_seed(peers, 99);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            seen.insert(manager.random_peer().expect("peer present").node_id);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn same_seed_reproduces_same_sequence() {
        let peers = vec![peer(1), peer(2), peer(3)];
        let mut a = PeerManager::with_seed(peers.clone(), 5);
        let mut b = PeerManager::with_seed(peers, 5);
        let draws_a: Vec<_> = (0..50).map(|_| a.random_peer().unwrap().node_id).collect();
        let draws_b: Vec<_> = (0..50).map(|_| b.random_peer().unwrap().node_id).collect();
        assert_eq!(draws_a, draws_b);
    }

    #[test]
    fn peer_lookup_finds_registered_peer() {
        let manager = PeerManager::with_seed(vec![peer(1), peer(2)], 0);
        assert!(manager.peer(NodeId::new(2)).is_some());
        assert!(manager.peer(NodeId::new(99)).is_none());
    }
}
