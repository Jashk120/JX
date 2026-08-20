use std::net::SocketAddr;

use ed25519_dalek::VerifyingKey;
use rand::rngs::StdRng;
use rand::{
    Rng,
    SeedableRng,
};
use sha2::{
    Digest,
    Sha256,
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

    /// A snapshot of the current peer set (clones, so the caller never holds
    /// the manager's lock). Observability helper for `status`-style output and
    /// tests.
    pub fn all(&self) -> Vec<PeerInfo> {
        self.peers.clone()
    }

    /// Adds `info` to the live peer set. Returns `true` if the peer was not
    /// already present (idempotent on duplicate). Does not affect the
    /// `MembershipRegistry` or `n` — use only when the new peer's key is
    /// already registered in the registry (i.e., after a coordinated restart
    /// with an updated `ClusterConfig`).
    pub fn add_peer(&mut self, info: PeerInfo) -> bool {
        if self.peers.iter().any(|p| p.node_id == info.node_id) {
            return false;
        }
        self.peers.push(info);
        true
    }

    /// Adds a new peer derived from its Ed25519 `VerifyingKey`. The SPKI
    /// fingerprint is computed from the key using the same derivation that
    /// `TlsIdentity::spki_fingerprint_of` produces for a boot-time peer
    /// (SubjectPublicKeyInfo encoding, SHA-256 hash), so runtime-added peers
    /// are TLS-pinned consistently.
    ///
    /// `reconnect_addr`, when `Some`, marks the peer as serving the reconnect
    /// protocol (Phase 4) on that address — mirroring the reconnect port a
    /// genesis member carries in `cluster.toml`. It comes from the same
    /// `MembershipOp::Add` that admitted the peer, so a dynamically-added
    /// member can serve as a reconnect source for the existing cluster.
    ///
    /// Returns `false` if the peer was already present (idempotent on
    /// duplicate). Does not affect `RosterHistory` or quorum math — the
    /// caller (`GossipNode::process_finalized_rounds`) owns those updates.
    pub fn add_peer_from_key(
        &mut self,
        node_id: primitives::NodeId,
        key: &VerifyingKey,
        addr: SocketAddr,
        reconnect_addr: Option<SocketAddr>,
    ) -> bool {
        if self.peers.iter().any(|p| p.node_id == node_id) {
            return false;
        }
        let spki_fingerprint = spki_fingerprint_of(key);
        let mut peer = PeerInfo::new(node_id, addr, spki_fingerprint);
        if let Some(reconnect_addr) = reconnect_addr {
            peer = peer.with_reconnect(reconnect_addr);
        }
        self.peers.push(peer);
        true
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// Derives an SPKI fingerprint from an Ed25519 `VerifyingKey` by encoding it
/// as SubjectPublicKeyInfo bytes (RFC 8410) and taking the SHA-256 digest.
/// This must produce the same bytes as `TlsIdentity::spki_fingerprint_of`
/// for the cert built from the same key — verified by
/// `spki_derivation_matches_tls_identity`.
fn spki_fingerprint_of(key: &VerifyingKey) -> [u8; 32] {
    // Ed25519 SPKI DER: fixed 12-byte OID header + 32-byte key (RFC 8410).
    let mut spki = Vec::with_capacity(44);
    spki.extend_from_slice(&[
        0x30, 0x2a, // SEQUENCE (42 bytes)
        0x30, 0x05, // SEQUENCE (5 bytes) — AlgorithmIdentifier
        0x06, 0x03, // OID (3 bytes)
        0x2b, 0x65, 0x70, // 1.3.101.112 (id-EdDSA Ed25519)
        0x03, 0x21, 0x00, // BIT STRING, 33 bytes, 0 unused bits
    ]);
    spki.extend_from_slice(key.as_bytes());
    Sha256::digest(&spki).into()
}

#[cfg(test)]
mod tests {
    use std::net::{
        IpAddr,
        Ipv4Addr,
        SocketAddr,
    };

    use ed25519_dalek::SigningKey;
    use primitives::NodeId;

    use super::*;
    use crate::tls::TlsIdentity;

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

    #[test]
    fn peer_manager_add_peer_idempotent() {
        let mut manager = PeerManager::with_seed(vec![peer(1)], 0);
        assert!(manager.add_peer(peer(2)), "new peer is added");
        assert_eq!(manager.len(), 2);
        assert!(!manager.add_peer(peer(2)), "duplicate peer id is a no-op");
        assert_eq!(manager.len(), 2);
    }

    #[test]
    fn spki_derivation_matches_tls_identity() {
        let seed = [7u8; 32];
        let verifying_key = SigningKey::from_bytes(&seed).verifying_key();
        let identity = TlsIdentity::from_seed(seed, 1).expect("identity builds");
        assert_eq!(spki_fingerprint_of(&verifying_key), identity.spki_fingerprint());
    }

    #[test]
    fn add_peer_from_key_derives_spki_fingerprint() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let mut manager = PeerManager::with_seed(Vec::new(), 0);
        assert!(manager.add_peer_from_key(NodeId::new(9), &key.verifying_key(), addr, None));
        let peer = manager.peer(NodeId::new(9)).expect("peer added");
        assert_eq!(peer.addr, addr);
        assert_eq!(peer.expected_spki_fingerprint, spki_fingerprint_of(&key.verifying_key()));
    }

    #[test]
    fn add_peer_from_key_carries_reconnect_addr() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let reconnect_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8081);
        let mut manager = PeerManager::with_seed(Vec::new(), 0);
        assert!(manager.add_peer_from_key(
            NodeId::new(9),
            &key.verifying_key(),
            addr,
            Some(reconnect_addr)
        ));
        let peer = manager.peer(NodeId::new(9)).expect("peer added");
        assert_eq!(peer.reconnect_addr, Some(reconnect_addr));
    }

    #[test]
    fn add_peer_from_key_idempotent_on_duplicate() {
        let key = SigningKey::from_bytes(&[3u8; 32]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080);
        let mut manager = PeerManager::with_seed(Vec::new(), 0);
        assert!(manager.add_peer_from_key(NodeId::new(9), &key.verifying_key(), addr, None));
        assert!(!manager.add_peer_from_key(NodeId::new(9), &key.verifying_key(), addr, None));
        assert_eq!(manager.len(), 1);
    }
}
