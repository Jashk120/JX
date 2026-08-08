use std::net::SocketAddr;

use primitives::NodeId;

/// Everything needed to talk to one known peer (Consensus Spec §5).
///
/// `expected_spki_fingerprint` is the SHA-256 of the peer's TLS public key
/// (SPKI), used to pin the TLS connection to that peer's identity
/// independent of the consensus key registry.
#[derive(Clone, Debug, PartialEq)]
pub struct PeerInfo {
    pub node_id: NodeId,
    pub addr: SocketAddr,
    pub expected_spki_fingerprint: [u8; 32],
}

impl PeerInfo {
    pub fn new(node_id: NodeId, addr: SocketAddr, expected_spki_fingerprint: [u8; 32]) -> Self {
        Self { node_id, addr, expected_spki_fingerprint }
    }
}
