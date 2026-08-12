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
    /// The peer's dedicated reconnect port (Phase 4), if it runs the
    /// reconnect server. `None` for peers that do not — existing code that
    /// never reconnects is unaffected.
    pub reconnect_addr: Option<SocketAddr>,
    pub expected_spki_fingerprint: [u8; 32],
}

impl PeerInfo {
    pub fn new(node_id: NodeId, addr: SocketAddr, expected_spki_fingerprint: [u8; 32]) -> Self {
        Self { node_id, addr, reconnect_addr: None, expected_spki_fingerprint }
    }

    /// Builder: marks this peer as serving the reconnect protocol on
    /// `reconnect_addr`. The gossip port (`addr`) is left untouched — the
    /// reconnect port is a separate socket.
    pub fn with_reconnect(mut self, reconnect_addr: SocketAddr) -> Self {
        self.reconnect_addr = Some(reconnect_addr);
        self
    }
}
