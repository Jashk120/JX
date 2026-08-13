//! The shared `cluster.toml` configuration plus hex encode/decode helpers.
//!
//! `cluster.toml` is the single file both VPSes load. It is written once by
//! `jkaind init` and carries, per member, the gossip and reconnect endpoints,
//! the Ed25519 verifying key (hex, 32 bytes) and the TLS SPKI fingerprint
//! (hex, 32 bytes). It contains no secrets — the per-node `secret-<id>.bin`
//! files (64 bytes: consensus signing seed ‖ TLS seed) stay on their node.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{
    Context,
    Result,
    bail,
};
use ed25519_dalek::VerifyingKey;
use primitives::NodeId;
use serde::{
    Deserialize,
    Serialize,
};

/// The on-disk form of the cluster configuration (TOML).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClusterConfigFile {
    pub members: Vec<MemberFile>,
}

/// One member's entry in `cluster.toml`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MemberFile {
    pub node_id: u64,
    pub gossip_addr: SocketAddr,
    /// The member's dedicated reconnect port (Phase 4). `None` for members
    /// that do not serve the reconnect protocol.
    #[serde(default)]
    pub reconnect_addr: Option<SocketAddr>,
    /// Hex-encoded Ed25519 verifying key (32 bytes).
    pub verifying_key: String,
    /// Hex-encoded SHA-256 of the member's TLS SPKI (32 bytes).
    pub spki_fingerprint: String,
}

impl ClusterConfigFile {
    /// Loads `cluster.toml` from `path`.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading cluster config {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parsing cluster config {}", path.display()))
    }

    /// Writes the config to `path`.
    pub fn save(&self, path: &Path) -> Result<()> {
        let text = toml::to_string(self).context("serializing cluster config")?;
        std::fs::write(path, text)
            .with_context(|| format!("writing cluster config {}", path.display()))
    }

    /// The entry for `node_id`, if present.
    pub fn member_for(&self, node_id: u64) -> Option<&MemberFile> {
        self.members.iter().find(|m| m.node_id == node_id)
    }

    /// Converts to the gossip-layer [`gossip::ClusterConfig`], the single
    /// source of truth used to build registries and peer lists.
    pub fn to_cluster_config(&self) -> Result<gossip::ClusterConfig> {
        let mut members = Vec::with_capacity(self.members.len());
        for member in &self.members {
            let verifying_key_bytes = decode_hex(&member.verifying_key).ok_or_else(|| {
                anyhow::anyhow!("member {}: invalid verifying_key hex", member.node_id)
            })?;
            let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
                .map_err(|_| anyhow::anyhow!("member {}: invalid verifying key", member.node_id))?;
            let spki_fingerprint = decode_hex(&member.spki_fingerprint).ok_or_else(|| {
                anyhow::anyhow!("member {}: invalid spki_fingerprint hex", member.node_id)
            })?;
            members.push(gossip::MemberEntry {
                node_id: NodeId::new(member.node_id),
                addr: member.gossip_addr,
                reconnect_addr: member.reconnect_addr,
                verifying_key,
                spki_fingerprint,
            });
        }
        if members.is_empty() {
            bail!("cluster config declares no members");
        }
        Ok(gossip::ClusterConfig::new(members))
    }

    /// The peer list for `node_id`, excluding the node itself.
    pub fn peers_for(&self, node_id: u64) -> Result<Vec<gossip::PeerInfo>> {
        Ok(self.to_cluster_config()?.peers_for(NodeId::new(node_id)))
    }
}

impl MemberFile {
    /// Builds a member entry from already-derived material. Used by `init`
    /// to assemble the config before writing it.
    pub fn new(
        node_id: u64,
        gossip_addr: SocketAddr,
        reconnect_addr: SocketAddr,
        verifying_key: &VerifyingKey,
        spki_fingerprint: [u8; 32],
    ) -> Self {
        Self {
            node_id,
            gossip_addr,
            reconnect_addr: Some(reconnect_addr),
            verifying_key: encode_hex(&verifying_key.to_bytes()),
            spki_fingerprint: encode_hex(&spki_fingerprint),
        }
    }
}

/// Hex-encodes `bytes` to lowercase ASCII.
pub fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decodes a lowercase or uppercase hex string of exactly 32 bytes.
pub fn decode_hex(input: &str) -> Option<[u8; 32]> {
    let bytes = decode_hex_bytes(input)?;
    bytes.try_into().ok()
}

/// Decodes a lowercase or uppercase hex string into a byte vector of any
/// length. Returns `None` on a non-even or non-hex character.
pub fn decode_hex_bytes(input: &str) -> Option<Vec<u8>> {
    if !input.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(input.len() / 2);
    for pair in input.as_bytes().chunks_exact(2) {
        let hi = nibble(pair[0])?;
        let lo = nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn sample_config() -> ClusterConfigFile {
        let key1 = SigningKey::generate(&mut OsRng);
        let key2 = SigningKey::generate(&mut OsRng);
        ClusterConfigFile {
            members: vec![
                MemberFile::new(
                    1,
                    "203.0.113.5:7000".parse().expect("addr"),
                    "203.0.113.5:7001".parse().expect("addr"),
                    &key1.verifying_key(),
                    [1u8; 32],
                ),
                MemberFile::new(
                    2,
                    "203.0.113.6:7000".parse().expect("addr"),
                    "203.0.113.6:7001".parse().expect("addr"),
                    &key2.verifying_key(),
                    [2u8; 32],
                ),
            ],
        }
    }

    #[test]
    fn hex_round_trips() {
        let bytes = [0u8, 1, 0x0f, 0x10, 0xff, 0xab, 0xcd, 0x55];
        let mut full = [0u8; 32];
        full[..8].copy_from_slice(&bytes);
        assert_eq!(decode_hex(&encode_hex(&full)), Some(full));
        assert_eq!(decode_hex("ABCDEF0123456789"), None, "too short");
        assert_eq!(decode_hex("z"), None, "non-hex digit");
    }

    #[test]
    fn cluster_config_round_trips_through_toml() {
        let config = sample_config();
        let text = toml::to_string(&config).expect("serializes");
        let parsed: ClusterConfigFile = toml::from_str(&text).expect("parses");
        assert_eq!(parsed, config);
    }

    #[test]
    fn to_cluster_config_matches_manual_construction() {
        let file = sample_config();
        let derived = file.to_cluster_config().expect("converts");
        let registry = derived.registry();
        for member in &file.members {
            let id = NodeId::new(member.node_id);
            assert!(registry.key_for(&id).is_ok(), "member {} registered", member.node_id);
        }
        let peers = derived.peers_for(NodeId::new(1));
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].node_id, NodeId::new(2));
        assert_eq!(peers[0].reconnect_addr, Some("203.0.113.6:7001".parse().expect("addr")));
    }

    #[test]
    fn member_for_finds_and_misses() {
        let config = sample_config();
        assert_eq!(config.member_for(2).map(|m| m.node_id), Some(2));
        assert!(config.member_for(99).is_none());
    }

    #[test]
    fn empty_config_is_rejected() {
        let config = ClusterConfigFile { members: Vec::new() };
        assert!(config.to_cluster_config().is_err());
    }
}
