//! The membership operation wire format (Phase 1).
//!
//! Membership changes become an ordinary `Transaction` payload so they inherit
//! consensus's existing ordering and agreement machinery. A `Transaction`'s
//! payload bytes decode into exactly one [`MembershipOp`]; Phase 2 applies it
//! to a [`MembershipRegistry`].
//!
//! The format mirrors the executor's `Op` encoding:
//!
//! ```text
//! [opcode: u8]
//! [field: u32 (big-endian) byte length + raw bytes]
//! ```
//!
//! | opcode | meaning  | fields              |
//! |--------|----------|---------------------|
//! | `0x00` | `Add`    | node_id, key, addr  |
//! | `0x01` | `Remove` | node_id             |
//!
//! `node_id` (8 bytes) and the Ed25519 verifying key (32 bytes) are
//! fixed-width and written raw; only `addr` is length-prefixed, since its
//! serialized length varies with the IP version. `SocketAddr` is encoded as
//! `[tag: u8]` (`0x04` = IPv4, `0x06` = IPv6) followed by the IP bytes and a
//! big-endian `u16` port. Every other opcode byte, a payload too short for its
//! declared fields, or trailing bytes after the last field decodes to a
//! deterministic [`CryptoError`] — identical bytes always produce the
//! identical outcome on every node.
//!
//! `MembershipOp` lives in `crypto`, not `primitives`, because `Add` carries
//! an Ed25519 [`VerifyingKey`]; `primitives` stays free of any cryptography
//! dependency (see the rationale in `membership.rs`).

use std::collections::BTreeMap;
use std::net::{
    IpAddr,
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
};

use ed25519_dalek::VerifyingKey;
use primitives::NodeId;

use crate::error::{
    CryptoError,
    Result,
};
use crate::membership::MembershipRegistry;

const MEMBERSHIP_ADD: u8 = 0x00;
const MEMBERSHIP_REMOVE: u8 = 0x01;

const ADDR_IPV4: u8 = 0x04;
const ADDR_IPV6: u8 = 0x06;

/// A membership change decoded from a `Transaction` payload.
///
/// A `MembershipOp` is the wire message that mutates a `MembershipRegistry`
/// (Phase 2); it deliberately lives apart from the registry itself, mirroring
/// how the executor separates `Op` (wire format) from the mutable state.
#[derive(Clone, Debug)]
pub enum MembershipOp {
    /// Adds `node`, registering `key` as the Ed25519 key used to verify events
    /// it creates, together with the `SocketAddr` where it can be reached.
    ///
    /// `key` is boxed to keep the enum small — a `VerifyingKey` is 192 bytes,
    /// and the `Remove` variant holds only an 8-byte `NodeId`.
    Add { node: NodeId, key: Box<VerifyingKey>, addr: SocketAddr },
    /// Removes `node` from the registry.
    Remove { node: NodeId },
}

impl MembershipOp {
    /// Decodes `payload` into the membership operation it encodes.
    ///
    /// Deterministic by construction: the same bytes always yield the same
    /// `MembershipOp` or the same `CryptoError`.
    pub fn decode(payload: &[u8]) -> Result<MembershipOp> {
        let (&opcode, mut cursor) = payload.split_first().ok_or(CryptoError::MalformedOp)?;
        // The opcode is matched before any field is read, so an unknown
        // opcode is reported even when the rest of the payload is truncated.
        match opcode {
            MEMBERSHIP_ADD => {
                let node = NodeId::new(take_u64(&mut cursor)?);
                let key = take_key(&mut cursor)?;
                let addr = take_addr(&mut cursor)?;
                reject_trailing(cursor)?;
                Ok(MembershipOp::Add { node, key: Box::new(key), addr })
            }
            MEMBERSHIP_REMOVE => {
                let node = NodeId::new(take_u64(&mut cursor)?);
                reject_trailing(cursor)?;
                Ok(MembershipOp::Remove { node })
            }
            _ => Err(CryptoError::UnknownMembershipOpcode(opcode)),
        }
    }

    /// The canonical encoding of this operation — the inverse of
    /// [`MembershipOp::decode`]. `decode(&op.encode())` returns `Ok(op)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            MembershipOp::Add { node, key, addr } => {
                buf.push(MEMBERSHIP_ADD);
                buf.extend_from_slice(&node.get().to_be_bytes());
                buf.extend_from_slice(&key.to_bytes());
                write_bytes(&mut buf, &encode_addr(addr));
            }
            MembershipOp::Remove { node } => {
                buf.push(MEMBERSHIP_REMOVE);
                buf.extend_from_slice(&node.get().to_be_bytes());
            }
        }
        buf
    }
}

// `VerifyingKey` implements `Eq`, but via its compressed-point encoding;
// comparing `.to_bytes()` instead gives the canonical representation, which
// is the same bytes `encode`/`decode` round-trip.
impl PartialEq for MembershipOp {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                MembershipOp::Add { node, key, addr },
                MembershipOp::Add { node: other_node, key: other_key, addr: other_addr },
            ) => node == other_node && key.to_bytes() == other_key.to_bytes() && addr == other_addr,
            (MembershipOp::Remove { node }, MembershipOp::Remove { node: other_node }) => {
                node == other_node
            }
            _ => false,
        }
    }
}

impl Eq for MembershipOp {}

/// A time-ordered sequence of `MembershipRegistry` snapshots, keyed by the
/// consensus round at which each snapshot becomes active.
///
/// Backed by `BTreeMap` so [`RosterHistory::roster_for_round`] is an O(log n)
/// predecessor lookup, not a linear scan. This matters because it is called
/// on every quorum computation in `ancestry.rs`, `fame.rs`, and `round.rs`.
///
/// # Invariant: round ≥ 1
///
/// The genesis snapshot is always inserted at round 1. Round 0 is never a
/// valid event birth round in the hashgraph (all events start at round 1),
/// so `roster_for_round(0)` is unreachable under correct usage. If a future
/// refactor introduces a round-0 genesis event, this invariant must be
/// revisited before it silently hits the panic inside `roster_for_round`.
#[derive(Clone, Debug)]
pub struct RosterHistory {
    snapshots: BTreeMap<u64, MembershipRegistry>,
}

impl RosterHistory {
    /// Creates a `RosterHistory` with `genesis` activated at round 1.
    /// Round 1 is the earliest valid event birth round.
    pub fn new(genesis: MembershipRegistry) -> Self {
        let mut snapshots = BTreeMap::new();
        snapshots.insert(1, genesis);
        Self { snapshots }
    }

    /// The registry active at `round` — the last snapshot whose activation
    /// round is ≤ `round`.
    ///
    /// # Panics
    /// Panics if `round` is 0 (no snapshot exists at or before round 0).
    /// Valid event birth rounds are always ≥ 1.
    pub fn roster_for_round(&self, round: u64) -> &MembershipRegistry {
        self.snapshots
            .range(..=round)
            .next_back()
            .map(|(_, reg)| reg)
            .expect("roster_for_round called with round 0 or before any snapshot")
    }

    /// Records a new registry snapshot that activates at `activation_round`.
    /// Idempotent: a second call with the same round overwrites the previous
    /// snapshot (all nodes derive the same registry from the same finalized
    /// op, so the result is always identical).
    pub fn schedule(&mut self, activation_round: u64, registry: MembershipRegistry) {
        self.snapshots.insert(activation_round, registry);
    }
}

/// Reads exactly `len` bytes from `cursor`, advancing it past them. Returns
/// `MalformedOp` if fewer than `len` bytes remain.
fn take_exact<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let head = cursor.get(..len).ok_or(CryptoError::MalformedOp)?;
    *cursor = &cursor[len..];
    Ok(head)
}

fn take_u64(cursor: &mut &[u8]) -> Result<u64> {
    let bytes = take_exact(cursor, 8)?;
    let value = u64::from_be_bytes(bytes.try_into().map_err(|_| CryptoError::MalformedOp)?);
    Ok(value)
}

fn take_u16(cursor: &mut &[u8]) -> Result<u16> {
    let bytes = take_exact(cursor, 2)?;
    let value = u16::from_be_bytes(bytes.try_into().map_err(|_| CryptoError::MalformedOp)?);
    Ok(value)
}

/// Reads the 32-byte Ed25519 verifying key from `cursor`. Returns
/// `MalformedOp` if the bytes are not a valid compressed Edwards point.
fn take_key(cursor: &mut &[u8]) -> Result<VerifyingKey> {
    let bytes = take_exact(cursor, 32)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| CryptoError::MalformedOp)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| CryptoError::MalformedOp)
}

/// Reads one length-prefixed field from `cursor`, advancing it past the
/// field. Returns `MalformedOp` if the declared length overruns the payload.
fn take_bytes(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    let head = cursor.get(..4).ok_or(CryptoError::MalformedOp)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let end = 4usize.checked_add(len).ok_or(CryptoError::MalformedOp)?;
    let body = cursor.get(4..end).ok_or(CryptoError::MalformedOp)?;
    let bytes = body.to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}

/// Reads the length-prefixed `SocketAddr` field from `cursor`. The field body
/// is `[tag: u8]` (`0x04` = IPv4, `0x06` = IPv6) followed by the IP bytes and
/// a big-endian `u16` port.
fn take_addr(cursor: &mut &[u8]) -> Result<SocketAddr> {
    let encoded = take_bytes(cursor)?;
    let (&tag, mut rest) = encoded.split_first().ok_or(CryptoError::MalformedOp)?;
    let ip = match tag {
        ADDR_IPV4 => {
            let bytes = take_exact(&mut rest, 4)?;
            IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
        }
        ADDR_IPV6 => {
            let bytes = take_exact(&mut rest, 16)?;
            let arr: [u8; 16] = bytes.try_into().map_err(|_| CryptoError::MalformedOp)?;
            IpAddr::V6(Ipv6Addr::from(arr))
        }
        _ => return Err(CryptoError::MalformedOp),
    };
    let port = take_u16(&mut rest)?;
    reject_trailing(rest)?;
    Ok(SocketAddr::new(ip, port))
}

fn reject_trailing(cursor: &[u8]) -> Result<()> {
    if cursor.is_empty() { Ok(()) } else { Err(CryptoError::MalformedOp) }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn encode_addr(addr: &SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr.ip() {
        IpAddr::V4(ip) => {
            buf.push(ADDR_IPV4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(ADDR_IPV6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    fn add_op(addr: SocketAddr) -> MembershipOp {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        MembershipOp::Add { node: NodeId::new(1), key: Box::new(verifying_key), addr }
    }

    #[test]
    fn add_ipv4_round_trips_through_encode_decode() {
        let op = add_op(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080));
        assert_eq!(MembershipOp::decode(&op.encode()), Ok(op));
    }

    #[test]
    fn add_ipv6_round_trips_through_encode_decode() {
        let op = add_op(SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            8080,
        ));
        assert_eq!(MembershipOp::decode(&op.encode()), Ok(op));
    }

    #[test]
    fn remove_round_trips_through_encode_decode() {
        let op = MembershipOp::Remove { node: NodeId::new(1) };
        assert_eq!(MembershipOp::decode(&op.encode()), Ok(op));
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(MembershipOp::decode(&[]), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        assert_eq!(MembershipOp::decode(&[0x7f]), Err(CryptoError::UnknownMembershipOpcode(0x7f)));
    }

    #[test]
    fn truncated_node_id_is_rejected() {
        assert_eq!(MembershipOp::decode(&[MEMBERSHIP_ADD]), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn truncated_key_is_rejected() {
        let mut payload = Vec::new();
        payload.push(MEMBERSHIP_ADD);
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&[0u8; 20]);
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn truncated_addr_tag_is_rejected() {
        let mut payload = Vec::new();
        payload.push(MEMBERSHIP_ADD);
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
        // The addr length prefix declares an empty addr blob, so no tag follows.
        payload.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn truncated_addr_bytes_is_rejected() {
        let mut payload = Vec::new();
        payload.push(MEMBERSHIP_ADD);
        payload.extend_from_slice(&1u64.to_be_bytes());
        payload.extend_from_slice(&SigningKey::generate(&mut OsRng).verifying_key().to_bytes());
        // The addr blob declares 3 bytes; an IPv4 addr needs 7, IPv6 needs 19.
        payload.extend_from_slice(&3u32.to_be_bytes());
        payload.extend_from_slice(&[ADDR_IPV4, 0x01, 0x02]);
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn trailing_bytes_after_remove_are_rejected() {
        let mut payload = MembershipOp::Remove { node: NodeId::new(1) }.encode();
        payload.push(0xff);
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn trailing_bytes_after_add_are_rejected() {
        let mut payload =
            add_op(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080)).encode();
        payload.push(0xff);
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    #[test]
    fn invalid_key_bytes_are_rejected() {
        let mut payload = Vec::new();
        payload.push(MEMBERSHIP_ADD);
        payload.extend_from_slice(&1u64.to_be_bytes());
        // A y-coordinate of 2 encodes no valid Edwards point.
        payload.extend_from_slice(&[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8080);
        write_bytes(&mut payload, &encode_addr(&addr));
        assert_eq!(MembershipOp::decode(&payload), Err(CryptoError::MalformedOp));
    }

    mod roster_history_tests {
        use super::*;

        fn registry_with(members: &[u64]) -> MembershipRegistry {
            let mut registry = MembershipRegistry::new();
            for id in members {
                let key = SigningKey::generate(&mut OsRng).verifying_key();
                registry.register(NodeId::new(*id), key);
            }
            registry
        }

        #[test]
        fn genesis_snapshot_is_active_at_round_one() {
            let history = RosterHistory::new(registry_with(&[1]));
            assert_eq!(history.roster_for_round(1).len(), 1);
        }

        #[test]
        fn roster_for_round_returns_predecessor_snapshot() {
            let mut history = RosterHistory::new(registry_with(&[1]));
            history.schedule(5, registry_with(&[1, 2]));
            assert_eq!(history.roster_for_round(4).len(), 1);
        }

        #[test]
        fn roster_for_round_at_exact_activation_round() {
            let mut history = RosterHistory::new(registry_with(&[1]));
            history.schedule(5, registry_with(&[1, 2]));
            assert_eq!(history.roster_for_round(5).len(), 2);
        }

        #[test]
        fn schedule_overwrites_existing_round() {
            let mut history = RosterHistory::new(registry_with(&[1]));
            history.schedule(5, registry_with(&[1, 2]));
            history.schedule(5, registry_with(&[1, 2, 3]));
            assert_eq!(history.roster_for_round(5).len(), 3);
        }
    }
}
