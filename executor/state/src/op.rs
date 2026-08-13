//! The transaction payload format (Phase 8).
//!
//! A `Transaction`'s payload bytes decode into exactly one [`DecodedOp`] — a
//! pure-KV [`Op`] or a [`MembershipOp`] side channel — before the executor
//! applies it to the state. The format is a deliberately tiny, explicit
//! binary encoding with no external dependencies:
//!
//! ```text
//! [opcode: u8]
//! [field: u32 (big-endian) byte length + raw bytes]
//! ```
//!
//! | opcode | meaning  | fields       |
//! |--------|----------|--------------|
//! | `0x00` | `Put`    | key, value   |
//! | `0x01` | `Delete` | key          |
//! | `0x02` | `MembershipOp` | decoded by `crypto::MembershipOp::decode` (body only, no `0x02` prefix) |
//!
//! A `Put` writes (or overwrites) `value` under `key`; a `Delete` removes
//! `key` (a no-op if absent). A `MembershipOp` never touches `State` — the
//! executor hands it back as a side channel. Every other opcode byte, a
//! payload too short for its declared fields, or trailing bytes after the
//! last field decodes to a deterministic [`ExecutorError`] — identical bytes
//! always produce the identical outcome on every node. The big-endian length
//! prefix mirrors the `u32` length convention used by `crypto`'s canonical
//! encoding (`CanonicalEncode` for `Transaction`).

use crypto::MembershipOp;

use crate::error::{
    ExecutorError,
    Result,
};

const OP_PUT: u8 = 0x00;
const OP_DELETE: u8 = 0x01;
const OP_MEMBERSHIP: u8 = 0x02;

/// A single state transition decoded from a `Transaction` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// Writes `value` under `key`, replacing any existing value.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Removes `key` from the state, if present.
    Delete { key: Vec<u8> },
}

impl Op {
    /// Decodes `payload` into the operation it encodes.
    ///
    /// Deterministic by construction: the same bytes always yield the same
    /// `Op` or the same `ExecutorError`.
    pub fn decode(payload: &[u8]) -> Result<Op> {
        let (&opcode, mut cursor) = payload.split_first().ok_or(ExecutorError::EmptyPayload)?;
        // The opcode is matched before any field is read, so an unknown
        // opcode is reported even when the rest of the payload is truncated.
        match opcode {
            OP_PUT => {
                let key = take_bytes(&mut cursor)?;
                let value = take_bytes(&mut cursor)?;
                reject_trailing(cursor)?;
                Ok(Op::Put { key, value })
            }
            OP_DELETE => {
                let key = take_bytes(&mut cursor)?;
                reject_trailing(cursor)?;
                Ok(Op::Delete { key })
            }
            _ => Err(ExecutorError::UnknownOpcode(opcode)),
        }
    }

    /// The canonical encoding of this operation — the inverse of
    /// [`Op::decode`]. `decode(&op.encode())` returns `Ok(op)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Op::Put { key, value } => {
                buf.push(OP_PUT);
                write_bytes(&mut buf, key);
                write_bytes(&mut buf, value);
            }
            Op::Delete { key } => {
                buf.push(OP_DELETE);
                write_bytes(&mut buf, key);
            }
        }
        buf
    }
}

/// The result of decoding a single transaction payload. KV operations go to
/// `State`; membership operations are returned as a side channel and never
/// touch `State`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodedOp {
    Kv(Op),
    Membership(MembershipOp),
}

impl DecodedOp {
    /// Decodes `payload` into the operation it encodes.
    ///
    /// Deterministic by construction: the same bytes always yield the same
    /// `DecodedOp` or the same `ExecutorError`.
    pub fn decode(payload: &[u8]) -> Result<DecodedOp> {
        let (&opcode, cursor) = payload.split_first().ok_or(ExecutorError::EmptyPayload)?;
        match opcode {
            OP_PUT => {
                let mut cursor = cursor;
                let key = take_bytes(&mut cursor)?;
                let value = take_bytes(&mut cursor)?;
                reject_trailing(cursor)?;
                Ok(DecodedOp::Kv(Op::Put { key, value }))
            }
            OP_DELETE => {
                let mut cursor = cursor;
                let key = take_bytes(&mut cursor)?;
                reject_trailing(cursor)?;
                Ok(DecodedOp::Kv(Op::Delete { key }))
            }
            OP_MEMBERSHIP => {
                // `cursor` is already the body slice — the outer 0x02 type
                // tag was consumed above. `MembershipOp::decode` receives
                // bytes starting with the inner 0x00 (Add) or 0x01 (Remove)
                // opcode. No re-assembly needed.
                MembershipOp::decode(cursor)
                    .map(DecodedOp::Membership)
                    .map_err(|_| ExecutorError::MalformedMembershipOp)
            }
            _ => Err(ExecutorError::UnknownOpcode(opcode)),
        }
    }
}

/// Reads one length-prefixed field from `cursor`, advancing it past the
/// field. Returns `Truncated` if the declared length overruns the payload.
fn take_bytes(cursor: &mut &[u8]) -> Result<Vec<u8>> {
    let head = cursor.get(..4).ok_or(ExecutorError::Truncated)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let end = 4usize.checked_add(len).ok_or(ExecutorError::Truncated)?;
    let body = cursor.get(4..end).ok_or(ExecutorError::Truncated)?;
    let bytes = body.to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}

fn reject_trailing(cursor: &[u8]) -> Result<()> {
    if cursor.is_empty() { Ok(()) } else { Err(ExecutorError::TrailingBytes) }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use primitives::NodeId;

    use super::*;

    fn add_membership_op() -> MembershipOp {
        MembershipOp::Add {
            node: NodeId::new(7),
            key: Box::new(SigningKey::from_bytes(&[1u8; 32]).verifying_key()),
            addr: "127.0.0.1:7000".parse().expect("valid addr"),
            reconnect_addr: None,
        }
    }

    #[test]
    fn put_round_trips_through_encode_decode() {
        let op = Op::Put { key: b"alice".to_vec(), value: b"100".to_vec() };
        assert_eq!(Op::decode(&op.encode()), Ok(op));
    }

    #[test]
    fn delete_round_trips_through_encode_decode() {
        let op = Op::Delete { key: b"alice".to_vec() };
        assert_eq!(Op::decode(&op.encode()), Ok(op));
    }

    #[test]
    fn empty_payload_is_rejected() {
        assert_eq!(Op::decode(&[]), Err(ExecutorError::EmptyPayload));
    }

    #[test]
    fn unknown_opcode_is_rejected() {
        let payload = [0x7f, 0, 0, 0, 0];
        assert_eq!(Op::decode(&payload), Err(ExecutorError::UnknownOpcode(0x7f)));
    }

    #[test]
    fn truncated_length_prefix_is_rejected() {
        assert_eq!(Op::decode(&[OP_PUT, 0, 0]), Err(ExecutorError::Truncated));
    }

    #[test]
    fn declared_length_overrunning_payload_is_rejected() {
        // Put with key_len = 10 but only two key bytes present.
        let payload = [OP_PUT, 0, 0, 0, 10, 1, 2];
        assert_eq!(Op::decode(&payload), Err(ExecutorError::Truncated));
    }

    #[test]
    fn trailing_bytes_after_last_field_are_rejected() {
        let mut payload = Op::Delete { key: b"k".to_vec() }.encode();
        payload.push(0xff);
        assert_eq!(Op::decode(&payload), Err(ExecutorError::TrailingBytes));
    }

    #[test]
    fn put_with_missing_value_is_rejected() {
        // Delete-shaped bytes under the Put opcode: key present, no value.
        let mut payload = Op::Delete { key: b"k".to_vec() }.encode();
        payload[0] = OP_PUT;
        assert_eq!(Op::decode(&payload), Err(ExecutorError::Truncated));
    }

    #[test]
    fn membership_op_round_trips_through_decoded_op() {
        let op = add_membership_op();
        let mut payload = vec![OP_MEMBERSHIP];
        payload.extend_from_slice(&op.encode());
        assert_eq!(DecodedOp::decode(&payload), Ok(DecodedOp::Membership(op)));
    }

    #[test]
    fn kv_ops_decode_to_kv_variant() {
        let put = Op::Put { key: b"k".to_vec(), value: b"v".to_vec() };
        assert_eq!(DecodedOp::decode(&put.encode()), Ok(DecodedOp::Kv(put)));
    }

    #[test]
    fn malformed_membership_body_is_rejected() {
        // 0x02 followed by a truncated Add body (opcode but no node id).
        let payload = [OP_MEMBERSHIP, 0x00];
        assert_eq!(DecodedOp::decode(&payload), Err(ExecutorError::MalformedMembershipOp));
    }

    #[test]
    fn unknown_opcode_under_decoded_op_is_rejected() {
        let payload = [0x7f];
        assert_eq!(DecodedOp::decode(&payload), Err(ExecutorError::UnknownOpcode(0x7f)));
    }
}
