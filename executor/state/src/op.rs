//! The transaction payload format (Phase 8).
//!
//! A `Transaction`'s payload bytes decode into exactly one [`Op`] before the
//! executor applies it to the state. The format is a deliberately tiny,
//! explicit binary encoding with no external dependencies:
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
//! | `0x02` | `MembershipOp` | (decoded by `crypto::MembershipOp`, not here) |
//!
//! A `Put` writes (or overwrites) `value` under `key`; a `Delete` removes
//! `key` (a no-op if absent). Every other opcode byte, a payload too short
//! for its declared fields, or trailing bytes after the last field decodes
//! to a deterministic [`ExecutorError`] — identical bytes always produce the
//! identical outcome on every node. The big-endian length prefix mirrors the
//! `u32` length convention used by `crypto`'s canonical encoding
//! (`CanonicalEncode` for `Transaction`).

use crate::error::{
    ExecutorError,
    Result,
};

const OP_PUT: u8 = 0x00;
const OP_DELETE: u8 = 0x01;

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
    use super::*;

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
}
