//! The executor's state (Phase 8).
//!
//! A minimal key-value store: every key and value is an opaque byte string.
//! The map is a `BTreeMap`, so iteration order is the ascending byte order of
//! the keys — deterministic on every node, which is what makes [`State`]
//! equality and the canonical serialization [`State::to_bytes`] meaningful.
//!
//! All mutation flows through [`State::apply`], a pure, deterministic
//! function: it reads nothing but its arguments and performs no I/O, so the
//! same sequence of operations always produces the same resulting state.

use std::collections::BTreeMap;

use crate::op::Op;

/// The executor's key-value state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct State {
    entries: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl State {
    pub fn new() -> Self {
        Self::default()
    }

    /// The value stored under `key`, if any.
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.entries.get(key).map(Vec::as_slice)
    }

    /// Whether `key` is present in the state, regardless of its value.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.entries.contains_key(key)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Applies `op` to the state. A `Put` writes or overwrites; a `Delete`
    /// removes the key (a no-op when it is absent). Deterministic and pure.
    pub fn apply(&mut self, op: &Op) {
        match op {
            Op::Put { key, value } => {
                self.entries.insert(key.clone(), value.clone());
            }
            Op::Delete { key } => {
                self.entries.remove(key);
            }
        }
    }

    /// Canonical byte serialization of the state: one length-prefixed
    /// (key, value) pair per entry, in ascending key order. Two states that
    /// are `==` serialize to identical bytes, so this is the check to use for
    /// "bit-identical state across nodes".
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for (key, value) in &self.entries {
            write_bytes(&mut buf, key);
            write_bytes(&mut buf, value);
        }
        buf
    }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_then_get_returns_value() {
        let mut state = State::new();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        assert_eq!(state.get(b"k"), Some(&b"v"[..]));
    }

    #[test]
    fn put_overwrites_existing_value() {
        let mut state = State::new();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v1".to_vec() });
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v2".to_vec() });
        assert_eq!(state.get(b"k"), Some(&b"v2"[..]));
    }

    #[test]
    fn delete_removes_key() {
        let mut state = State::new();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        state.apply(&Op::Delete { key: b"k".to_vec() });
        assert_eq!(state.get(b"k"), None);
        assert!(state.is_empty());
    }

    #[test]
    fn delete_of_absent_key_is_a_no_op() {
        let mut state = State::new();
        state.apply(&Op::Delete { key: b"missing".to_vec() });
        assert!(state.is_empty());
    }

    #[test]
    fn to_bytes_is_canonical_and_deterministic() {
        let mut state = State::new();
        state.apply(&Op::Put { key: b"b".to_vec(), value: b"2".to_vec() });
        state.apply(&Op::Put { key: b"a".to_vec(), value: b"1".to_vec() });

        let mut expected = Vec::new();
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"a");
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"1");
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"b");
        expected.extend_from_slice(&1u32.to_be_bytes());
        expected.extend_from_slice(b"2");

        assert_eq!(state.to_bytes(), expected);
    }
}
