//! The executor's state (Phase 8).
//!
//! A key-value store backed by a Fjall LSM partition (with a write-ahead
//! log): every key and value is an opaque byte string, and the partition is
//! sorted by key, so iteration is the ascending byte order — deterministic
//! on every node, which is what makes [`State`] equality and the canonical
//! serialization [`State::to_bytes`] meaningful.
//!
//! All mutation flows through [`State::apply`], a deterministic function: it
//! reads nothing external and performs no non-deterministic I/O, so the same
//! sequence of operations always produces the same resulting state. Writes to
//! the backing partition are lossy — a storage error is logged and the op is
//! still applied to the in-memory Merkle tree, so the consensus-hot path never
//! fails on storage hiccups (the durable source of truth on restart is the
//! per-accepted-round snapshot in `StateDb`, not the live partition).

use std::sync::Arc;

use fjall::Keyspace;

use crate::merkle::{
    MerkleProof,
    SparseMerkleTree,
};
use crate::op::Op;

/// The executor's key-value state, backed by a Fjall LSM partition.
pub struct State {
    kv: Arc<Keyspace>,
    tree: SparseMerkleTree,
}

impl State {
    /// Creates a `State` over the given keyspace. The keyspace must be empty
    /// (freshly opened, or cleared via `StateDb::clear_state`).
    pub fn new(kv: Arc<Keyspace>) -> Self {
        Self { kv, tree: SparseMerkleTree::new() }
    }

    /// The value stored under `key`, if any.
    pub fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.kv.get(key).ok().flatten().map(|value| value.as_slice().to_vec())
    }

    /// Whether `key` is present in the state, regardless of its value.
    pub fn contains(&self, key: &[u8]) -> bool {
        self.get(key).is_some()
    }

    pub fn len(&self) -> usize {
        self.kv.len().unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The Merkle root over the state — the deterministic commitment a
    /// checkpoint commits to as its `state_hash` (Phase 8).
    pub fn root(&self) -> [u8; 32] {
        self.tree.root()
    }

    /// A Merkle proof of inclusion for `key`, or `None` when `key` is absent.
    pub fn proof(&self, key: &[u8]) -> Option<MerkleProof> {
        let value = self.get(key)?;
        let siblings = self.tree.proof_siblings(key)?;
        Some(MerkleProof { key: key.to_vec(), value, siblings })
    }

    /// Applies `op` to the state. A `Put` writes or overwrites; a `Delete`
    /// removes the key (a no-op when it is absent). Deterministic: each
    /// operation writes the partition in O(1) and updates the Merkle tree in
    /// O(depth), so [`State::root`] stays in sync with the partition at all
    /// times. A storage error is logged and dropped — the op still updates
    /// the tree, and the next accepted checkpoint snapshot restores the
    /// durable truth.
    pub fn apply(&mut self, op: &Op) {
        match op {
            Op::Put { key, value } => {
                if let Err(e) = self.kv.insert(key.as_slice(), value.as_slice()) {
                    eprintln!("[state] failed to persist Put: {e}");
                }
                self.tree.insert(key, value);
            }
            Op::Delete { key } => {
                if let Err(e) = self.kv.remove(key.as_slice()) {
                    eprintln!("[state] failed to persist Delete: {e}");
                }
                self.tree.delete(key);
            }
        }
    }

    /// Canonical byte serialization of the state: one length-prefixed
    /// (key, value) pair per entry, in ascending key order. Two states that
    /// are `==` serialize to identical bytes, so this is the check to use for
    /// "bit-identical state across nodes".
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for guard in self.kv.iter() {
            let Ok((key, value)) = guard.into_inner() else {
                break;
            };
            write_bytes(&mut buf, key.as_slice());
            write_bytes(&mut buf, value.as_slice());
        }
        buf
    }

    /// The inverse of [`State::to_bytes`]: parses the length-prefixed
    /// (key, value) pairs in the exact format `to_bytes` produces and stores
    /// them into `kv`, rebuilding the Merkle tree. The keyspace must be empty
    /// (use `StateDb::clear_state` first). Returns `None` on any truncation,
    /// length overflow, or storage failure. Empty bytes decode to an empty
    /// `State`.
    pub fn from_bytes(kv: Arc<Keyspace>, bytes: &[u8]) -> Option<Self> {
        let mut state = Self::new(kv);
        let mut cursor = bytes;
        while !cursor.is_empty() {
            let key = read_bytes(&mut cursor)?;
            let value = read_bytes(&mut cursor)?;
            state.kv.insert(key.as_slice(), value.as_slice()).ok()?;
            state.tree.insert(&key, &value);
        }
        Some(state)
    }
}

impl Clone for State {
    /// Shares the backing partition: clones refer to the same keyspace, so
    /// reads observe the same entries. Comparison is by canonical bytes.
    fn clone(&self) -> Self {
        Self { kv: Arc::clone(&self.kv), tree: self.tree.clone() }
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("State").field("len", &self.len()).field("root", &self.root()).finish()
    }
}

impl PartialEq for State {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for State {}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_bytes(bytes: &mut &[u8]) -> Option<Vec<u8>> {
    if bytes.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().ok()?) as usize;
    let end = 4usize.checked_add(len)?;
    if bytes.len() < end {
        return None;
    }
    let out = bytes[4..end].to_vec();
    *bytes = &bytes[end..];
    Some(out)
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::StateDb;

    fn new_state() -> State {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        State::new(db.state_keyspace())
    }

    #[test]
    fn put_then_get_returns_value() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        assert_eq!(state.get(b"k"), Some(b"v".to_vec()));
    }

    #[test]
    fn put_overwrites_existing_value() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v1".to_vec() });
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v2".to_vec() });
        assert_eq!(state.get(b"k"), Some(b"v2".to_vec()));
    }

    #[test]
    fn delete_removes_key() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        state.apply(&Op::Delete { key: b"k".to_vec() });
        assert_eq!(state.get(b"k"), None);
        assert!(state.is_empty());
    }

    #[test]
    fn delete_of_absent_key_is_a_no_op() {
        let mut state = new_state();
        state.apply(&Op::Delete { key: b"missing".to_vec() });
        assert!(state.is_empty());
    }

    #[test]
    fn to_bytes_is_canonical_and_deterministic() {
        let mut state = new_state();
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

    #[test]
    fn from_bytes_round_trips() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"alpha".to_vec(), value: vec![0; 200] });
        state.apply(&Op::Put { key: b"beta".to_vec(), value: b"v".to_vec() });
        state.apply(&Op::Delete { key: b"gamma".to_vec() });

        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let rebuilt = State::from_bytes(db.state_keyspace(), &state.to_bytes()).expect("rebuilds");
        assert_eq!(rebuilt, state);
    }

    #[test]
    fn from_bytes_rejects_truncated_input() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"value".to_vec() });
        let bytes = state.to_bytes();

        // Truncate inside the length prefix, inside the key, and inside the value.
        assert_eq!(State::from_bytes(new_state().kv, &bytes[..1]), None);
        assert_eq!(State::from_bytes(new_state().kv, &bytes[..bytes.len() - 5]), None);
        assert_eq!(State::from_bytes(new_state().kv, &bytes[..bytes.len() - 1]), None);
    }

    #[test]
    fn from_bytes_rejects_overflowing_length() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        let bytes = state.to_bytes();
        // A length prefix claiming more bytes than the buffer holds.
        let mut bad = bytes[..4].to_vec();
        bad.extend_from_slice(&u32::MAX.to_be_bytes());
        bad.extend_from_slice(b"x");
        assert_eq!(State::from_bytes(new_state().kv, &bad), None);
    }

    #[test]
    fn from_bytes_empty_is_empty_state() {
        assert_eq!(State::from_bytes(new_state().kv, &[]), Some(new_state()));
    }

    #[test]
    fn root_is_deterministic_across_equivalent_states() {
        let mut left = new_state();
        left.apply(&Op::Put { key: b"a".to_vec(), value: b"1".to_vec() });
        left.apply(&Op::Put { key: b"b".to_vec(), value: b"2".to_vec() });

        let mut right = new_state();
        right.apply(&Op::Put { key: b"b".to_vec(), value: b"2".to_vec() });
        right.apply(&Op::Put { key: b"a".to_vec(), value: b"1".to_vec() });

        assert_eq!(left.root(), right.root());
        assert_ne!(left.root(), State::new(new_state().kv).root());
    }

    #[test]
    fn proof_verifies_against_root() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        let root = state.root();
        let proof = state.proof(b"k").expect("present");
        assert_eq!(proof.value, b"v");
        assert!(proof.verify(&root));
        assert!(state.proof(b"missing").is_none());
    }

    #[test]
    fn from_bytes_rebuilds_the_tree() {
        let mut state = new_state();
        state.apply(&Op::Put { key: b"k".to_vec(), value: b"v".to_vec() });
        let rebuilt = State::from_bytes(new_state().kv, &state.to_bytes()).expect("decodes");
        assert_eq!(rebuilt.root(), state.root());
        let proof = rebuilt.proof(b"k").expect("present");
        assert!(proof.verify(&state.root()));
    }
}
