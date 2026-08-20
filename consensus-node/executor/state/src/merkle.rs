//! Sparse Merkle tree over the KV state (Phase 8, "Merkle tree state").
//!
//! A 256-bit sparse Merkle tree: each key's path index is `SHA-256(key)`, and
//! leaves commit to the raw key and value behind a domain-separation prefix so
//! a leaf can never collide with an internal node. The node hashing follows
//! the Hiero/Hedera convention:
//!
//! ```text
//! empty subtree          = SHA256(0x00)
//! leaf(key, value)       = SHA256(0x00 || len(key) || key || len(value) || value)
//! internal(left, right)  = SHA256(0x02 || left || right)
//! singleton(child)       = SHA256(0x01 || child)
//! ```
//!
//! `len` is the `u32` big-endian length prefix used by the rest of the
//! canonical encodings (`State::to_bytes`, `Op`). It disambiguates
//! `("ab", "c")` from `("a", "bc")` and keeps the empty leaf distinct from the
//! empty subtree. Inserting or deleting a key recomputes only the O(depth)
//! branch hashes on the affected path, so a per-round checkpoint root is cheap
//! regardless of state size.

use std::collections::HashMap;
use std::sync::LazyLock;

use sha2::{
    Digest,
    Sha256,
};

/// The hash width (SHA-256): 32 bytes.
pub type Hash = [u8; 32];

/// Tree depth: a full 256-bit path, one bit per level.
const DEPTH: u16 = 256;

/// The empty-subtree hash, `SHA256(0x00)`: the "zero" of every internal node.
static EMPTY: LazyLock<Hash> = LazyLock::new(|| Sha256::digest([0x00u8]).into());

fn empty() -> Hash {
    *EMPTY
}

/// The path index of `key`: `SHA-256(key)` interpreted as a 256-bit big-endian
/// bit string (bit 0 is the most significant bit of `path[0]`).
pub fn path_of(key: &[u8]) -> Hash {
    Sha256::digest(key).into()
}

fn leaf_hash(key: &[u8], value: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key);
    hasher.update((value.len() as u32).to_be_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

fn internal(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x02u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn singleton(child: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(child);
    hasher.finalize().into()
}

/// Combines a left and right child hash into a parent hash, applying the
/// singleton rule when exactly one child is empty.
fn combine(left: Hash, right: Hash) -> Hash {
    match (left == empty(), right == empty()) {
        (true, true) => empty(),
        (true, false) => singleton(right),
        (false, true) => singleton(left),
        (false, false) => internal(left, right),
    }
}

/// The bit of `path` at `bit` (bit 0 is the most significant bit of
/// `path[0]`).
fn bit(path: &Hash, bit: u16) -> u8 {
    let byte = (bit / 8) as usize;
    let shift = 7 - (bit % 8);
    (path[byte] >> shift) & 1
}

fn flip(mut path: Hash, bit: u16) -> Hash {
    let byte = (bit / 8) as usize;
    let shift = 7 - (bit % 8);
    path[byte] ^= 1 << shift;
    path
}

/// Masks `path` to its first `depth` bits, zeroing the rest: the canonical key
/// for the branch node at `depth`.
fn mask(path: &Hash, depth: u16) -> Hash {
    let mut out = *path;
    let full = (depth / 8) as usize;
    let rem = depth % 8;
    let zero_from = if rem == 0 { full } else { full + 1 };
    for byte in out.iter_mut().skip(zero_from) {
        *byte = 0;
    }
    if rem != 0 {
        out[full] &= 0xFFu8 << (8 - rem);
    }
    out
}

/// A sparse Merkle tree over the KV state.
///
/// Stores only leaf hashes (keyed by full path) and branch-node hashes (keyed
/// by `(depth, masked prefix)`), so a `Put`/`Delete` recomputes exactly the
/// O(depth) nodes on the affected path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMerkleTree {
    leaves: HashMap<Hash, Hash>,
    nodes: HashMap<(u16, Hash), Hash>,
    root: Hash,
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self { leaves: HashMap::new(), nodes: HashMap::new(), root: empty() }
    }
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// The Merkle root — the current state commitment.
    pub fn root(&self) -> Hash {
        self.root
    }

    /// Inserts (or overwrites) `value` under `key`, recomputing O(depth)
    /// branch hashes.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) {
        let path = path_of(key);
        let leaf = leaf_hash(key, value);
        self.leaves.insert(path, leaf);
        let mut current = leaf;
        for depth in (0..DEPTH).rev() {
            let sibling = self.subtree_hash(depth + 1, flip(path, depth));
            let (left, right) =
                if bit(&path, depth) == 0 { (current, sibling) } else { (sibling, current) };
            current = combine(left, right);
            self.set_branch(depth, mask(&path, depth), current);
        }
        self.root = current;
    }

    /// Removes `key`. Returns `false` (leaving the root unchanged) when the
    /// key was absent.
    pub fn delete(&mut self, key: &[u8]) -> bool {
        let path = path_of(key);
        if self.leaves.remove(&path).is_none() {
            return false;
        }
        let mut current = empty();
        for depth in (0..DEPTH).rev() {
            let sibling = self.subtree_hash(depth + 1, flip(path, depth));
            let (left, right) =
                if bit(&path, depth) == 0 { (current, sibling) } else { (sibling, current) };
            current = combine(left, right);
            self.set_branch(depth, mask(&path, depth), current);
        }
        self.root = current;
        true
    }

    /// The sibling hashes along `key`'s path, from the leaf's sibling (depth
    /// 255) up to the root's child (depth 0). `None` when `key` is absent.
    pub fn proof_siblings(&self, key: &[u8]) -> Option<Vec<Hash>> {
        let path = path_of(key);
        if !self.leaves.contains_key(&path) {
            return None;
        }
        Some(
            (0..DEPTH).rev().map(|depth| self.subtree_hash(depth + 1, flip(path, depth))).collect(),
        )
    }

    /// The hash of the subtree rooted at `depth` along `path`.
    fn subtree_hash(&self, depth: u16, path: Hash) -> Hash {
        if depth == DEPTH {
            return self.leaves.get(&path).copied().unwrap_or_else(empty);
        }
        self.nodes.get(&(depth, mask(&path, depth))).copied().unwrap_or_else(empty)
    }

    /// Stores or removes a branch-node hash: an empty hash is removed so the
    /// node map never keeps stale entries.
    fn set_branch(&mut self, depth: u16, path: Hash, hash: Hash) {
        if hash == empty() {
            self.nodes.remove(&(depth, path));
        } else {
            self.nodes.insert((depth, path), hash);
        }
    }
}

/// A Merkle proof of inclusion: the key, its committed value, and the sibling
/// hashes along the path from the leaf to the root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MerkleProof {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
    /// Sibling hashes from the leaf's sibling (depth 255) up to the root's
    /// child (depth 0). Always [`DEPTH`] entries.
    pub siblings: Vec<Hash>,
}

impl MerkleProof {
    /// Verifies this proof against `root`: recomputes the leaf hash and walks
    /// the sibling path back up to the root.
    pub fn verify(&self, root: &Hash) -> bool {
        if self.siblings.len() != DEPTH as usize {
            return false;
        }
        let path = path_of(&self.key);
        let mut current = leaf_hash(&self.key, &self.value);
        for (depth, &sibling) in (0..DEPTH).rev().zip(&self.siblings) {
            let (left, right) =
                if bit(&path, depth) == 0 { (current, sibling) } else { (sibling, current) };
            current = combine(left, right);
        }
        current == *root
    }

    /// Canonical encoding:
    /// `key_len || key || value_len || value || siblings_len || siblings`,
    /// with `u32` big-endian lengths and 32-byte sibling hashes.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf =
            Vec::with_capacity(8 + self.key.len() + self.value.len() + self.siblings.len() * 32);
        write_bytes(&mut buf, &self.key);
        write_bytes(&mut buf, &self.value);
        buf.extend_from_slice(&(self.siblings.len() as u32).to_be_bytes());
        for sibling in &self.siblings {
            buf.extend_from_slice(sibling);
        }
        buf
    }

    /// The inverse of [`MerkleProof::encode`]. `None` on truncation, trailing
    /// bytes, or a sibling count that is not [`DEPTH`].
    pub fn decode(mut bytes: &[u8]) -> Option<Self> {
        let key = read_bytes(&mut bytes)?;
        let value = read_bytes(&mut bytes)?;
        let count = read_u32(&mut bytes)? as usize;
        if count != DEPTH as usize {
            return None;
        }
        let mut siblings = Vec::with_capacity(count);
        for _ in 0..count {
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(read_exact(&mut bytes, 32)?);
            siblings.push(sibling);
        }
        if !bytes.is_empty() {
            return None;
        }
        Some(Self { key, value, siblings })
    }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_bytes(bytes: &mut &[u8]) -> Option<Vec<u8>> {
    let len = read_u32(bytes)? as usize;
    Some(read_exact(bytes, len)?.to_vec())
}

fn read_u32(bytes: &mut &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(read_exact(bytes, 4)?.try_into().ok()?))
}

fn read_exact<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let head = bytes.get(..len)?;
    *bytes = &bytes[len..];
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(bytes: &[u8]) -> Hash {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn empty_root_is_hash_of_single_zero_byte() {
        assert_eq!(SparseMerkleTree::new().root(), hash(&[0x00]));
    }

    #[test]
    fn insert_then_proof_verifies() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let root = tree.root();
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"v".to_vec(), siblings };
        assert!(proof.verify(&root));
    }

    #[test]
    fn proof_fails_for_wrong_value() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let root = tree.root();
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"wrong".to_vec(), siblings };
        assert!(!proof.verify(&root));
    }

    #[test]
    fn proof_fails_for_wrong_root() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"v".to_vec(), siblings };
        assert!(!proof.verify(&hash(b"not the root")));
    }

    #[test]
    fn absent_key_has_no_proof() {
        let tree = SparseMerkleTree::new();
        assert!(tree.proof_siblings(b"missing").is_none());
    }

    #[test]
    fn root_is_order_independent() {
        let mut left = SparseMerkleTree::new();
        left.insert(b"a", b"1");
        left.insert(b"b", b"2");

        let mut right = SparseMerkleTree::new();
        right.insert(b"b", b"2");
        right.insert(b"a", b"1");

        assert_eq!(left.root(), right.root());
    }

    #[test]
    fn overwrite_changes_root_and_delete_restores() {
        let mut tree = SparseMerkleTree::new();
        let empty_root = tree.root();
        tree.insert(b"k", b"v1");
        let root1 = tree.root();
        assert_ne!(root1, empty_root);

        tree.insert(b"k", b"v2");
        let root2 = tree.root();
        assert_ne!(root2, root1);

        tree.insert(b"other", b"x");
        let root3 = tree.root();
        assert_ne!(root3, root2);

        assert!(tree.delete(b"other"));
        assert_eq!(tree.root(), root2);
        assert!(tree.delete(b"k"));
        assert_eq!(tree.root(), empty_root);
    }

    #[test]
    fn delete_absent_key_is_a_no_op() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let root = tree.root();
        assert!(!tree.delete(b"missing"));
        assert_eq!(tree.root(), root);
    }

    #[test]
    fn shared_prefix_paths_coexist() {
        // Two keys that collide in their first bits must still yield distinct
        // proofs and a stable root. Deterministically chosen key pair that
        // exercises the branch-node sharing.
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"key-1", b"value-1");
        tree.insert(b"key-2", b"value-2");
        let root = tree.root();

        for key in [b"key-1".as_slice(), b"key-2".as_slice()] {
            let siblings = tree.proof_siblings(key).expect("present");
            let value = if key == b"key-1" { b"value-1".to_vec() } else { b"value-2".to_vec() };
            let proof = MerkleProof { key: key.to_vec(), value, siblings };
            assert!(proof.verify(&root), "proof for {key:?} verifies");
        }
    }

    #[test]
    fn proof_encode_decode_round_trips() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"v".to_vec(), siblings };
        let decoded = MerkleProof::decode(&proof.encode()).expect("decodes");
        assert_eq!(decoded, proof);
        assert!(decoded.verify(&tree.root()));
    }

    #[test]
    fn proof_decode_rejects_wrong_sibling_count() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"v".to_vec(), siblings };
        let mut bytes = proof.encode();
        // Corrupt the sibling count (u32 BE, offset 4+1+4+1 = after key+value lengths).
        let count_off = 4 + 1 + 4 + 1;
        bytes[count_off..count_off + 4].copy_from_slice(&(DEPTH as u32 - 1).to_be_bytes());
        assert!(MerkleProof::decode(&bytes).is_none());
    }

    #[test]
    fn proof_decode_rejects_truncation() {
        let mut tree = SparseMerkleTree::new();
        tree.insert(b"k", b"v");
        let siblings = tree.proof_siblings(b"k").expect("present");
        let proof = MerkleProof { key: b"k".to_vec(), value: b"v".to_vec(), siblings };
        let bytes = proof.encode();
        assert!(MerkleProof::decode(&bytes[..bytes.len() - 1]).is_none());
    }
}
