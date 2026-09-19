//! Append-only Merkle log over actor membership (RFC-6962, PLAN-5 D-9).
//!
//! Each root actor holds a commitment to its sub-actor set as the root of a
//! binary Merkle tree built exactly as RFC-6962 §2.1 defines: the leaves are
//! domain-separated sub-actor hashes (see [`crate::sub_actor`]), and the
//! tree shape for `n` leaves is fixed by splitting at the largest power of
//! two strictly below `n`. This module is entirely separate from the state
//! SMT in [`crate::merkle`]: different domain separation, different empty
//! value (`SHA256("")` here, `SHA256(0x00)` there), and no shared code.
//!
//! ```text
//! leaf_hash(data)      = SHA256(0x00 || data)
//! node_hash(left, right) = SHA256(0x01 || left || right)
//! MTH([])              = SHA256("") = EMPTY_ROOT
//! MTH([leaf])          = leaf (already a leaf_hash)
//! MTH(leaves)          = node_hash(MTH(leaves[..k]), MTH(leaves[k..]))
//!                        with k the largest power of two strictly below n
//! ```
//!
//! Inclusion proofs (`PATH`, §2.1.1) and consistency proofs (`PROOF`,
//! §2.1.2) list sibling/subtree hashes bottom-up: the deepest hash first,
//! the top-level sibling last. Their wire encodings carry the claimed sizes
//! plus an explicit `node_count` framing field; `decode` rejects truncation,
//! trailing bytes, or a `node_count` that does not match the hashes present.
//! A `node_count` that disagrees with the algorithm-derived count for the
//! claimed sizes is rejected at apply time, not here.

use sha2::{
    Digest,
    Sha256,
};

/// A 32-byte SHA-256 hash: a leaf hash, a node hash, or a tree root.
pub type Hash = [u8; 32];

/// The root of the empty actor log: `SHA256("")` =
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
/// This is deliberately **not** the state SMT's `SHA256(0x00)` empty value.
/// Invariant: `leaf_count == 0` if and only if the stored root equals
/// [`EMPTY_ROOT`].
pub const EMPTY_ROOT: Hash = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// RFC-6962 leaf hash: `SHA256(0x00 || data)`.
///
/// The `0x00` prefix domain-separates leaves from internal nodes, so a leaf
/// preimage is never replayable as a node preimage (and vice versa).
pub fn leaf_hash(data: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x00u8]);
    hasher.update(data);
    hasher.finalize().into()
}

/// RFC-6962 internal node hash: `SHA256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update([0x01u8]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// RFC-6962 `MTH` (§2.1) over already-hashed leaves.
///
/// Empty input yields [`EMPTY_ROOT`]; a single leaf yields itself; otherwise
/// the list splits at the largest power of two strictly below `n` and the
/// halves are combined with [`node_hash`].
pub fn mth(leaf_hashes: &[Hash]) -> Hash {
    match leaf_hashes.len() {
        0 => EMPTY_ROOT,
        1 => leaf_hashes[0],
        n => {
            let k = largest_pow2_below(n as u64) as usize;
            node_hash(&mth(&leaf_hashes[..k]), &mth(&leaf_hashes[k..]))
        }
    }
}

/// An RFC-6962 consistency proof (`PROOF`, §2.1.2): the nodes proving the
/// tree of `old_leaf_count` leaves is a prefix of the tree of
/// `new_leaf_count` leaves, deepest hash first.
///
/// Wire encoding: `old_leaf_count:u64BE || new_leaf_count:u64BE ||
/// node_count:u32BE || node_count × 32B`. Hashes are raw 32-byte strings,
/// back-to-back, with no per-element length prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConsistencyProof {
    pub old_leaf_count: u64,
    pub new_leaf_count: u64,
    pub nodes: Vec<Hash>,
}

/// An RFC-6962 inclusion proof (`PATH`, §2.1.1): the sibling hashes folding
/// the leaf at `leaf_index` up to the root of `leaf_count` leaves, deepest
/// sibling first.
///
/// Wire encoding: `leaf_index:u64BE || leaf_count:u64BE || node_count:u32BE
/// || node_count × 32B`, with the same raw-hash framing as
/// [`ConsistencyProof`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub leaf_count: u64,
    pub nodes: Vec<Hash>,
}

impl ConsistencyProof {
    /// Canonical encoding — the inverse of [`ConsistencyProof::decode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.nodes.len() * 32);
        buf.extend_from_slice(&self.old_leaf_count.to_be_bytes());
        buf.extend_from_slice(&self.new_leaf_count.to_be_bytes());
        buf.extend_from_slice(
            &u32::try_from(self.nodes.len()).expect("proof exceeds u32::MAX nodes").to_be_bytes(),
        );
        for node in &self.nodes {
            buf.extend_from_slice(node);
        }
        buf
    }

    /// The inverse of [`ConsistencyProof::encode`]. `None` on truncation,
    /// trailing bytes, or a `node_count` that does not match the number of
    /// hashes actually present.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = bytes;
        let proof = Self::decode_from(&mut cursor)?;
        cursor.is_empty().then_some(proof)
    }

    /// Decodes a `ConsistencyProof`, advancing `cursor` past the fixed header
    /// plus `node_count × 32B` hashes. `None` on truncation or a `node_count`
    /// that overruns the remaining bytes; trailing bytes after the proof are
    /// left for the caller (see [`ConsistencyProof::decode`]).
    pub fn decode_from(cursor: &mut &[u8]) -> Option<Self> {
        let old_leaf_count = read_u64(cursor)?;
        let new_leaf_count = read_u64(cursor)?;
        let nodes = read_hashes_from(cursor)?;
        Some(Self { old_leaf_count, new_leaf_count, nodes })
    }
}

impl InclusionProof {
    /// Canonical encoding — the inverse of [`InclusionProof::decode`].
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(20 + self.nodes.len() * 32);
        buf.extend_from_slice(&self.leaf_index.to_be_bytes());
        buf.extend_from_slice(&self.leaf_count.to_be_bytes());
        buf.extend_from_slice(
            &u32::try_from(self.nodes.len()).expect("proof exceeds u32::MAX nodes").to_be_bytes(),
        );
        for node in &self.nodes {
            buf.extend_from_slice(node);
        }
        buf
    }

    /// The inverse of [`InclusionProof::encode`]. `None` on truncation,
    /// trailing bytes, or a `node_count` that does not match the number of
    /// hashes actually present.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let mut cursor = bytes;
        let proof = Self::decode_from(&mut cursor)?;
        cursor.is_empty().then_some(proof)
    }

    /// Decodes an `InclusionProof`, advancing `cursor` past the fixed header
    /// plus `node_count × 32B` hashes. `None` on truncation or a `node_count`
    /// that overruns the remaining bytes; trailing bytes after the proof are
    /// left for the caller (see [`InclusionProof::decode`]).
    pub fn decode_from(cursor: &mut &[u8]) -> Option<Self> {
        let leaf_index = read_u64(cursor)?;
        let leaf_count = read_u64(cursor)?;
        let nodes = read_hashes_from(cursor)?;
        Some(Self { leaf_index, leaf_count, nodes })
    }
}

/// RFC-6962 `PATH` (§2.1.1): the audit path for the leaf at `index`.
///
/// `None` when `index` is out of range (including the empty tree). The
/// returned nodes are ordered deepest-first, matching the recursion
/// `PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])` for `m < k` (and the
/// mirrored half for `m >= k`).
pub fn prove_inclusion(leaf_hashes: &[Hash], index: usize) -> Option<InclusionProof> {
    if index >= leaf_hashes.len() {
        return None;
    }
    let mut nodes = Vec::new();
    inclusion_path(index as u64, leaf_hashes, &mut nodes);
    Some(InclusionProof { leaf_index: index as u64, leaf_count: leaf_hashes.len() as u64, nodes })
}

/// Verifies an RFC-6962 audit path: replays the `PATH` recursion for
/// (`leaf_index`, `leaf_count`), folding `leaf_hash` with the proof nodes,
/// and accepts only when every node is consumed and the fold equals `root`.
pub fn verify_inclusion(leaf_hash: &Hash, proof: &InclusionProof, root: &Hash) -> bool {
    if proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count {
        return false;
    }
    match inclusion_rec(proof.leaf_index, proof.leaf_count, leaf_hash, &proof.nodes) {
        Some((calc, rest)) => rest.is_empty() && calc == *root,
        None => false,
    }
}

/// RFC-6962 `PROOF` (§2.1.2): the consistency proof from the first
/// `old_count` leaves of `leaf_hashes` to all of them.
///
/// `None` when `old_count` exceeds the tree size. `old_count == 0` (the
/// bootstrap from [`EMPTY_ROOT`]) and `old_count == len` both yield an
/// empty proof.
pub fn prove_consistency(leaf_hashes: &[Hash], old_count: usize) -> Option<ConsistencyProof> {
    if old_count > leaf_hashes.len() {
        return None;
    }
    let mut nodes = Vec::new();
    if old_count > 0 && old_count < leaf_hashes.len() {
        consistency_subproof(old_count as u64, leaf_hashes, true, &mut nodes);
    }
    Some(ConsistencyProof {
        old_leaf_count: old_count as u64,
        new_leaf_count: leaf_hashes.len() as u64,
        nodes,
    })
}

/// Verifies an RFC-6962 consistency proof (§2.1.2): replays the `SUBPROOF`
/// recursion for the proof's claimed sizes, reconstructing both the old and
/// the new root purely from the proof nodes (plus `old_root` for the single
/// externally-known subtree), and accepts only when every node is consumed
/// and both reconstructions match.
///
/// The `old_leaf_count == 0` bootstrap carries no nodes and commits to
/// nothing about the new tree: it accepts exactly when the proof is empty
/// and `old_root` is [`EMPTY_ROOT`].
pub fn verify_consistency(old_root: &Hash, proof: &ConsistencyProof, new_root: &Hash) -> bool {
    let m = proof.old_leaf_count;
    let n = proof.new_leaf_count;
    if m > n {
        return false;
    }
    if m == 0 {
        return proof.nodes.is_empty() && *old_root == EMPTY_ROOT;
    }
    if m == n {
        return proof.nodes.is_empty() && old_root == new_root;
    }
    match consistency_rec(m, n, true, &proof.nodes, old_root) {
        Some(((calc_old, calc_new), rest)) => {
            rest.is_empty() && calc_old == *old_root && calc_new == *new_root
        }
        None => false,
    }
}

/// Largest power of two strictly below `n`; requires `n > 1`.
fn largest_pow2_below(n: u64) -> u64 {
    debug_assert!(n > 1);
    let floor = 1u64 << n.ilog2();
    if floor == n { floor / 2 } else { floor }
}

fn inclusion_path(m: u64, leaves: &[Hash], out: &mut Vec<Hash>) {
    if leaves.len() <= 1 {
        return;
    }
    let k = largest_pow2_below(leaves.len() as u64) as usize;
    if m < k as u64 {
        inclusion_path(m, &leaves[..k], out);
        out.push(mth(&leaves[k..]));
    } else {
        inclusion_path(m - k as u64, &leaves[k..], out);
        out.push(mth(&leaves[..k]));
    }
}

/// Replays the `PATH` recursion, folding `leaf` with proof nodes consumed
/// front-to-back; returns the folded hash and the unconsumed tail.
fn inclusion_rec<'a>(m: u64, n: u64, leaf: &Hash, proof: &'a [Hash]) -> Option<(Hash, &'a [Hash])> {
    if n == 1 {
        if m != 0 {
            return None;
        }
        return Some((*leaf, proof));
    }
    if m >= n {
        return None;
    }
    let k = largest_pow2_below(n);
    if m < k {
        let (left, rest) = inclusion_rec(m, k, leaf, proof)?;
        let (sibling, rest) = rest.split_first()?;
        Some((node_hash(&left, sibling), rest))
    } else {
        let (right, rest) = inclusion_rec(m - k, n - k, leaf, proof)?;
        let (sibling, rest) = rest.split_first()?;
        Some((node_hash(sibling, &right), rest))
    }
}

/// The `SUBPROOF(m, D[n], b)` recursion (§2.1.2): appends the minimal node
/// list proving the first `m` of `leaves` are a prefix of all of them.
/// `b` marks whether the old root is externally known (the original call)
/// or must itself be committed by a proof node (right-spine recursion).
fn consistency_subproof(m: u64, leaves: &[Hash], b: bool, out: &mut Vec<Hash>) {
    let n = leaves.len() as u64;
    if m == n {
        if !b {
            out.push(mth(leaves));
        }
        return;
    }
    let k = largest_pow2_below(n) as usize;
    if m <= k as u64 {
        consistency_subproof(m, &leaves[..k], b, out);
        out.push(mth(&leaves[k..]));
    } else {
        consistency_subproof(m - k as u64, &leaves[k..], false, out);
        out.push(mth(&leaves[..k]));
    }
}

/// Replays the `SUBPROOF` recursion, reconstructing the `(old-side,
/// new-side)` subtree hashes from proof nodes consumed front-to-back. The
/// externally-known old subtree (`b == true` base case) resolves to
/// `known_old`; every other subtree resolves to a proof node.
fn consistency_rec<'a>(
    m: u64,
    n: u64,
    b: bool,
    proof: &'a [Hash],
    known_old: &Hash,
) -> Option<((Hash, Hash), &'a [Hash])> {
    if m == n {
        if b {
            return Some(((*known_old, *known_old), proof));
        }
        let (head, rest) = proof.split_first()?;
        return Some(((*head, *head), rest));
    }
    if m > n {
        return None;
    }
    let k = largest_pow2_below(n);
    if m <= k {
        let ((old_side, left_new), rest) = consistency_rec(m, k, b, proof, known_old)?;
        let (sibling, rest) = rest.split_first()?;
        Some(((old_side, node_hash(&left_new, sibling)), rest))
    } else {
        let ((old_side, right_new), rest) = consistency_rec(m - k, n - k, false, proof, known_old)?;
        let (sibling, rest) = rest.split_first()?;
        Some(((node_hash(sibling, &old_side), node_hash(sibling, &right_new)), rest))
    }
}

fn read_u64(bytes: &mut &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(read_exact(bytes, 8)?.try_into().ok()?))
}

fn read_u32(bytes: &mut &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes(read_exact(bytes, 4)?.try_into().ok()?))
}

/// Reads the `node_count:u32BE || node_count × 32B` framing, advancing
/// `bytes` past exactly the claimed hashes. `None` when the claimed count
/// overruns the remaining bytes; bytes after the proof are left unread.
fn read_hashes_from(bytes: &mut &[u8]) -> Option<Vec<Hash>> {
    let count = read_u32(bytes)? as usize;
    let want = count.checked_mul(32)?;
    let head = read_exact(bytes, want)?;
    let (chunks, remainder) = head.as_chunks::<32>();
    if !remainder.is_empty() {
        return None;
    }
    Some(chunks.to_vec())
}

fn read_exact<'a>(bytes: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let head = bytes.get(..len)?;
    *bytes = &bytes[len..];
    Some(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf_hashes(n: u8) -> Vec<Hash> {
        (0..n).map(|i| leaf_hash(&[i])).collect()
    }

    #[test]
    fn empty_root_is_sha256_of_empty_string() {
        let expected: Hash = Sha256::digest([]).into();
        assert_eq!(EMPTY_ROOT, expected);
        assert_eq!(
            EMPTY_ROOT,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
    }

    #[test]
    fn mth_matches_rfc6962_shape() {
        assert_eq!(mth(&[]), EMPTY_ROOT);
        let leaves = leaf_hashes(3);
        assert_eq!(mth(&leaves[..1]), leaves[0]);
        assert_eq!(mth(&leaves[..2]), node_hash(&leaves[0], &leaves[1]));
        // n = 3 splits at k = 2: node(MTH(first two), third).
        assert_eq!(mth(&leaves), node_hash(&node_hash(&leaves[0], &leaves[1]), &leaves[2]));
        // n = 5 splits at k = 4.
        let five = leaf_hashes(5);
        assert_eq!(
            mth(&five),
            node_hash(&mth(&five[..4]), &five[4]),
            "n = 5 splits at the largest power of two below 5"
        );
        // A balanced power-of-two tree folds pairwise.
        let four = leaf_hashes(4);
        assert_eq!(
            mth(&four),
            node_hash(&node_hash(&four[0], &four[1]), &node_hash(&four[2], &four[3]))
        );
    }

    #[test]
    fn inclusion_prove_verify_round_trips_for_several_sizes() {
        for n in [0u8, 1, 2, 3, 5] {
            let leaves = leaf_hashes(n);
            let root = mth(&leaves);
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = prove_inclusion(&leaves, i).expect("in range");
                assert_eq!(proof.leaf_index, i as u64);
                assert_eq!(proof.leaf_count, n as u64);
                assert!(verify_inclusion(leaf, &proof, &root), "n = {n}, index = {i}");
            }
        }
    }

    #[test]
    fn inclusion_proof_is_empty_for_single_leaf() {
        let leaves = leaf_hashes(1);
        let proof = prove_inclusion(&leaves, 0).expect("present");
        assert!(proof.nodes.is_empty());
        assert!(verify_inclusion(&leaves[0], &proof, &leaves[0]));
    }

    #[test]
    fn inclusion_prove_rejects_out_of_range_index() {
        assert!(prove_inclusion(&[], 0).is_none());
        assert!(prove_inclusion(&leaf_hashes(2), 2).is_none());
    }

    #[test]
    fn inclusion_verify_rejects_tampered_inputs() {
        let leaves = leaf_hashes(5);
        let root = mth(&leaves);
        let proof = prove_inclusion(&leaves, 2).expect("present");
        assert!(!verify_inclusion(&leaf_hash(&[0xff]), &proof, &root), "wrong leaf");
        assert!(!verify_inclusion(&leaves[2], &proof, &EMPTY_ROOT), "wrong root");
        let mut tampered = proof.clone();
        tampered.nodes[0][0] ^= 1;
        assert!(!verify_inclusion(&leaves[2], &tampered, &root), "tampered node");
        let mut truncated = proof.clone();
        truncated.nodes.pop();
        assert!(!verify_inclusion(&leaves[2], &truncated, &root), "truncated proof");
        let mut extended = proof.clone();
        extended.nodes.push([9u8; 32]);
        assert!(!verify_inclusion(&leaves[2], &extended, &root), "extended proof");
        let mut wrong_index = proof.clone();
        wrong_index.leaf_index = 3;
        assert!(!verify_inclusion(&leaves[2], &wrong_index, &root), "wrong index");
    }

    #[test]
    fn consistency_prove_verify_round_trips_over_prefixes() {
        // Every old prefix of a 5-leaf tree proves consistent with the full tree.
        let leaves = leaf_hashes(5);
        let new_root = mth(&leaves);
        for old in 0..=leaves.len() {
            let old_root = mth(&leaves[..old]);
            let proof = prove_consistency(&leaves, old).expect("valid prefix");
            assert_eq!(proof.old_leaf_count, old as u64);
            assert_eq!(proof.new_leaf_count, leaves.len() as u64);
            assert!(verify_consistency(&old_root, &proof, &new_root), "old = {old}");
        }
    }

    #[test]
    fn consistency_empty_tree_proves_empty_against_itself() {
        let proof = prove_consistency(&[], 0).expect("empty proves");
        assert!(proof.nodes.is_empty());
        assert!(verify_consistency(&EMPTY_ROOT, &proof, &EMPTY_ROOT));
    }

    #[test]
    fn consistency_bootstrap_requires_empty_root() {
        let leaves = leaf_hashes(3);
        let new_root = mth(&leaves);
        let proof = prove_consistency(&leaves, 0).expect("bootstrap proof");
        assert!(proof.nodes.is_empty());
        assert!(verify_consistency(&EMPTY_ROOT, &proof, &new_root));
        assert!(!verify_consistency(&leaves[0], &proof, &new_root), "non-empty old root");
    }

    #[test]
    fn consistency_prove_rejects_old_beyond_new() {
        assert!(prove_consistency(&leaf_hashes(2), 3).is_none());
    }

    #[test]
    fn consistency_verify_rejects_tampered_inputs() {
        let leaves = leaf_hashes(5);
        let old_root = mth(&leaves[..3]);
        let new_root = mth(&leaves);
        let proof = prove_consistency(&leaves, 3).expect("present");
        assert!(!verify_consistency(&mth(&leaves[..2]), &proof, &new_root), "wrong old root");
        assert!(!verify_consistency(&old_root, &proof, &EMPTY_ROOT), "wrong new root");
        let mut tampered = proof.clone();
        let last = tampered.nodes.len() - 1;
        tampered.nodes[last][31] ^= 1;
        assert!(!verify_consistency(&old_root, &tampered, &new_root), "tampered node");
        let mut truncated = proof.clone();
        truncated.nodes.pop();
        assert!(!verify_consistency(&old_root, &truncated, &new_root), "truncated proof");
        let mut swapped = proof.clone();
        core::mem::swap(&mut swapped.old_leaf_count, &mut swapped.new_leaf_count);
        assert!(!verify_consistency(&old_root, &swapped, &new_root), "old count above new");
    }

    #[test]
    fn consistency_proof_encode_decode_round_trips() {
        let leaves = leaf_hashes(5);
        for old in 0..=leaves.len() {
            let proof = prove_consistency(&leaves, old).expect("valid");
            let decoded = ConsistencyProof::decode(&proof.encode()).expect("decodes");
            assert_eq!(decoded, proof);
            assert!(verify_consistency(&mth(&leaves[..old]), &decoded, &mth(&leaves)));
        }
    }

    #[test]
    fn inclusion_proof_encode_decode_round_trips() {
        let leaves = leaf_hashes(3);
        let proof = prove_inclusion(&leaves, 1).expect("present");
        let decoded = InclusionProof::decode(&proof.encode()).expect("decodes");
        assert_eq!(decoded, proof);
    }

    #[test]
    fn proof_decode_rejects_malformed_framing() {
        let leaves = leaf_hashes(3);
        let consistency = prove_consistency(&leaves, 1).expect("present");
        let inclusion = prove_inclusion(&leaves, 1).expect("present");
        for bytes in [consistency.encode(), inclusion.encode()] {
            assert!(ConsistencyProof::decode(&bytes[..bytes.len() - 1]).is_none(), "truncated");
            let mut extended = bytes.clone();
            extended.push(0);
            assert!(ConsistencyProof::decode(&extended).is_none(), "trailing byte");
            assert!(InclusionProof::decode(&bytes[..bytes.len() - 1]).is_none(), "truncated");
            assert!(InclusionProof::decode(&extended).is_none(), "trailing byte");
        }
        // node_count claims two hashes but only one is present.
        let mut short = Vec::new();
        short.extend_from_slice(&1u64.to_be_bytes());
        short.extend_from_slice(&3u64.to_be_bytes());
        short.extend_from_slice(&2u32.to_be_bytes());
        short.extend_from_slice(&[7u8; 32]);
        assert!(ConsistencyProof::decode(&short).is_none(), "count exceeds hashes present");
        assert!(InclusionProof::decode(&short).is_none(), "count exceeds hashes present");
        // node_count claims zero hashes but one follows.
        let mut long = Vec::new();
        long.extend_from_slice(&1u64.to_be_bytes());
        long.extend_from_slice(&3u64.to_be_bytes());
        long.extend_from_slice(&0u32.to_be_bytes());
        long.extend_from_slice(&[7u8; 32]);
        assert!(ConsistencyProof::decode(&long).is_none(), "hashes exceed claimed count");
        assert!(InclusionProof::decode(&long).is_none(), "hashes exceed claimed count");
        assert!(ConsistencyProof::decode(&[]).is_none(), "empty input");
        assert!(ConsistencyProof::decode(&[0u8; 10]).is_none(), "short header");
    }
}
