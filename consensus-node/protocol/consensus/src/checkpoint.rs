//! Phase 3 — signed state checkpoints.
//!
//! A [`CheckpointPayload`] is the unsigned commitment every node makes once a
//! round is decided: the round, the Merkle root of the deterministic `State`,
//! and the SHA-256 of the canonical roster active at that round. Each node
//! signs [`CheckpointPayload::signing_bytes`] — a fixed 200 bytes — and the
//! resulting [`CheckpointSig`]s are gossiped. A [`CheckpointAccumulator`]
//! collects them per round and yields a [`SignedCheckpoint`] the first time
//! the signers exceed 2/3 of the roster active at that round. That accepted
//! form authorises pruning old history from the live `Hashgraph`.

use std::collections::HashMap;

use blst::min_pk::Signature as BlsSignature;
use crypto::{
    CanonicalEncode,
    Hashable,
    MembershipRegistry,
    RosterHistory,
};
use primitives::{
    EventHash,
    NodeId,
};
use sha2::{
    Digest,
    Sha256,
};

use crate::hashgraph::{
    EventRecord,
    Hashgraph,
};

/// Signed-window length in rounds (PLAN-4 Phase A wire break).
///
/// Value recommended by `docs/issues/phase0-walk-depth-spike.md`: measured
/// transition depth 2 rounds, 8x margin, aligned with
/// `CHECKPOINT_LAG_ROUNDS`. Pending owner ratification.
pub const SIGNED_WINDOW_ROUNDS: u64 = 16;

/// Rounds of raw events to keep after a checkpoint round is confirmed, so a
/// peer that fell behind by up to this many rounds can still delta-sync
/// normally. This is the signed-window length / prune floor (PLAN-4 Hard
/// Condition 1): `checkpoint_payload` commits to the window
/// `[R - SIGNED_WINDOW_ROUNDS, R]`, so retention must hold exactly that
/// window. The gossip layer subtracts it from the confirmed round before
/// calling `Hashgraph::prune_before_round`.
pub const RETENTION_ROUNDS: u64 = SIGNED_WINDOW_ROUNDS;

/// One record item's content for [`compute_records_root`].
///
/// Corresponds field-for-field to `proto::RecordItem` defined in
/// `proto/jkain_stream.proto` lines ~88-92:
/// ```proto
/// message RecordItem {
///   bytes  event_hash = 1; // source event, 32 bytes
///   uint32 tx_index   = 2; // index in that event's payload
///   bytes  tx_payload = 3; // Op::Put/Delete or MembershipOp bytes
/// }
/// ```
/// The triple is `(event_hash, tx_index, tx_payload)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsRootItem {
    pub event_hash: [u8; 32],
    pub tx_index: u32,
    pub tx_payload: Vec<u8>,
}

/// Computes the records root for a round's record items in **consensus order**
/// (`Hashgraph::consensus_order(round)` derived, which is final and deterministic
/// once the round is decided). Padded binary Merkle tree, Hiero-style
/// domain separation (mirror of `executor/state/src/merkle.rs`):
///
/// ```text
/// empty                = SHA256(0x00)
/// leaf(item)           = SHA256(0x00 || event_hash[32] || u32_BE(tx_index) || u32_BE(len(tx_payload)) || tx_payload)
/// internal(l, r)       = SHA256(0x02 || l || r)
/// singleton(c)         = SHA256(0x01 || c)
/// combine(l,r):
///   (empty,empty) -> empty
///   (empty,r)     -> singleton(r)
///   (l,empty)     -> singleton(l)
///   (l,r)         -> internal(l,r)
/// ```
///
/// Leaves are `leaf(item)` in consensus order, padded to the next power of two
/// with `empty`. The tree is then folded bottom-up with `combine`. Empty round
/// ⇒ `empty` alone (stable). This construction is normative and mirrored
/// byte-for-byte in the Go mirror crate.
///
/// Determinism: consensus-order items for root; signer sorting before aggregation
/// (documented at the call site in `gossip::node`).
pub fn compute_records_root(items: &[RecordsRootItem]) -> [u8; 32] {
    try_compute_records_root(items)
        .expect("records root overflow: tx_payload length exceeds u32::MAX")
}

pub fn try_compute_records_root(items: &[RecordsRootItem]) -> Result<[u8; 32], primitives::Error> {
    if items.is_empty() {
        return Ok(empty_hash());
    }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(items.len());
    for item in items {
        leaves.push(try_leaf_hash(item)?);
    }
    let padded_len = leaves.len().next_power_of_two();
    leaves.resize(padded_len, empty_hash());
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = chunk[1];
            next.push(combine_hash(left, right));
        }
        level = next;
    }
    Ok(level[0])
}

/// Domain separation tag prefixing every [`compute_window_root`] leaf. It
/// replaces the bare `0x00` prefix of [`compute_records_root`] so the window
/// tree can never collide with the records tree (or `CheckpointDST`), even
/// for byte-identical event hashes.
const WINDOW_ROOT_DST: &[u8] = b"JKAIN-WINDOW-ROOT-V1";

/// Computes the canonical signed-window Merkle root over decided history.
///
/// The canonical set is `window(round, W) = { events with `round_received`
/// in `[round.saturating_sub(W), round]` }`, ordered by `round_received`
/// ascending with ties broken by `Hashgraph::consensus_order(r)` within each
/// round. A pure function of decided history: every honest node holding the
/// same decided rounds derives the identical root, regardless of local
/// retention or acceptance progress.
///
/// Each event in that order contributes one leaf (see `window_leaf_hash`):
///
/// ```text
/// leaf = SHA256("JKAIN-WINDOW-ROOT-V1" || event_hash[32] || seq[u64 BE]
///   || birth_round[u64 BE] || rr_tag[u8] (|| rr[u64 BE] when Some)
///   || ts_tag[u8] (|| ts[u64 BE] when Some)
///   || width[u32 BE] || ancestor_seqs[u64 BE x width])
/// ```
///
/// Width normalization: `width` is `hg.member_count_at_round(round)` — the
/// decided-history roster width at the checkpoint round — and each record's
/// stored `ancestor_seqs` row is truncated or zero-padded to exactly that
/// many slots. The raw stored row must not be used directly:
/// `Hashgraph::add_member` appends a zero slot to every stored row, so the
/// raw width is node/moment-dependent and the leaf would not be canonical.
///
/// Leaves fold through the same padded power-of-two `combine_hash` /
/// `empty_hash` construction as [`compute_records_root`]. An empty window
/// yields `empty_hash()`, identical to an empty [`compute_records_root`].
pub fn compute_window_root(hg: &Hashgraph, round: u64, window_rounds: u64) -> [u8; 32] {
    try_compute_window_root(hg, round, window_rounds)
        .expect("window root overflow: canonical member count exceeds u32::MAX")
}

pub fn try_compute_window_root(
    hg: &Hashgraph,
    round: u64,
    window_rounds: u64,
) -> Result<[u8; 32], primitives::Error> {
    let start = round.saturating_sub(window_rounds);
    let mut hashes: Vec<EventHash> = Vec::new();
    for r in start..=round {
        hashes.extend(hg.consensus_order(r));
    }
    if hashes.is_empty() {
        return Ok(empty_hash());
    }
    let canonical_width = hg.member_count_at_round(round);
    let width_u32 = u32::try_from(canonical_width).map_err(|_| primitives::Error::OutOfRange {
        field: "window_root member count",
        got: canonical_width.to_string(),
    })?;
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(hashes.len());
    for hash in &hashes {
        let record = hg.get(hash).ok_or_else(|| primitives::Error::OutOfRange {
            field: "window_root event",
            got: hash_hex(hash),
        })?;
        leaves.push(window_leaf_hash(hash, record, canonical_width, width_u32));
    }
    let padded_len = leaves.len().next_power_of_two();
    leaves.resize(padded_len, empty_hash());
    let mut level = leaves;
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            let left = chunk[0];
            let right = chunk[1];
            next.push(combine_hash(left, right));
        }
        level = next;
    }
    Ok(level[0])
}

/// One window leaf: the `WINDOW_ROOT_DST`-tagged binding of an event's
/// identity (`event_hash`, creator `seq`, birth `round`) to its ordering
/// metadata (`round_received`, `consensus_timestamp`) and its ancestry
/// summary (`ancestor_seqs`, normalized to `canonical_width` slots).
fn window_leaf_hash(
    hash: &EventHash,
    record: &EventRecord,
    canonical_width: usize,
    width_u32: u32,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(WINDOW_ROOT_DST);
    h.update(hash.as_bytes());
    h.update(record.seq().to_be_bytes());
    h.update(record.round().to_be_bytes());
    match record.round_received() {
        Some(round_received) => {
            h.update([1u8]);
            h.update(round_received.to_be_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
    match record.consensus_timestamp() {
        Some(timestamp) => {
            h.update([1u8]);
            h.update(timestamp.get().to_be_bytes());
        }
        None => {
            h.update([0u8]);
        }
    }
    h.update(width_u32.to_be_bytes());
    let row = record.ancestor_seqs();
    for i in 0..canonical_width {
        h.update(row.get(i).copied().unwrap_or(0).to_be_bytes());
    }
    h.finalize().into()
}

/// Lowercase hex of an event hash, for the missing-event error payload.
fn hash_hex(hash: &EventHash) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for byte in hash.as_bytes() {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// Domain separation tag for [`compute_roster_history_root`]. Distinct from
/// `WINDOW_ROOT_DST` (`JKAIN-WINDOW-ROOT-V1`), the records-tree tag
/// (`JKAIN-RECORDS-ROOT-V1`), and `CheckpointDST`
/// (`JKAIN-CHECKPOINT-BLS-V1`), so the roster-history commitment can never
/// collide with any other checkpoint hash, even for byte-identical input.
const ROSTER_HISTORY_ROOT_DST: &[u8] = b"JKAIN-ROSTER-HISTORY-ROOT-V1";

/// Computes the canonical roster-history commitment over decided history.
///
/// The canonical selection for checkpoint `round` with window `W` is, with
/// `window_start = round.saturating_sub(W)`:
/// the predecessor — the snapshot with the greatest activation round below
/// `window_start`, when one exists — plus every snapshot with activation
/// round in `[window_start, round]` inclusive. Snapshots activating after
/// `round` are excluded. The predecessor is included so the roster active
/// at `window_start` is reconstructible from the committed set alone.
///
/// A pure function of decided history: membership activation rounds are
/// decided by consensus, so every signer holding the same decided rounds
/// selects the identical set. The raw retained set is deliberately NOT
/// used: `RosterHistory::prune_before` drops snapshots in lockstep with the
/// event-graph prune (`hashgraph.rs`), so "what this node retained" is
/// node-local and would diverge across signers.
///
/// The selected snapshots are re-encoded with
/// `crate::reconnect::encode_roster_history` (deterministic, ascending
/// activation order) and committed as
/// `SHA256("JKAIN-ROSTER-HISTORY-ROOT-V1" || encoded_bytes)`. An empty
/// selection (no snapshot at or below `round`, e.g. round 0) yields
/// `SHA256(ROSTER_HISTORY_ROOT_DST)` alone (DST-only, stable).
pub fn roster_history_root(rh: &RosterHistory, round: u64, window_rounds: u64) -> [u8; 32] {
    compute_roster_history_root(rh, round, window_rounds)
        .expect("roster history root encoding overflow: entry count exceeds u32::MAX")
}

/// The canonical roster-history selection for checkpoint `round` with
/// window `W`: with `window_start = round.saturating_sub(W)`, the
/// predecessor — the snapshot with the greatest activation round below
/// `window_start`, when one exists — plus every snapshot with activation
/// round in `[window_start, round]` inclusive. Snapshots activating after
/// `round` are excluded. The predecessor is included so the roster active
/// at `window_start` is reconstructible from the committed set alone.
///
/// Returns `None` when the selection is empty (no snapshot at or below
/// `round`, e.g. round 0). This is the exact subset
/// [`compute_roster_history_root`] commits to: the reconnect teacher serves
/// this selection (not its raw retained history), and the learner seeds its
/// scratch graph from it.
pub fn canonical_roster_history(
    rh: &RosterHistory,
    round: u64,
    window_rounds: u64,
) -> Option<RosterHistory> {
    let window_start = round.saturating_sub(window_rounds);
    // `snapshots()` iterates ascending, so the trailing assignment below
    // leaves the greatest activation round below `window_start`.
    let mut predecessor: Option<(u64, MembershipRegistry)> = None;
    let mut selected: Vec<(u64, MembershipRegistry)> = Vec::new();
    for (activation, registry) in rh.snapshots() {
        if *activation < window_start {
            predecessor = Some((*activation, registry.clone()));
        } else if *activation <= round {
            selected.push((*activation, registry.clone()));
        }
    }
    if let Some(pred) = predecessor {
        selected.insert(0, pred);
    }
    if selected.is_empty() {
        return None;
    }
    RosterHistory::from_snapshots(selected)
}

pub fn compute_roster_history_root(
    rh: &RosterHistory,
    round: u64,
    window_rounds: u64,
) -> Result<[u8; 32], primitives::Error> {
    let Some(subset) = canonical_roster_history(rh, round, window_rounds) else {
        return Ok(Sha256::digest(ROSTER_HISTORY_ROOT_DST).into());
    };
    let encoded = crate::reconnect::encode_roster_history(&subset)?;
    let mut h = Sha256::new();
    h.update(ROSTER_HISTORY_ROOT_DST);
    h.update(&encoded);
    Ok(h.finalize().into())
}

/// One step in a Merkle inclusion proof for a [`RecordsRootItem`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsProofStep {
    /// The sibling hash at this level (32 bytes).
    pub sibling_hash: [u8; 32],
    /// True if the sibling is to the right of the current node, false if to
    /// the left. Determines the combine order: `(cur, sib)` when right, else
    /// `(sib, cur)`.
    pub sibling_is_right: bool,
}

/// A Merkle inclusion proof for a single [`RecordsRootItem`] in the padded
/// binary tree defined by [`compute_records_root`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordsProof {
    /// The item index (consensus order) this proof corresponds to.
    pub item_index: u32,
    /// Sibling steps from leaf up to but not including the root.
    pub steps: Vec<RecordsProofStep>,
}

/// Builds Merkle inclusion proofs for every item in `items` (consensus order).
///
/// Uses the identical padding and combine logic as [`compute_records_root`]:
/// padded to the next power of two with `empty_hash()`, bottom-up `combine`.
/// Empty rounds produce an empty vector (no proofs). A singleton round yields
/// one entry with zero steps.
pub fn build_records_proofs(items: &[RecordsRootItem]) -> Vec<RecordsProof> {
    try_build_records_proofs(items).expect("records proof overflow: index exceeds u32::MAX")
}

pub fn try_build_records_proofs(
    items: &[RecordsRootItem],
) -> Result<Vec<RecordsProof>, primitives::Error> {
    if items.is_empty() {
        return Ok(Vec::new());
    }
    let mut leaves: Vec<[u8; 32]> = Vec::with_capacity(items.len());
    for item in items {
        leaves.push(try_leaf_hash(item)?);
    }
    let padded_len = leaves.len().next_power_of_two();
    let mut padded = leaves;
    padded.resize(padded_len, empty_hash());
    // Build all levels bottom-up, storing each level's node hashes.
    let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
    levels.push(padded);
    while levels.last().is_some_and(|l| l.len() > 1) {
        let Some(prev) = levels.last() else {
            break;
        };
        let mut next = Vec::with_capacity(prev.len() / 2);
        for chunk in prev.chunks(2) {
            next.push(combine_hash(chunk[0], chunk[1]));
        }
        levels.push(next);
    }
    let mut proofs = Vec::with_capacity(items.len());
    for (idx, _) in items.iter().enumerate() {
        let mut steps = Vec::with_capacity(levels.len().saturating_sub(1));
        let mut cur_idx = idx;
        for level in &levels[..levels.len().saturating_sub(1)] {
            let sibling_idx = cur_idx ^ 1;
            if sibling_idx < level.len() {
                let sibling_hash = level[sibling_idx];
                let sibling_is_right = cur_idx % 2 == 0;
                steps.push(RecordsProofStep { sibling_hash, sibling_is_right });
            }
            cur_idx /= 2;
        }
        let item_index = u32::try_from(idx).map_err(|_| primitives::Error::OutOfRange {
            field: "RecordsRootItem index",
            got: idx.to_string(),
        })?;
        proofs.push(RecordsProof { item_index, steps });
    }
    Ok(proofs)
}

/// Computes the records root and the inclusion proofs in one pass.
///
/// Returns `(root, proofs)` where `proofs` is `build_records_proofs(items)`.
pub fn compute_records_root_with_proofs(
    items: &[RecordsRootItem],
) -> ([u8; 32], Vec<RecordsProof>) {
    let root = compute_records_root(items);
    let proofs = build_records_proofs(items);
    (root, proofs)
}

pub fn try_compute_records_root_with_proofs(
    items: &[RecordsRootItem],
) -> Result<([u8; 32], Vec<RecordsProof>), primitives::Error> {
    let root = try_compute_records_root(items)?;
    let proofs = try_build_records_proofs(items)?;
    Ok((root, proofs))
}

/// Verifies a single [`RecordsProof`] against `root` for `item`.
///
/// Recomputes the leaf hash and walks the proof steps using the same
/// `combine_hash` as [`compute_records_root`].
pub fn verify_records_proof(root: &[u8; 32], item: &RecordsRootItem, proof: &RecordsProof) -> bool {
    let Ok(mut cur) = try_leaf_hash(item) else {
        return false;
    };
    for step in &proof.steps {
        cur = if step.sibling_is_right {
            combine_hash(cur, step.sibling_hash)
        } else {
            combine_hash(step.sibling_hash, cur)
        };
    }
    &cur == root
}

fn empty_hash() -> [u8; 32] {
    Sha256::digest([0x00u8]).into()
}

#[allow(dead_code)]
fn leaf_hash(item: &RecordsRootItem) -> [u8; 32] {
    try_leaf_hash(item).expect("leaf hash overflow: tx_payload length exceeds u32::MAX")
}

fn try_leaf_hash(item: &RecordsRootItem) -> Result<[u8; 32], primitives::Error> {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(item.event_hash);
    h.update(item.tx_index.to_be_bytes());
    let len = u32::try_from(item.tx_payload.len()).map_err(|_| primitives::Error::OutOfRange {
        field: "RecordsRootItem tx_payload length",
        got: item.tx_payload.len().to_string(),
    })?;
    h.update(len.to_be_bytes());
    h.update(&item.tx_payload);
    Ok(h.finalize().into())
}

fn internal_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x02u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn singleton_hash(child: [u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(child);
    h.finalize().into()
}

fn combine_hash(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let empty = empty_hash();
    match (left == empty, right == empty) {
        (true, true) => empty,
        (true, false) => singleton_hash(right),
        (false, true) => singleton_hash(left),
        (false, false) => internal_hash(left, right),
    }
}

/// The unsigned payload every node commits to for a given round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointPayload {
    pub round: u64,
    /// The `records_root` binding record-stream contents to the checkpoint
    /// (Hedera safeguard adaptation). Computed via [`compute_records_root`].
    pub records_root: [u8; 32],
    /// The Merkle root of the state as it stood when the round's events were
    /// finalized.
    pub state_hash: [u8; 32],
    /// SHA-256 of the canonical roster bytes active at `round`.
    pub roster_hash: [u8; 32],
    /// SHA-256 of the previous round's [`CheckpointPayload::signing_bytes`].
    /// A pure function of decided history (PLAN-2 B): every honest node
    /// derives the identical value for round `R` regardless of local
    /// acceptance progress. All-zero at genesis.
    pub prev_checkpoint_hash: [u8; 32],
    /// Merkle root of the canonical signed window
    /// `[round - SIGNED_WINDOW_ROUNDS, round]` (PLAN-4 Phase A), computed via
    /// [`compute_window_root`].
    pub window_root: [u8; 32],
    /// Commitment to the canonical roster-history selection for `round`
    /// (PLAN-4 Phase A), computed via [`compute_roster_history_root`], so the
    /// reconnect's `roster_history_bytes` stop being peer-asserted.
    pub roster_history_root: [u8; 32],
    /// The roster active at `round`, for self-description.
    pub roster_snapshot: MembershipRegistry,
}

impl CheckpointPayload {
    /// Builds the payload, deriving `roster_hash` from the canonical
    /// serialization of `roster_snapshot`. Both `window_root` and
    /// `roster_history_root` are explicit parameters: callers that do not
    /// compute them (tests) pass `[0u8; 32]`; production callers
    /// (`Hashgraph::checkpoint_payload`) compute them over
    /// `SIGNED_WINDOW_ROUNDS` of decided history.
    pub fn new(
        round: u64,
        records_root: [u8; 32],
        state_hash: [u8; 32],
        window_root: [u8; 32],
        roster_history_root: [u8; 32],
        roster_snapshot: MembershipRegistry,
    ) -> Self {
        let roster_hash = roster_snapshot
            .hash()
            .expect("roster hash cannot fail: MembershipRegistry::hash is infallible");
        Self {
            round,
            records_root,
            state_hash,
            roster_hash,
            // Genesis sentinel: a payload built without explicit chaining is
            // its own history root.
            prev_checkpoint_hash: [0u8; 32],
            window_root,
            roster_history_root,
            roster_snapshot,
        }
    }

    /// Chains this payload to its predecessor: `hash` must be
    /// `SHA256(prev_round_payload.signing_bytes())`, derived from decided
    /// history — never from local acceptance state (PLAN-2 Rule 1).
    pub fn with_prev_checkpoint_hash(mut self, hash: [u8; 32]) -> Self {
        self.prev_checkpoint_hash = hash;
        self
    }

    /// Canonical bytes signed by each node: `round (8 BE) || records_root (32)
    /// || state_hash (32) || roster_hash (32) || prev_checkpoint_hash (32)
    /// || window_root (32) || roster_history_root (32)`.
    /// Compact and unambiguous — every node derives the identical 200 bytes
    /// for the same decided round.
    pub fn signing_bytes(&self) -> [u8; 200] {
        let mut buf = [0u8; 200];
        buf[..8].copy_from_slice(&self.round.to_be_bytes());
        buf[8..40].copy_from_slice(&self.records_root);
        buf[40..72].copy_from_slice(&self.state_hash);
        buf[72..104].copy_from_slice(&self.roster_hash);
        buf[104..136].copy_from_slice(&self.prev_checkpoint_hash);
        buf[136..168].copy_from_slice(&self.window_root);
        buf[168..200].copy_from_slice(&self.roster_history_root);
        buf
    }
    /// `SHA256(signing_bytes())` — exactly what round `R + 1` embeds as its
    /// `prev_checkpoint_hash`.
    pub fn signing_bytes_hash(&self) -> [u8; 32] {
        Sha256::digest(self.signing_bytes()).into()
    }
}

/// One node's BLS signature over [`CheckpointPayload::signing_bytes`] for
/// `round`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckpointSig {
    pub round: u64,
    pub signer: NodeId,
    pub sig: BlsSignature,
}

impl CanonicalEncode for CheckpointSig {
    fn encode_canonical(&self, buf: &mut Vec<u8>) -> Result<(), primitives::Error> {
        buf.extend_from_slice(&self.round.to_be_bytes());
        buf.extend_from_slice(&self.signer.get().to_be_bytes());
        buf.extend_from_slice(&self.sig.to_bytes());
        Ok(())
    }
}

impl CheckpointSig {
    /// The inverse of [`CanonicalEncode`]: parses the fixed 112-byte wire form
    /// `round || signer || sig`. `None` for any other length or invalid BLS
    /// compressed point.
    pub fn decode(bytes: &[u8]) -> Option<CheckpointSig> {
        if bytes.len() != 112 {
            return None;
        }
        let round = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
        let signer = NodeId::new(u64::from_be_bytes(bytes[8..16].try_into().ok()?));
        let mut sig_bytes = [0u8; 96];
        sig_bytes.copy_from_slice(&bytes[16..112]);
        let sig = BlsSignature::from_bytes(&sig_bytes).ok()?;
        Some(CheckpointSig { round, signer, sig })
    }
}

/// A [`CheckpointPayload`] together with a BLS aggregate signature over its
/// signing bytes. The aggregate is valid only if `signers` are distinct members
/// of `payload.roster_snapshot` and exceed 2/3 of the roster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedCheckpoint {
    pub payload: CheckpointPayload,
    pub aggregate_sig: BlsSignature,
    pub signers: Vec<NodeId>,
}

impl SignedCheckpoint {
    /// Verifies the aggregate against the payload's roster snapshot.
    /// Checks: distinct signers present in `payload.roster_snapshot`,
    /// `count*3 > total*2`, and `crypto::bls::verify_aggregate` over
    /// `payload.signing_bytes()` with `CHECKPOINT_DST`.
    pub fn verify(&self) -> bool {
        self.verify_with_registry(&self.payload.roster_snapshot)
    }

    /// Like [`Self::verify`] but checks against an external registry (e.g. a
    /// trusted roster hash anchor). Useful for callers that already have a
    /// registry; the internal snapshot is still used for hash anchoring.
    pub fn verify_with_registry(&self, registry: &MembershipRegistry) -> bool {
        // Dedicated distinctness check: payload.roster_snapshot may differ from
        // external registry, but signers must be members of both for acceptance.
        let total = self.payload.roster_snapshot.len();
        if total == 0 {
            return false;
        }
        // Collect distinct signers present in both the payload snapshot and
        // the supplied registry (if they differ). For the common case where
        // `registry` is the snapshot itself, this is just the snapshot check.
        let mut distinct: Vec<NodeId> = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for signer in &self.signers {
            if !seen.insert(*signer) {
                continue;
            }
            if !self.payload.roster_snapshot.contains(signer) {
                return false;
            }
            if !registry.contains(signer) {
                return false;
            }
            distinct.push(*signer);
        }
        if distinct.len() * 3 <= total * 2 {
            return false;
        }
        if distinct.len() != self.signers.len() {
            // Duplicate signer in the list.
            return false;
        }
        // Gather BLS public keys for each signer, sorted by NodeId to match
        // aggregation order. Aggregation order is deterministic: signers sorted
        // ascending.
        let mut sorted_signers = distinct;
        sorted_signers.sort();
        let mut pks: Vec<blst::min_pk::PublicKey> = Vec::with_capacity(sorted_signers.len());
        let mut pk_refs: Vec<&blst::min_pk::PublicKey> = Vec::with_capacity(sorted_signers.len());
        for signer in &sorted_signers {
            let Some(bls_bytes) = self.payload.roster_snapshot.bls_key_for(signer) else {
                return false;
            };
            let Ok(pk) = blst::min_pk::PublicKey::from_bytes(bls_bytes) else {
                return false;
            };
            pks.push(pk);
        }
        for pk in &pks {
            pk_refs.push(pk);
        }
        crypto::bls::verify_aggregate(&self.aggregate_sig, &self.payload.signing_bytes(), &pk_refs)
    }
}

/// Accumulates partial BLS signatures for a single round until quorum is met.
pub struct CheckpointAccumulator {
    payload: CheckpointPayload,
    /// The canonical serialized state whose Merkle root equals
    /// `payload.state_hash`, captured in the same producing pass as the
    /// payload and carried through accumulation so acceptance persists
    /// exactly the committed bytes instead of re-selecting them from a
    /// mutable snapshot map.
    snapshot: Vec<u8>,
    sigs: HashMap<NodeId, CheckpointSig>,
}

impl CheckpointAccumulator {
    pub fn new(payload: CheckpointPayload, snapshot: Vec<u8>) -> Self {
        Self { payload, snapshot, sigs: HashMap::new() }
    }

    /// The payload this accumulator is collecting signatures for.
    pub fn payload(&self) -> &CheckpointPayload {
        &self.payload
    }

    /// The carried snapshot bytes — the state whose root is
    /// `self.payload.state_hash`.
    pub fn snapshot(&self) -> &[u8] {
        &self.snapshot
    }

    /// The signing bytes every collected signature is over.
    pub fn signing_bytes(&self) -> [u8; 200] {
        self.payload.signing_bytes()
    }

    /// Adds one BLS partial signature. The signer **must** be a member of
    /// `registry`; non-members are silently rejected. Returns
    /// `Some(SignedCheckpoint)` the first time the collected signers exceed 2/3
    /// of `registry`'s members — the roster active at the checkpoint round, not
    /// the live roster — and `None` otherwise. A duplicate signer counts once.
    ///
    /// Signers are sorted ascending by `NodeId` before aggregation so the
    /// aggregation order is deterministic across nodes.
    ///
    /// Weight model: all nodes currently have unit stake, so the threshold is
    /// `sigs.len() * 3 > total_members * 2`, matching `finalize_round`. When
    /// stake weights are added, replace with
    /// `total_weight_of_signers * 3 > total_weight * 2`.
    pub fn add_sig(
        &mut self,
        sig: CheckpointSig,
        registry: &MembershipRegistry,
    ) -> Option<SignedCheckpoint> {
        if sig.round != self.payload.round {
            return None;
        }
        if !registry.contains(&sig.signer) {
            return None;
        }
        let total = registry.len();
        if self.sigs.len() * 3 > total * 2 {
            return None; // already accepted
        }
        self.sigs.entry(sig.signer).or_insert(sig);
        if self.sigs.len() * 3 > total * 2 {
            // Determinism: sort signers ascending before aggregating.
            let mut sorted: Vec<&CheckpointSig> = self.sigs.values().collect();
            sorted.sort_by_key(|s| s.signer);
            let sig_refs: Vec<&BlsSignature> = sorted.iter().map(|s| &s.sig).collect();
            let agg = match crypto::bls::aggregate(&sig_refs) {
                Ok(a) => a,
                Err(_) => return None,
            };
            let mut signers: Vec<NodeId> = self.sigs.keys().copied().collect();
            signers.sort();
            Some(SignedCheckpoint { payload: self.payload.clone(), aggregate_sig: agg, signers })
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use crypto::bls::BlsIdentity;
    use crypto::{
        Hashable,
        RosterHistory,
        Signable,
    };
    use ed25519_dalek::SigningKey;
    use primitives::{
        Event,
        Timestamp,
        UnsignedEvent,
    };
    use rand::rngs::OsRng;

    use super::*;
    use crate::reconnect::{
        RetainedEvent,
        encode_roster_history,
    };

    fn bls_for(id: u64) -> BlsIdentity {
        BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls ikm")
    }

    fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            let bls = bls_for(id);
            let ed_key = ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key();
            // Use the BLS public key derived from the deterministic IKM so tests
            // can sign without plumbing real member secrets.
            registry.register(NodeId::new(id), ed_key, bls.public.to_bytes());
        }
        registry
    }

    fn registry_of_with_bls(members: &[(u64, BlsIdentity)]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for (id, bls) in members {
            let ed_key = ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key();
            registry.register(NodeId::new(*id), ed_key, bls.public.to_bytes());
        }
        registry
    }

    fn sig_for(round: u64, signer: u64, payload: &CheckpointPayload) -> CheckpointSig {
        let bls = bls_for(signer);
        let sig = bls.sign(&payload.signing_bytes());
        CheckpointSig { round, signer: NodeId::new(signer), sig }
    }

    fn empty_records_root() -> [u8; 32] {
        compute_records_root(&[])
    }

    #[test]
    fn checkpoint_payload_signing_bytes_is_deterministic() {
        let roster = registry_of(&[1, 2, 3, 4]);
        let rr = empty_records_root();
        let a = CheckpointPayload::new(3, rr, [7u8; 32], [0u8; 32], [0u8; 32], roster.clone());
        let b = CheckpointPayload::new(3, rr, [7u8; 32], [0u8; 32], [0u8; 32], roster);
        assert_eq!(a.signing_bytes(), b.signing_bytes());
        assert_eq!(a.signing_bytes().len(), 200);
        assert_ne!(
            a.signing_bytes(),
            CheckpointPayload::new(
                4,
                rr,
                [7u8; 32],
                [0u8; 32],
                [0u8; 32],
                a.roster_snapshot.clone()
            )
            .signing_bytes()
        );
        assert_ne!(
            a.signing_bytes(),
            CheckpointPayload::new(
                3,
                rr,
                [8u8; 32],
                [0u8; 32],
                [0u8; 32],
                a.roster_snapshot.clone()
            )
            .signing_bytes()
        );
        // Different records_root changes the commitment.
        let rr2 = compute_records_root(&[RecordsRootItem {
            event_hash: [1u8; 32],
            tx_index: 0,
            tx_payload: vec![1, 2, 3],
        }]);
        assert_ne!(
            a.signing_bytes(),
            CheckpointPayload::new(3, rr2, [7u8; 32], [0u8; 32], [0u8; 32], a.roster_snapshot)
                .signing_bytes()
        );
    }

    #[test]
    fn signing_bytes_length_is_200() {
        let roster = registry_of(&[1]);
        let payload = CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster);
        assert_eq!(payload.signing_bytes().len(), 200);
    }
    #[test]
    fn signing_bytes_binds_window_and_roster_history_roots() {
        let roster = registry_of(&[1]);
        let base =
            CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster.clone());
        let other_window =
            CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [5u8; 32], [0u8; 32], roster.clone());
        let other_history =
            CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [6u8; 32], roster);
        assert_ne!(base.signing_bytes(), other_window.signing_bytes());
        assert_ne!(base.signing_bytes(), other_history.signing_bytes());
        assert_eq!(&other_window.signing_bytes()[136..168], &[5u8; 32][..]);
        assert_eq!(&other_history.signing_bytes()[168..200], &[6u8; 32][..]);
    }
    #[test]
    fn prev_checkpoint_hash_defaults_to_genesis_and_binds_signing() {
        let roster = registry_of(&[1]);
        let genesis = CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster);
        // `new` leaves the chain anchor at the genesis sentinel.
        assert_eq!(genesis.prev_checkpoint_hash, [0u8; 32]);

        let chained = genesis.clone().with_prev_checkpoint_hash([9u8; 32]);
        // Chaining changes the signed bytes — but only in the prev 32.
        assert_ne!(genesis.signing_bytes(), chained.signing_bytes());
        assert_eq!(&genesis.signing_bytes()[..104], &chained.signing_bytes()[..104]);
        assert_eq!(&chained.signing_bytes()[104..136], &[9u8; 32][..]);
        assert_eq!(&genesis.signing_bytes()[136..], &chained.signing_bytes()[136..]);
    }
    #[test]
    fn signing_bytes_hash_binds_the_full_chain() {
        let roster = registry_of(&[1]);
        let a =
            CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster.clone())
                .with_prev_checkpoint_hash([1u8; 32]);
        let b = CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster)
            .with_prev_checkpoint_hash([2u8; 32]);
        // Different ancestry ⇒ different commitment, even for an otherwise
        // identical round. This is the property that kills history splices.
        assert_ne!(a.signing_bytes_hash(), b.signing_bytes_hash());
    }

    #[test]
    fn records_root_determinism_same_items_twice_same_root() {
        let items = vec![
            RecordsRootItem { event_hash: [1u8; 32], tx_index: 0, tx_payload: b"hello".to_vec() },
            RecordsRootItem { event_hash: [2u8; 32], tx_index: 1, tx_payload: b"world".to_vec() },
        ];
        let r1 = compute_records_root(&items);
        let r2 = compute_records_root(&items);
        assert_eq!(r1, r2);
    }

    #[test]
    fn records_root_different_order_different_root() {
        let a = vec![
            RecordsRootItem { event_hash: [1u8; 32], tx_index: 0, tx_payload: b"a".to_vec() },
            RecordsRootItem { event_hash: [2u8; 32], tx_index: 0, tx_payload: b"b".to_vec() },
        ];
        let mut b = a.clone();
        b.reverse();
        assert_ne!(compute_records_root(&a), compute_records_root(&b));
    }

    #[test]
    fn records_root_empty_round_stable() {
        let r1 = compute_records_root(&[]);
        let r2 = compute_records_root(&[]);
        assert_eq!(r1, r2);
        let expected: [u8; 32] = Sha256::digest([0x00u8]).into();
        assert_eq!(r1, expected);
    }

    #[test]
    fn records_root_single_item_is_leaf() {
        let item = RecordsRootItem {
            event_hash: [0xAB; 32],
            tx_index: 7,
            tx_payload: b"payload".to_vec(),
        };
        let root = compute_records_root(std::slice::from_ref(&item));
        let mut h = Sha256::new();
        h.update([0x00u8]);
        h.update(item.event_hash);
        h.update(item.tx_index.to_be_bytes());
        let len = u32::try_from(item.tx_payload.len()).unwrap();
        h.update(len.to_be_bytes());
        h.update(&item.tx_payload);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(root, expected);
    }

    #[test]
    fn records_root_two_items_is_internal_of_leaves() {
        let a = RecordsRootItem { event_hash: [1u8; 32], tx_index: 0, tx_payload: b"a".to_vec() };
        let b = RecordsRootItem { event_hash: [2u8; 32], tx_index: 1, tx_payload: b"b".to_vec() };
        let root = compute_records_root(&[a.clone(), b.clone()]);
        let leaf = |item: &RecordsRootItem| {
            let mut h = Sha256::new();
            h.update([0x00u8]);
            h.update(item.event_hash);
            h.update(item.tx_index.to_be_bytes());
            let len = u32::try_from(item.tx_payload.len()).unwrap();
            h.update(len.to_be_bytes());
            h.update(&item.tx_payload);
            let out: [u8; 32] = h.finalize().into();
            out
        };
        let la = leaf(&a);
        let lb = leaf(&b);
        let mut h = Sha256::new();
        h.update([0x02u8]);
        h.update(la);
        h.update(lb);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(root, expected);
    }

    #[test]
    fn records_root_three_items_padded_with_empty() {
        let items = vec![
            RecordsRootItem { event_hash: [1u8; 32], tx_index: 0, tx_payload: b"a".to_vec() },
            RecordsRootItem { event_hash: [2u8; 32], tx_index: 0, tx_payload: b"b".to_vec() },
            RecordsRootItem { event_hash: [3u8; 32], tx_index: 0, tx_payload: b"c".to_vec() },
        ];
        let root3 = compute_records_root(&items);
        let root4 = compute_records_root(&[
            items[0].clone(),
            items[1].clone(),
            items[2].clone(),
            RecordsRootItem { event_hash: [0u8; 32], tx_index: 0, tx_payload: Vec::new() },
        ]);
        assert_ne!(root3, root4);
        assert_ne!(root3, compute_records_root(&items[..2]));
    }

    #[test]
    fn accumulator_accepts_quorum_at_two_thirds_plus_one() {
        let ids = [1, 2, 3, 4];
        let members: Vec<(u64, BlsIdentity)> = ids.iter().map(|&id| (id, bls_for(id))).collect();
        let registry = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut accumulator = CheckpointAccumulator::new(payload.clone(), Vec::new());
        assert!(accumulator.add_sig(sig_for(1, 1, &payload), &registry).is_none());
        assert!(accumulator.add_sig(sig_for(1, 2, &payload), &registry).is_none());
        let accepted = accumulator.add_sig(sig_for(1, 3, &payload), &registry);
        assert!(accepted.is_some());
        let accepted = accepted.unwrap();
        assert_eq!(accepted.payload.round, 1);
        assert_eq!(accepted.signers.len(), 3);
        assert!(accepted.verify());
    }

    #[test]
    fn accumulator_rejects_below_quorum() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut accumulator = CheckpointAccumulator::new(payload.clone(), Vec::new());
        assert!(accumulator.add_sig(sig_for(1, 1, &payload), &registry).is_none());
        assert!(accumulator.add_sig(sig_for(1, 2, &payload), &registry).is_none());
        assert!(accumulator.add_sig(sig_for(1, 2, &payload), &registry).is_none());
    }

    #[test]
    fn accumulator_uses_round_roster_not_stale_roster() {
        let ids = [1, 2, 3, 4];
        let members: Vec<(u64, BlsIdentity)> = ids.iter().map(|&id| (id, bls_for(id))).collect();
        let round_roster = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], round_roster.clone());
        let mut accumulator = CheckpointAccumulator::new(payload.clone(), Vec::new());
        // 5th node joins after the checkpoint round
        let live_roster = {
            let mut reg = round_roster.clone();
            let bls5 = bls_for(5);
            reg.register(
                NodeId::new(5),
                ed25519_dalek::SigningKey::generate(&mut OsRng).verifying_key(),
                bls5.public.to_bytes(),
            );
            reg
        };
        accumulator.add_sig(sig_for(1, 1, &payload), &round_roster);
        accumulator.add_sig(sig_for(1, 2, &payload), &round_roster);
        let accepted = accumulator.add_sig(sig_for(1, 3, &payload), &round_roster);
        assert!(accepted.is_some(), "quorum computed from the round roster");

        let live_payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], live_roster.clone());
        let mut stale = CheckpointAccumulator::new(live_payload.clone(), Vec::new());
        // Need sigs for live roster's payload
        let sig1 = sig_for(1, 1, &live_payload);
        let sig2 = sig_for(1, 2, &live_payload);
        let sig3 = sig_for(1, 3, &live_payload);
        stale.add_sig(sig1, &live_roster);
        stale.add_sig(sig2, &live_roster);
        assert!(stale.add_sig(sig3, &live_roster).is_none());
    }

    #[test]
    fn duplicate_signer_does_not_double_count() {
        let ids = [1, 2, 3, 4];
        let members: Vec<(u64, BlsIdentity)> = ids.iter().map(|&id| (id, bls_for(id))).collect();
        let registry = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut accumulator = CheckpointAccumulator::new(payload.clone(), Vec::new());
        accumulator.add_sig(sig_for(1, 1, &payload), &registry);
        assert!(accumulator.add_sig(sig_for(1, 1, &payload), &registry).is_none());
        accumulator.add_sig(sig_for(1, 2, &payload), &registry);
        assert!(accumulator.add_sig(sig_for(1, 2, &payload), &registry).is_none());
        let accepted = accumulator.add_sig(sig_for(1, 3, &payload), &registry);
        assert!(accepted.is_some());
        assert_eq!(accepted.unwrap().signers.len(), 3);
        assert!(accumulator.add_sig(sig_for(1, 4, &payload), &registry).is_none());
    }

    #[test]
    fn checkpoint_sig_round_trips_through_canonical_bytes() {
        let roster = registry_of(&[1]);
        let payload =
            CheckpointPayload::new(42, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster);
        let original = sig_for(42, 7, &payload);
        let bytes = original.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 112);
        assert_eq!(CheckpointSig::decode(&bytes), Some(original));

        let mut bad = bytes[..111].to_vec();
        assert_eq!(CheckpointSig::decode(&bad), None);
        bad.push(0);
        bad.push(0);
        assert_eq!(CheckpointSig::decode(&bad), None);
        // Truncation
        assert_eq!(CheckpointSig::decode(&bytes[..100]), None);
    }

    #[test]
    fn wrong_round_sig_is_ignored() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut accumulator = CheckpointAccumulator::new(payload, Vec::new());
        let bad = sig_for(
            2,
            1,
            &CheckpointPayload::new(2, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone()),
        );
        assert!(accumulator.add_sig(bad, &registry).is_none());
    }

    #[test]
    fn non_member_sig_is_ignored() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut accumulator = CheckpointAccumulator::new(payload, Vec::new());
        let bad_payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let bad_sig = sig_for(1, 5, &bad_payload);
        assert!(accumulator.add_sig(bad_sig, &registry).is_none());
        assert!(accumulator.sigs.is_empty());
    }

    #[test]
    fn accumulator_carries_snapshot_bytes() {
        let registry = registry_of(&[1, 2, 3]);
        let payload =
            CheckpointPayload::new(1, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], registry);
        let snapshot = vec![7u8; 4];
        let accumulator = CheckpointAccumulator::new(payload, snapshot.clone());
        assert_eq!(accumulator.snapshot(), &[7u8; 4]);
        assert_eq!(accumulator.snapshot(), snapshot.as_slice());
    }

    #[test]
    fn aggregate_roundtrip_through_verify() {
        let ids = [1, 2, 3, 4];
        let members: Vec<(u64, BlsIdentity)> = ids.iter().map(|&id| (id, bls_for(id))).collect();
        let registry = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(5, rr, [0xABu8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut acc = CheckpointAccumulator::new(payload.clone(), Vec::new());
        acc.add_sig(sig_for(5, 1, &payload), &registry);
        acc.add_sig(sig_for(5, 2, &payload), &registry);
        let accepted = acc.add_sig(sig_for(5, 3, &payload), &registry).expect("quorum");
        assert!(accepted.verify());
        assert!(accepted.verify_with_registry(&registry));
    }

    #[test]
    fn below_quorum_returns_none_no_acceptance() {
        let registry = registry_of(&[1, 2, 3, 4]);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut acc = CheckpointAccumulator::new(payload.clone(), Vec::new());
        assert!(acc.add_sig(sig_for(1, 1, &payload), &registry).is_none());
        assert!(acc.add_sig(sig_for(1, 2, &payload), &registry).is_none());
        // Still none, below quorum
        assert_eq!(acc.sigs.len(), 2);
    }

    #[test]
    fn tampered_partial_rejected_aggregate_mismatch() {
        let ids = [1, 2, 3];
        let members: Vec<(u64, BlsIdentity)> = ids.iter().map(|&id| (id, bls_for(id))).collect();
        let registry = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(1, rr, [0u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        let mut acc = CheckpointAccumulator::new(payload.clone(), Vec::new());
        // Two honest
        acc.add_sig(sig_for(1, 1, &payload), &registry);
        acc.add_sig(sig_for(1, 2, &payload), &registry);
        // Tampered: signer 3 but signed wrong message (different records_root)
        let wrong_payload = CheckpointPayload::new(
            1,
            [0xFFu8; 32],
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            registry.clone(),
        );
        let tampered = sig_for(1, 3, &wrong_payload);
        let accepted = acc.add_sig(tampered, &registry).expect("quorum reached even with bad sig");
        // Aggregate includes tampered sig, so verify must fail
        assert!(!accepted.verify(), "tampered partial must cause aggregate mismatch");
    }

    #[test]
    fn forged_third_partial_signature_fails_verify() {
        // 3-of-4 roster, but third sig is from a key NOT among honest signers
        let honest_ids = [1, 2, 3, 4];
        let members: Vec<(u64, BlsIdentity)> =
            honest_ids.iter().map(|&id| (id, bls_for(id))).collect();
        let registry = registry_of_with_bls(&members);
        let rr = empty_records_root();
        let payload =
            CheckpointPayload::new(7, rr, [11u8; 32], [0u8; 32], [0u8; 32], registry.clone());
        // Build an accumulator and feed two honest sigs
        let mut acc = CheckpointAccumulator::new(payload.clone(), Vec::new());
        acc.add_sig(sig_for(7, 1, &payload), &registry);
        acc.add_sig(sig_for(7, 2, &payload), &registry);
        // Forge sig for signer 3 using a different key (not in registry)
        let forger = BlsIdentity::from_ikm(&[0xEEu8; 32]).expect("forger");
        let forged_sig = CheckpointSig {
            round: 7,
            signer: NodeId::new(3),
            sig: forger.sign(&payload.signing_bytes()),
        };
        // The accumulator will accept it (member check passes for signer 3, but sig is from wrong key)
        // However the forger's key is not the registry's key for node 3, so aggregate will not verify
        let accepted = acc.add_sig(forged_sig, &registry).expect("quorum");
        assert!(!accepted.verify(), "forged sig by wrong key must fail aggregate verify");
    }

    #[test]
    fn wire_112_roundtrip_and_truncation_rejection() {
        let roster = registry_of(&[1]);
        let payload = CheckpointPayload::new(9, [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32], roster);
        let sig = sig_for(9, 1, &payload);
        let bytes = sig.canonical_bytes().unwrap();
        assert_eq!(bytes.len(), 112);
        assert_eq!(CheckpointSig::decode(&bytes).unwrap().signer, NodeId::new(1));
        // Truncate by one
        assert_eq!(CheckpointSig::decode(&bytes[..111]), None);
        // Extra byte
        let mut extra = bytes;
        extra.push(0);
        assert_eq!(CheckpointSig::decode(&extra), None);
    }

    fn window_keys(ids: &[u64]) -> Vec<(NodeId, SigningKey)> {
        ids.iter().map(|&id| (NodeId::new(id), SigningKey::generate(&mut OsRng))).collect()
    }

    fn window_registry(keys: &[(NodeId, SigningKey)]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for (id, key) in keys {
            let bls = BlsIdentity::from_ikm(&[id.get() as u8; 32]).expect("bls ikm");
            registry.register(*id, key.verifying_key(), bls.public.to_bytes());
        }
        registry
    }

    fn sign_window_event(
        key: &SigningKey,
        creator: NodeId,
        self_parent: Option<EventHash>,
        ts: u64,
    ) -> Event {
        UnsignedEvent::new(creator, self_parent, None, Timestamp::new(ts), Vec::new())
            .sign(key)
            .expect("test event signs")
    }

    #[derive(Clone)]
    struct WindowEventDef {
        event: Event,
        seq: u64,
        round: u64,
        ancestor_seqs: Vec<u64>,
        round_received: u64,
        consensus_ts: u64,
    }

    fn window_graph(
        registry: &MembershipRegistry,
        checkpoint_round: u64,
        defs: &[WindowEventDef],
    ) -> Hashgraph {
        let payload = CheckpointPayload::new(
            checkpoint_round,
            compute_records_root(&[]),
            [0u8; 32],
            [0u8; 32],
            [0u8; 32],
            registry.clone(),
        );
        let mut hg = Hashgraph::from_checkpoint(&payload, RosterHistory::new(registry.clone()));
        for def in defs {
            hg.insert_accepted(
                RetainedEvent {
                    event: def.event.clone(),
                    seq: def.seq,
                    round: def.round,
                    ancestor_seqs: def.ancestor_seqs.clone(),
                    round_received: Some(def.round_received),
                    consensus_timestamp: Some(Timestamp::new(def.consensus_ts)),
                },
                checkpoint_round,
            )
            .expect("window fixture inserts");
        }
        hg
    }

    fn two_member_window_defs(keys: &[(NodeId, SigningKey)]) -> Vec<WindowEventDef> {
        let (node_a, key_a) = &keys[0];
        let (node_b, key_b) = &keys[1];
        let event_a1 = sign_window_event(key_a, *node_a, None, 10);
        let event_b1 = sign_window_event(key_b, *node_b, None, 20);
        let hash_a1: EventHash = event_a1.hash().expect("test event hashes");
        let hash_b1: EventHash = event_b1.hash().expect("test event hashes");
        let event_a2 = sign_window_event(key_a, *node_a, Some(hash_a1), 30);
        let event_b2 = sign_window_event(key_b, *node_b, Some(hash_b1), 40);
        vec![
            WindowEventDef {
                event: event_a1,
                seq: 1,
                round: 1,
                ancestor_seqs: vec![1, 0],
                round_received: 1,
                consensus_ts: 100,
            },
            WindowEventDef {
                event: event_b1,
                seq: 1,
                round: 1,
                ancestor_seqs: vec![0, 1],
                round_received: 1,
                consensus_ts: 200,
            },
            WindowEventDef {
                event: event_a2,
                seq: 2,
                round: 1,
                ancestor_seqs: vec![2, 0],
                round_received: 2,
                consensus_ts: 300,
            },
            WindowEventDef {
                event: event_b2,
                seq: 2,
                round: 1,
                ancestor_seqs: vec![0, 2],
                round_received: 2,
                consensus_ts: 400,
            },
        ]
    }

    #[test]
    fn window_root_is_deterministic() {
        let keys = window_keys(&[1, 2]);
        let registry = window_registry(&keys);
        let defs = two_member_window_defs(&keys);
        let first = window_graph(&registry, 5, &defs);
        let second = window_graph(&registry, 5, &defs);
        assert_eq!(compute_window_root(&first, 2, 1), compute_window_root(&second, 2, 1));
    }

    #[test]
    fn window_root_changes_with_window_rounds() {
        let keys = window_keys(&[1, 2]);
        let registry = window_registry(&keys);
        let defs = two_member_window_defs(&keys);
        let hg = window_graph(&registry, 5, &defs);
        let narrow = compute_window_root(&hg, 2, 0);
        let wide = compute_window_root(&hg, 2, 1);
        assert_ne!(narrow, wide);
    }

    #[test]
    fn window_root_empty_is_records_root_empty() {
        let keys = window_keys(&[1, 2]);
        let registry = window_registry(&keys);
        let hg = window_graph(&registry, 5, &[]);
        assert_eq!(compute_window_root(&hg, 0, 0), compute_records_root(&[]));
    }

    #[test]
    fn window_root_binds_record_metadata() {
        let keys = window_keys(&[1, 2]);
        let registry = window_registry(&keys);
        let defs = two_member_window_defs(&keys);
        let baseline = window_graph(&registry, 5, &defs);
        // Exactly one in-window event carries different ordering metadata;
        // its consensus order slot is unchanged (150 < 200), so only the
        // leaf binding can move the root.
        let mut altered = defs.clone();
        altered[0].consensus_ts = 150;
        let changed = window_graph(&registry, 5, &altered);
        assert_ne!(compute_window_root(&baseline, 2, 1), compute_window_root(&changed, 2, 1));
    }

    #[test]
    fn window_root_ignores_rows_appended_by_add_member() {
        let keys = window_keys(&[1, 2]);
        let before_registry = window_registry(&keys[..1]);
        let after_registry = window_registry(&keys);
        let (node_a, key_a) = &keys[0];
        let event_a1 = sign_window_event(key_a, *node_a, None, 10);
        let hash_a1: EventHash = event_a1.hash().expect("test event hashes");
        let event_a2 = sign_window_event(key_a, *node_a, Some(hash_a1), 30);
        let defs = vec![
            WindowEventDef {
                event: event_a1,
                seq: 1,
                round: 1,
                ancestor_seqs: vec![1],
                round_received: 1,
                consensus_ts: 100,
            },
            WindowEventDef {
                event: event_a2,
                seq: 2,
                round: 1,
                ancestor_seqs: vec![2],
                round_received: 1,
                consensus_ts: 200,
            },
        ];
        let mut hg = window_graph(&before_registry, 5, &defs);
        let before = compute_window_root(&hg, 1, 5);
        hg.add_member(NodeId::new(2), 10, after_registry);
        // The stored rows really did grow a trailing zero slot ...
        assert_eq!(hg.get(&hash_a1).expect("present").ancestor_seqs_len(), 2);
        // ... yet the canonical root for round 1 is unchanged.
        assert_eq!(compute_window_root(&hg, 1, 5), before);
    }

    fn roster_registries() -> (MembershipRegistry, MembershipRegistry, MembershipRegistry) {
        let keys = window_keys(&[1, 2, 3]);
        (window_registry(&keys[..1]), window_registry(&keys[..2]), window_registry(&keys))
    }

    fn history_of(entries: Vec<(u64, MembershipRegistry)>) -> RosterHistory {
        RosterHistory::from_snapshots(entries).expect("test history builds")
    }

    #[test]
    fn roster_history_root_is_deterministic() {
        let (reg1, _, reg3) = roster_registries();
        let first = history_of(vec![(1, reg1.clone()), (5, reg3.clone())]);
        let second = history_of(vec![(1, reg1), (5, reg3)]);
        assert_eq!(roster_history_root(&first, 5, 4), roster_history_root(&second, 5, 4));
    }

    #[test]
    fn roster_history_root_changes_with_window_rounds() {
        let (reg1, reg2, reg3) = roster_registries();
        let rh = history_of(vec![(1, reg1), (3, reg2), (5, reg3)]);
        // W=0 selects {3, 5} (predecessor 3 plus round 5); W=4 selects
        // {1, 3, 5}. Different canonical sets, different roots.
        assert_ne!(roster_history_root(&rh, 5, 0), roster_history_root(&rh, 5, 4));
    }

    #[test]
    fn roster_history_root_includes_predecessor() {
        let (reg1, reg2, reg3) = roster_registries();
        let without_mid = history_of(vec![(1, reg1.clone()), (5, reg3.clone())]);
        let with_mid = history_of(vec![(1, reg1.clone()), (3, reg2), (5, reg3.clone())]);
        // With window_start = 3 both selections must contain round 1: pin
        // the {1, 5} selection byte-for-byte through the public encoding.
        let expected_subset = history_of(vec![(1, reg1), (5, reg3)]);
        let expected_bytes = encode_roster_history(&expected_subset).expect("test history encodes");
        let mut h = Sha256::new();
        h.update(b"JKAIN-ROSTER-HISTORY-ROOT-V1");
        h.update(&expected_bytes);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(roster_history_root(&without_mid, 5, 2), expected);
        // ... and the in-window round 3 is bound too: the two histories differ.
        assert_ne!(roster_history_root(&without_mid, 5, 2), roster_history_root(&with_mid, 5, 2));
    }

    #[test]
    fn roster_history_root_ignores_out_of_window_snapshot() {
        let (reg1, _, reg3) = roster_registries();
        let keys = window_keys(&[4]);
        let reg7 = window_registry(&keys);
        let base = history_of(vec![(1, reg1.clone()), (5, reg3.clone())]);
        let extended = history_of(vec![(1, reg1), (5, reg3), (7, reg7)]);
        // Activation round 7 is above the checkpoint round: excluded.
        assert_eq!(roster_history_root(&base, 5, 4), roster_history_root(&extended, 5, 4));
    }

    #[test]
    fn canonical_roster_history_encodes_to_the_committed_bytes() {
        let (reg1, reg2, reg3) = roster_registries();
        let rh = history_of(vec![(1, reg1.clone()), (3, reg2), (5, reg3.clone())]);
        // The canonical selection for round 5, W=2 is the predecessor (round
        // 1) plus the in-window rounds 3 and 5; encoding it must reproduce
        // exactly the bytes the root hashes.
        let canonical = canonical_roster_history(&rh, 5, 2).expect("selection is non-empty");
        let encoded = encode_roster_history(&canonical).expect("test history encodes");
        let mut h = Sha256::new();
        h.update(b"JKAIN-ROSTER-HISTORY-ROOT-V1");
        h.update(&encoded);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(compute_roster_history_root(&rh, 5, 2).expect("root computes"), expected);
        // Round 0 with nothing at or below it selects nothing.
        assert!(canonical_roster_history(&rh, 0, 0).is_none());
    }

    #[test]
    fn roster_history_root_empty_is_dst_only() {
        let (reg1, _, _) = roster_registries();
        let rh = history_of(vec![(1, reg1)]);
        // No snapshot at or below round 0: the selection is empty.
        let expected: [u8; 32] = Sha256::digest(b"JKAIN-ROSTER-HISTORY-ROOT-V1").into();
        assert_eq!(roster_history_root(&rh, 0, 0), expected);
    }
}
