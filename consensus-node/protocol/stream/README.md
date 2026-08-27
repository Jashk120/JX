# stream

Mirror stream files (Phase 8, point 3 of `ROADMAP.md`): the **new file types a
mirror node consumes**, emitted by a *consensus* node into a node-scoped
directory under `<data>/streams/`. See `PHASE8_MIRROR_STREAMS.md` at the repo
root for the full design.

Everything a mirror consumes is protobuf (per `AGENTS.md`, Wire Formats); the
internal consensus/gossip encodings are unchanged. The protobuf schema lives
at the monorepo root `proto/jkain_stream.proto` and is shared between
`consensus-node` and future crates; `protocol/stream/build.rs` compiles it via
`../../../proto` and generates it with `build.rs` (prost).

`STREAM_VERSION` 3 is stamped inside every `EventStreamFile` /
`RecordStreamFile` and `RecordsProofFile`. The bump 2 → 3 covered chained
checkpoints (`prev_checkpoint_hash`, signing_bytes 104 B → 136 B), Merkle
`records_root` (padded power-of-two with Hiero domain-separated prefixes), the
`state_diffs` field in `RecordStreamFile`, and the companion `.rsf_proofs`
sidecar.

## Two file types plus one sidecar

| File | Content | Written when |
|---|---|---|
| `events-<n>.esf` | every gossip event this node inserted, in insertion (= topological) order — the offline DAG source | the event window fills (a fixed event count, default 10 000) or on flush |
| `round-<r>.rsf` | one decided round's finalized transactions in consensus order (`RecordItem` = `event_hash||tx_index||tx_payload`), plus the round's threshold-signed `SignedCheckpoint` and the round's `state_diffs` (after-image, sorted LWW, `value=None` = tombstone) | the round's checkpoint reaches the ≥2/3 quorum |
| `round-<r>.rsf_proofs` | `RecordsProofFile { version, round, proofs }` — one `ProofEntry` per `RecordItem`, each carrying `ProofStep { sibling_hash[32], sibling_is_right }` from leaf to root over the padded Merkle tree that defines `records_root` | atomically alongside its `.rsf` |

`.esf` files are accompanied by `.esf_sig` Ed25519 signature files
(`file_signature` over `SHA256(file)` and `metadata_signature` over
`version||start_running_hash||end_running_hash`). **`.rsf` files have no
`.rsf_sig`** — since `1313db5` / PLAN-1 they are authenticated by content
binding: `records_root` recomputed from `items` and the BLS aggregate over
136-byte signing_bytes.

Every stream file is chained by the §5 running hash (SHA-256,
domain-separated, seed `[0u8; 32]`): `item_hash = SHA256(DOMAIN||"item"||item)`,
`chain_hash = SHA256(DOMAIN||"chain"||prev||item)`. Files are written
atomically (temp + `sync_all` + rename + dir fsync); `.esf_sig` is written
before the `.esf` so a crash can only orphan a signature — never leave a
stream file unsigned. `.rsf` + sidecar are written atomically via the same
helper; a missing sidecar on the filesystem is treated as empty (verifier
checks count/index/sibling widths + `VerifyRecordsProof`).

## Records root and proofs (Merkle)

`records_root` is the padded binary Merkle root over per-item leaves in
consensus order, with Hiero-style domain separation (mirror of
`executor/state/src/merkle.rs`):

```
empty            = SHA256(0x00)
leaf(item)       = SHA256(0x00 || event_hash[32] || u32_BE(tx_index) || u32_BE(len(tx_payload)) || tx_payload)
internal(l, r)   = SHA256(0x02 || l || r)
singleton(c)     = SHA256(0x01 || c)
combine(l,r): (empty,empty)->empty; (empty,r)->singleton(r); (l,empty)->singleton(l); else internal(l,r)
```

Leaves are padded to the next power of two with `empty`; the tree is folded
bottom-up with `combine`. Empty rounds yield `empty`; singleton rounds have
zero-step proofs. `build_records_proofs` / `verify_records_proof` (in
`protocol/consensus`) and `proof::build_records_proofs_from_items` /
`proof::verify_proof` (in this crate) are the canonical and mirror-facing
implementations; the Go mirror uses the same SHA-256 construction byte-for-byte
(golden vectors cover cross-language equality).

## Checkpoint chaining

`CheckpointPayload::signing_bytes` is `round(8 BE)||records_root(32)||state_hash(32)||roster_hash(32)||prev_checkpoint_hash(32)` = **136 B** (was 104 B before
PLAN-2). `prev_checkpoint_hash` is `SHA256(signing_bytes(prev_round))`,
genesis `[0;32]`. `SignedCheckpoint::verify` checks distinct signers in the
embedded roster, `valid*3>total*2`, and `crypto::bls::verify_aggregate` over
those bytes with DST `JKAIN-CHECKPOINT-BLS-V1`. The mirror also checks
`prev` continuity across consecutive `.rsf`s (genesis zeros for the earliest
file) and rejects history splices.

## State diffs

`RecordStreamFile.state_diffs` carries the round's KV mutations as after-images
`(key, new_value | tombstone)`, canonically **sorted ascending by key, last-write-wins** per key, validated by `VerifyStateDiffs` / `ValidateStateDiffs`
(sorted, no duplicate keys, non-empty keys). They are the source for mirror
state reconstruction (`StateChanges` analogue) and are not consulted by the
checkpoint quorum check itself.

## Modules

- `running_hash` — the §5 chain: `item_hash` + `chain_hash` over the seed.
- `signature` — `SignatureFile` build/write/read/verify (Ed25519), atomic writes.
  Used only for `.esf`/`.esf_sig`; record files no longer use this path.
- `convert` — translations between the protobuf mirror types and the canonical
  consensus/primitives forms (`Event`, `SignedCheckpoint`, record items,
  `StateDiff`).
- `event` — the event stream: `EventStreamWriter` (a second `storage::EventSink`)
  plus the file reader.
- `record` — the record stream: `RecordStreamWriter` (implements
  `RecordSink`), the item assembler over `Hashgraph::consensus_order`, plus the
  file reader and the proof sidecar writer (`write_records_proof_file`,
  `record_proof_files_in`).
- `proof` — Merkle proof sidecar: `build_records_proofs_from_items`,
  `write_records_proof_file` / `read_records_proof_file` / `proof_files_in`,
  `verify_proof` (single-item) and `VerifyRecordsProofFile` semantics.
- `verify` — the mirror-side verifier: running-hash chain continuity, `.esf`
  signature files, and the embedded checkpoint quorum
  (`valid * 3 > total * 2` against the trusted/embedded roster), plus
  `records_root` binding, `prev` chain, `state_diffs` sort, and per-round
  proof sidecar verification — the exact steps a Go mirror performs from the
  files alone. No `.rsf_sig` is consulted.

## Wiring

The gossip layer (`GossipNode`) holds the mirror sinks:

- `set_event_stream_sink` — a second `storage::EventSink` next to the
  `EventLog`, fed every freshly inserted event (`log_fresh_inserts`,
  reconnect-appended retained events). Ordering/roster-history changes and
  prunes are deliberately not forwarded; a mirror that needs a round→event
  mapping reads the record stream.
- `set_record_sink` — a `stream::RecordSink` notified from
  `accept_checkpoint`, so each decided round's `.rsf` + `.rsf_proofs` are
  emitted from the threshold-signed anchor. The writer holds a clone of the
  node's hashgraph to assemble `consensus_order(round)` items (final and
  immutable at that point) and a `state_diffs` capture for the round, then
  writes both files on a background task.
- `set_record_proof_sink` — optional separate `RecordStreamWriter` for the
  proof sidecar (typically the same writer as `record_sink`; kept separate so
  a dedicated proof writer can be used if desired).

All writers consume an ordered channel on a dedicated tokio task, so the
consensus hot path never blocks on disk.

`jkaind` opens `<data>/streams/` and registers the writers with the node's
signing material (`bls_identity` for record checkpoints, `signing_key` for
event sigs).

## Verification

A mirror (or a test acting as one) verifies a directory with
`verify::verify_record_stream_dir(dir, node_id, trusted_roster_hash)` /
`verify::verify_event_stream_dir(dir, node_key)`: chain continuity across
files, the `.esf` signature files, and — for record files — the embedded
checkpoint quorum (anchored against `trusted_roster_hash` or the embedded
roster when empty), the Merkle `records_root`, `prev_checkpoint_hash`
continuity, the sorted/deduped `state_diffs`, and the companion
`.rsf_proofs` file (count == items, index order, 32-byte siblings, and
`verify_records_proof` per item). Truncation, trailing bytes, tampering,
reordering, history splices, and forged rosters are all rejected.

The record stream is byte-identical across the cluster for the rounds a node
has written: `consensus_order(round)` is deterministic, prost encoding is
deterministic (canonical), and BLS aggregation is over sorted signers. A node
that starts from a checkpoint mid-history (reconnect) writes a record stream
chained from its own seed — chain-consistent within its directory, but not
identical to a genesis node's chain for those rounds.

## Tests

- `tests/determinism.rs` — two independent writers → byte-identical streams.
- `tests/chain.rs` — file N+1 start == file N end; truncation/trailing/tamper/
  reorder rejected.
- `tests/mirror.rs` — decode-as-Go: pure protobuf reads + the verifier, no
  writer code, proving cross-language decodability. Covers Merkle/proofs and
  prev chain.
- `protocol/gossip/tests/streams.rs` — end-to-end wiring: a live checkpoint
  accept emits a verifiable `.rsf` + `.rsf_proofs`; a live cluster's events
  flow into `.esf`s.
