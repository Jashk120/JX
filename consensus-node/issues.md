# Bug Audit — Open Issues

Full-repo audit (consensus-node + mirror-node + proto), conducted via parallel code review
with manual verification of every critical/high finding against the cited source.
`cargo clippy --workspace --all-targets --locked` was clean at audit time.
The mirror ingest duplication bug (unconditional `PutEvents`/`PutRecord` re-appending all
files on every poll) has been fixed and is intentionally omitted here.

Severity classes reflect worst-case impact; confidence is stated per issue
(`certain` = traced end-to-end in code, `likely` = mechanism certain, trigger timing
depends on runtime conditions, `possible` = requires a specific operational scenario).

---

## High

### H-1. Duplicate roster members bypass stream signature verification (forgery)
- **Files:** `protocol/stream/src/convert.rs:156-164`, `convert.rs:169-176`
- **Confidence:** certain

Two readers of the same repeated protobuf field disagree about duplicates:
`roster_from_members` resolves a node_id **last-wins** (HashMap insert overwrites),
while `checkpoint_member_key` resolves **first-match** (`iter().find()`).

An attacker who can rewrite `.rsf`/`.esf` files prepends one entry
`{node_id:1, key:k_attacker}` to an otherwise honest roster. The collapsed registry
built for the quorum check still uses the original key set (internal roster-hash check
and trusted-roster-hash check both pass with the *original* signatures), but
`checkpoint_member_key` then returns `k_attacker` — the attacker rewrites items,
recomputes the chain, and re-signs the file with their own key. Everything verifies.

This defeats both guarantees of `verify_record_stream_dir`: authenticity of emitting
node files ("no single node is trusted", `verify.rs:15-17`) and the wrong-node rejection
proven in `tests/mirror.rs:117-126`.

**Fix:** reject duplicate node_ids in `roster_from_members`, or resolve keys via the
validated registry instead of the raw pb list.

### H-2. Events finalized behind the watermark are permanently skipped → silent state divergence
- **Files:** `executor/state/src/executor.rs:110-132`, caller `protocol/gossip/src/node.rs:623-642`
- **Confidence:** likely (logic certain; reachability depends on gossip timing)

`bucket_finalized` skips any event whose `round_received <= processed_through_round`.
An event `y` absent from a node when rounds up to R are decided elsewhere arrives later
with `round_received <= R`; it is collected by Phase A but skipped forever by the
watermark check. Its KV/DID ops are applied late or never, its membership ops are never
bucketed, and this node's Merkle root diverges from honest nodes — checkpoints stop
aggregating and the divergence is silent. There is no reconciliation path once
`processed_through_round` has passed.

**Fix:** buffer out-of-order finalized events into a pending set and re-execute them in
order, or refuse to advance past a round with known-unseen ancestry.

### H-3. Reconnect learner loses `consensusTimestamp` → replay order diverges from the cluster
- **Files:** `protocol/consensus/src/hashgraph.rs:441-454` (esp. line 452),
  `protocol/consensus/src/reconnect.rs:38-48`, `protocol/gossip/src/proto.rs:150-167`
- **Confidence:** likely

When a teacher transfers its retained graph, each ordered event is reconstructed on the
learner with a fabricated zero timestamp (`insert_accepted` sets
`consensus_timestamp: round_received.map(|_| Timestamp::new(0))`). The real timestamp is
lost in transit: `RetainedEvent` carries no such field and the `ReconnectResponse` wire
encoding does not transmit it. Since `consensus_order` sorts primarily by timestamp
(`order.rs:264-276`), the learner replays same-round events in signature-fold order
instead of timestamp order → per-round state roots differ, subsequent checkpoint
signatures never verify against peers, and record streams emit in a different order.
The doc comment's safety claim on `insert_accepted` is false for within-round ordering.
Existing e2e test misses it because it writes distinct keys per event.

**Fix:** carry the teacher's `consensus_timestamp` through `RetainedEvent`,
`encode_retained_event`/`decode_retained_event`, and the `Frame::ReconnectResponse`
encoding; restore verbatim in `insert_accepted`. (Or have the learner re-derive order.)

### H-4. mirrord can never verify signatures; no way to configure `PubKey`
- **Files:** `mirror-node/cmd/mirrord/main.go:65-67`, `mirror-node/internal/config/config.go`,
  gates at `mirror-node/internal/stream/verify.go:49,89`, contract at
  `mirror-node/internal/ingest/ingest.go:22-28`
- **Confidence:** certain

The daemon builds `ingest.Config` without `PubKey`, and config exposes no flag/env var
for the node's Ed25519 verifying key. Both verifiers skip all signature checks when
`pubKey == nil` — exactly the configuration the ingest docs label test-only. Anyone able
to write files into `StreamsDir` supplies history that passes every check actually run.

**Fix:** expose the verifying key via config/flag/file and require (or loudly warn when
absent) in production startup.

### H-5. Mirror checkpoint quorum trusts a self-referential roster (no trusted-roster-hash anchor)
- **Files:** `mirror-node/internal/stream/verify.go:246-299`; Rust reference
  `protocol/stream/src/verify.rs:82-90,235-268`; attack demo
  `protocol/stream/tests/mirror.rs:194-287`
- **Confidence:** certain that the divergence exists

Go validates that the embedded roster hashes to `roster_hash`, then counts quorum
against that same embedded roster — no trusted-roster-hash input exists anywhere in the
Go path. The Rust verifier fail-closed requires an externally supplied hash precisely
because "a fabricated roster could make the self-referential quorum trivially pass".
`tests/mirror.rs` demonstrates the attack end-to-end (forged roster `{1,10,11,12}`,
3-of-4 attacker signatures reach quorum under self-trust). Combined with H-4, an
attacker who can write into `StreamsDir` fabricates a fully "verified" stream.
README.md's claim of parity with `verify.rs` is untrue for this function.

**Fix:** thread a configured trusted roster hash into the Go quorum check and fail
closed without it, matching `verify.rs`.

---

## Medium-high

### MH-1. Unbounded frame allocation from attacker-controlled length prefix
- **File:** `protocol/gossip/src/transport.rs:100-107`
- **Confidence:** certain

`recv_frame` allocates `vec![0u8; len]` where `len` is a raw u32 header (up to ~4 GiB),
zero-touching all pages before any validation. Inbound TLS uses `.with_no_client_auth()`
(`tls.rs:110`) — only clients pin the server — so any host able to open a TCP+TLS
connection can OOM the process by declaring large lengths and never sending payloads.

**Fix:** enforce a protocol-level max frame size in `TcpTransport::recv_frame` and reject
oversized prefixes with `GossipError::Framing`.

### MH-2. Unguarded `Vec::with_capacity` on wire-controlled counts in reconnect decoders
- **File:** `protocol/consensus/src/reconnect.rs:196-197, 236-237`
- **Confidence:** certain

`decode_signed_checkpoint` (`Vec::with_capacity(sig_count)`) and `decode_roster_history`
(`Vec::with_capacity(entry_count)`) reserve capacity straight from raw u32 wire values
(~344 GB possible for ~80 bytes of input); allocator failure aborts the process. The
remaining-buffer sanity guard pattern already used throughout `gossip/proto.rs` was
never applied to these nested decoders. Reachable pre-auth: frames fully decode before
type dispatch, including `ReconnectResponse` frames rejected only afterwards as
protocol violations.

**Fix:** add the `count > cursor.remaining() / MIN_ITEM` guard used in proto.rs before
both calls.

### MH-3. Graceful shutdown loses up to 10,000 buffered events from the event stream
- **Files:** `node/src/bin/jkaind.rs:617-628, 668-714`, `protocol/gossip/src/node.rs:933-937`,
  `protocol/stream/src/event.rs:167-196`
- **Confidence:** likely

`event_stream_sink` is only ever appended to — nothing calls its `flush()` or awaits the
writer barrier at shutdown (only the event-log sink is flushed in `accept_checkpoint`).
Dropping the node ends `run_writer` without writing its buffer, so every event since the
last 10k-window close is permanently absent from `.esf` while possibly present as
records — the streams silently fork on every restart not landing on a file boundary.

**Fix:** flush the stream sink + await `barrier()` in shutdown, and/or flush alongside
the event-log sink in `accept_checkpoint`.

### MH-4. One failed `.esf` write poisons the whole event-stream chain forever
- **File:** `protocol/stream/src/event.rs:167-190` (state machine `event.rs:83-88`)
- **Confidence:** certain (behavior; impact needs a write failure)

The running hash advances *before* the write and `state.advance()` runs even on failure:
buffered events are dropped, and the next successfully written file starts at a hash
unreachable from the previous file — `verify_event_stream_dir` then fails with
`ChainDiscontinuity` on every future run, silently (stderr log only). `record.rs:168-174,
211` handles this correctly and should be mirrored.

**Fix:** keep the buffer and retry on write failure instead of advancing unconditionally.

---

## Medium

### M-1. `outbound_checkpoint_sigs` never drains — linear bandwidth/memory growth
- **File:** `protocol/gossip/src/node.rs:136,212,793,1000-1007`
- **Confidence:** certain

Signatures are pushed per produced checkpoint and cloned-and-sent on every successful
sync round, but nothing ever removes entries after acceptance (the intent documented at
`node.rs:521-524` is unimplemented). After N decided rounds every sync sends N+
checkpoint-sig frames and memory grows forever.

**Fix:** drain sigs for rounds ≤ the latest accepted checkpoint inside `accept_checkpoint`
(or store keyed by round and retain/split_off).

### M-2. `pending_checkpoint_sigs`: unverified input buffered without bound; accepted-round entries never removed
- **File:** `protocol/gossip/src/node.rs:956-966, 833-841, 800-803`
- **Confidence:** certain

Sigs are buffered before any verification, with no cap or dedup, and drained only for
the exact round currently being produced. Once a round's accumulator is removed on
acceptance, later inbound sigs for that round land in a queue that can never flush —
steady-state gossip grows the map indefinitely even with honest peers. Correctness is
preserved (flushed sigs are verified before counting); this is resource exhaustion.

**Fix:** verify at ingest against `registry_at_round(sig.round)` + signing-bytes
commitment, cap per-round queues, drop rounds ≤ watermark, dedup by signer.

### M-3. Secret files created world-readable before chmod
- **File:** `node/src/bin/jkaind.rs:204-215, 998-1010`
- **Confidence:** certain

`fs::write(&secret_path, secret)` creates the consensus/TLS seed at umask perms
(typically 0644); `set_mode(0o600)` runs after bytes hit disk. A window exists in which
any local user can read the signing seed; if the chmod fails the process bails but
leaves the secret behind. RUNBOOK.md:80 promises `chmod 600` from `init`.

**Fix:** create via `OpenOptions::mode(0o600)` before writing, or write-temp → chmod →
rename.

### M-4. Swallowed KV storage error desynchronizes partition from Merkle tree → restart brick
- **Files:** `executor/state/src/state.rs:78-93`, interacting with
  `state_db.rs:76-80` + `restart.rs:47-64,208-213`
- **Confidence:** possible (requires a fjall write failure)

A failed `kv.insert` is logged and execution continues while the tree still updates:
partition bytes and `root()` disagree. Checkpoint production signs `state_hash = root()`
but `accept_checkpoint` persists the snapshot as partition bytes — the durable snapshot
rebuilds to a different root than the signed one, and on restart `verify_persisted`
refuses to start. The README claim that a dropped write is healed by the next snapshot
is false for the affected round.

**Fix:** propagate KV failures as fatal for the round, or validate (bytes ↔ root) before
signing/persisting.

### M-5. Mirror verifies files only in isolation — no seed anchor, no cross-file continuity
- **Files:** `mirror-node/internal/stream/verify.go:30-54, 60-94`,
  `mirror-node/internal/ingest/ingest.go:63-88`; Rust reference
  `protocol/stream/src/verify.rs:125-135`
- **Confidence:** certain

Each file's running hash is recomputed from its own claimed start forward; nothing checks
that the first file starts at the all-zero `CHAIN_SEED` or that `end[i] == start[i+1]`.
Deleting/reordering early files or splicing a forked mid-chain stream passes every check.
README advertises cross-file continuity as implemented; it exists nowhere in the Go tree.

**Fix:** track per-stream last-end hash across polls and apply `check_chain_link`
semantics (first file must start at seed).

### M-6. Missing signature file accepted permanently; transient-state reasoning inverted
- **Files:** `mirror-node/internal/ingest/ingest.go:111-124`, gates at
  `verify.go:49,89`; writer invariant `protocol/stream/src/signature.rs:17-19`,
  write order `event.rs:218-219`, `record.rs:209-210`
- **Confidence:** certain

`loadSig` returns `(nil, nil)` on ErrNotExist and verification is skipped forever — the
file is ingested immediately and never re-checked if the sig appears later. The comment
calls this "transient", but the Rust writer emits the sig *before* the stream file, so a
stream file without its companion sig indicates deletion or tampering, not a race (the
genuinely transient state is an orphaned sig with no file).

**Fix:** treat a sig-less stream file as a violation, or defer ingestion until the sig
arrives and verify before storing.

### M-7. `member init` overwrites existing secrets with no guard
- **File:** `node/src/bin/jkaind.rs:998-1000`
- **Confidence:** certain

Plain `init` refuses to clobber `secret-<id>.bin` without `--force` (`jkaind.rs:196-201`);
`member init` writes unconditionally. Re-running provisioning regenerates keys that no
longer match an already-submitted/ordered `add-member` op, silently stranding the member.

**Fix:** require `--force` to overwrite, matching `init`.

---

## Low

### L-1. `prune_before_round` can erase a stalled creator's frontier → false fork flagging
- **File:** `protocol/consensus/src/hashgraph.rs:867-875`
- **Confidence:** possible (requires a member stalling across a prune boundary)

Pruning the tip removes the creator's `latest_by_creator` entry entirely if no live
descendant anchors it. When the creator resumes, `run_sync` computes
`self_parent = None` and mints a fresh "genesis" event whose seq collides with other
nodes' `by_creator_seq`, flagging an innocent creator as a forker permanently (slow
observer-relative ordering path, duplicate famous witnesses excluded). Latent because
reconnect machinery usually rescues far-behind nodes first.

**Fix:** on prune of the tip, repoint `latest_by_creator` to the highest surviving
ancestor instead of removing the entry.

### L-2. `set_round_received` overwrites finalized ordering despite docstring claiming no-op
- **File:** `protocol/storage/src/event_log.rs:127-142`
- **Confidence:** certain

Docstring says no-op "or its ordering is already recorded"; the code only ignores equal
values and silently overwrites different ones. `round_received` is consensus-final;
overwriting can mask ordering bugs.

**Fix:** no-op whenever `stored.round_received.is_some()`.

### L-3. Delta computation assumes requester and responder rosters match
- **File:** `protocol/gossip/src/frontier.rs:47-66`
- **Confidence:** possible (transient window; self-heals via reconnect)

`delta_events` iterates only members present in the requester's `known` map; roster skew
across a membership activation means the new member's events are never included while
`other_parent` still references the peer's head → `MissingParent` → full checkpoint
reconnect churn for a routine transition race.

### L-4. Truncating `as u32` length prefixes in canonical encoders
- **Files:** `protocol/crypto/src/canonical_impls.rs:52,59`;
  `protocol/consensus/src/reconnect.rs:77,82`
- **Confidence:** certain about the cast; theoretical impact

Payload/tx-count > 2³²−1 wraps the length prefix; encodings sign/hash fine but cannot
round-trip. Fail-closed today (decoders reject trailing bytes) but should use
`u32::try_from(...)` guards.

### L-5. Ed25519 verification strictness inconsistent across verifiers
- **Files:** `protocol/crypto/src/signable_impls.rs:38-43` (`verify`) vs
  `protocol/stream/src/signature.rs:182`, `stream/src/verify.rs:263` (`verify_strict`) vs
  `mirror-node/internal/stream/verify.go:171` (Go stdlib lenient `Verify`)
- **Confidence:** certain that divergence exists; rare occurrence

Not exploitable today (dalek 2.2 plain `verify` enforces canonical `s`), but
"this file verifies" becomes implementation-dependent on malleable-but-valid encodings.

**Fix:** use `verify_strict` uniformly; document or harden the Go side equivalently.

### L-6. Mirror quorum denominator counts duplicate roster entries
- **File:** `mirror-node/internal/stream/verify.go:261` vs `216-224`
- **Confidence:** certain; low impact

Raw entry count vs canonical dedup makes quorum harder only — fails closed. Becomes
moot once duplicates are rejected (H-1).

### L-7. `srv.Shutdown(context.Background())` can hang shutdown indefinitely
- **File:** `mirror-node/cmd/mirrord/main.go:95`

No deadline; one stuck client connection blocks process exit.

### L-8. Writer startup reads and validates the entire stream directory into memory
- **Files:** `protocol/stream/src/event.rs:240-249`, `stream/src/record.rs:243-249`

Resume state scans every historical file fully; open time/memory is O(total stream
size) and one malformed legacy file blocks writer startup permanently. Reading only the
highest-index candidate's tail would suffice.

### L-9. Unbounded queues (documented tradeoffs, DoS-shaped)
- **Files:** `protocol/stream/src/event.rs:95`, `record.rs:88` (unbounded mpsc sinks);
  `node/src/control.rs:143-147` (spawn per connection), `280-289` (hex payload of
  unlimited size); `protocol/gossip/src/node.rs:272-274` (`pending_transactions` capped
  only at drain time)

Mitigated by the local-socket trust model for control; flagged for completeness.

### L-10. Misc CLI/config robustness
- `--gossip-port 0` accepted although the error text says ports must be 1-65535
  (`jkaind.rs:1160-1162`); `--sync-interval 0` yields a zero-sleep sync loop hammering
  peers (`node.rs:398`). Both behaviors pinned by negative tests
  (`cli_negative.rs:98-144`) — documented-but-risky rather than accidental.
- `StateDb::watermark` silently maps a wrong-width stored value to `0`
  (`state_db.rs:149-154`) instead of surfacing corruption.
- `DidId` parse/display round-trip breaks for aliases containing `:`; no construction-
  time validation excludes it (`did.rs:79-89,112-116`).
- `DidId::decode` maps non-UTF8 network/alias to `ExecutorError::Truncated` — valid but
  misleading diagnostics (`did.rs:105-106`).

### L-11. Mirror HTTP API serves ad-hoc JSON, not protobuf (wire-format policy)
- **File:** `mirror-node/internal/api/server.go:27-73`

AGENTS.md requires protobuf for everything speaking to external consumers (a mirror
node is named explicitly). The stream files comply; the HTTP surface hand-rolls JSON
and no confirmed scope decision covers the exemption.

---

## Verified clean during audit

For future reference, the following were reviewed and found correct:
clippy workspace-wide (clean); `primitives` crate; Merkle tree bit-ordering/proofs;
config parsing/hex strictness; fame/election math incl. coin rounds and CAS clamp;
ancestry fast/slow fork paths; TLS pinning/SPKI derivation; restart/replay idempotency;
proto↔Go field parity for all 11 messages; running-hash domain bytes and item-hash
byte equality across Rust/Go; canonical roster/checkpoint signing-byte layouts;
cluster-init secrets git-ignored.
