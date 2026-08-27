# proto

Shared protobuf schemas for the JKaIN monorepo. The single shared schema lives
at the repo root `proto/jkain_stream.proto` — no vendored copies.

## Contents

- `jkain_stream.proto` — mirror stream files emitted by `consensus-node` into
  `<data>/streams/` (`consensus-node/protocol/stream`). Two file types, both
  chained by the §5 running hash:
  - `.esf` event stream files, accompanied by `.esf_sig` Ed25519 signature
    files (file + metadata signatures).
  - `.rsf` record stream files (one per decided round), **with no `.rsf_sig`**.
    Since `1313db5` / PLAN-1, record authenticity is via content binding:
    `records_root` + BLS aggregate checkpoint over the 136-byte
    `round||records_root||state_hash||roster_hash||prev_checkpoint_hash`.
    Each `.rsf` is accompanied by a `.rsf_proofs` sidecar carrying per-item
    Merkle inclusion proofs (see `RecordsProofFile`).

  See `consensus-node/protocol/stream/README.md` for the full design.

## Wire format and versions

- **`STREAM_VERSION` 3** — stamped inside every `EventStreamFile` /
  `RecordStreamFile` and `RecordsProofFile` (see `protocol/stream/src/lib.rs`).
  Bump 2 → 3 was for PLAN-2: `prev_checkpoint_hash` chaining of checkpoints
  (history splice resistance), Merkle `records_root` (padded power-of-two,
  Hiero domain-separated prefixes `0x00`/`0x01`/`0x02`), after-image
  `state_diffs` in `RecordStreamFile`, and the `.rsf_proofs` sidecar.
- **Backward compat** — new fields are `optional`/`repeated` and additive;
  readers reject only an unknown `version` or malformed trailing bytes.
  The proto package is `jkain.stream`.

## Usage

The schema is compiled by `consensus-node/protocol/stream/build.rs` (prost) via:

```
manifest_dir.join("../../../proto")  // consensus-node/protocol/stream -> repo root/proto
```

The Go mirror compiles the same file into `mirror-node/internal/stream/pb`
via `make proto` (the `go_package` is supplied with a protoc `M` flag,
keeping the root schema language-neutral). Future crates (SDKs, etc.) should
compile the same file rather than vendoring a copy.

Any change is a wire-format break — update `STREAM_VERSION` in
`protocol/stream/src/lib.rs`, keep `optional` fields for backward compat, and
confirm the protobuf scope with the user per `AGENTS.md` Wire Formats.

## Adding a new schema

Add `your_service.proto` here, compile it from the consuming crate's `build.rs`
pointing at `../../../proto` (or the appropriate relative path from that crate),
and document its role here and in that crate's README.
