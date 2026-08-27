# PLAN-2 Step 7 Golden Vectors (mirror-node copy)

This directory holds a copy of the shared golden fixtures also present at
`consensus-node/protocol/stream/tests/testdata/plan2_golden.json`.

## File

- `plan2_golden.json` — identical to the consensus-node copy. Do not edit
  independently; edit the source and copy.

See `consensus-node/protocol/stream/tests/testdata/README.md` for generation
and consumption docs.

## Quick verification

```bash
# Rust side
cargo test -p stream --test golden -- --nocapture

# Go side
CGO_ENABLED=1 go test ./internal/stream -run Golden -v
CGO_ENABLED=1 go test ./...
```

Vectors prove:

- `ComputeRecordsRoot` (Go) == `compute_records_root` (Rust): empty `SHA256(0x00)`,
  leaf `SHA256(0x00||event_hash||tx_index_be||len_be||payload)`,
  internal `SHA256(0x02||l||r)`, singleton `SHA256(0x01||c)`, padded power-of-two.
- `CheckpointSigningBytes` (Go) == `signing_bytes` (Rust): 136B `round_be8||records_root||state_hash||roster_hash||prev_checkpoint_hash`.
- `StateDiff` sorted LWW + tombstone (`value` absent) protobuf encoding matches
  (`prost` vs Go `proto.MarshalOptions{Deterministic:true}`).

All fixtures are deterministic, no randomness, <100KB textual hex JSON.
