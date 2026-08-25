# ingest/testdata

Golden fixtures for BLS-verified remote ingestion (PLAN-1 todo 13).

- `valid.ckpt` — protobuf `SignedCheckpoint` (48-byte G1 bls_keys, 96-byte G2 aggregate_sig, DST `JKAIN-CHECKPOINT-BLS-V1`, quorum 3-of-3, round 1, `records_root` binding over 3 `RecordItem`s).
- `valid.rsf` — `RecordStreamFile` version 2 containing the same 3 items + the identical checkpoint, with running-hash chaining from `ChainSeed`.

Both are generated via the BLS `blst` bindings with `compute_records_root` (`h_0 = SHA256("JKAIN-RECORDS-ROOT-V1"||u32BE(count))`, `h_i = SHA256(h_{i-1}||SHA256(event_hash||u32BE(tx_index)||u32BE(len(payload))||payload))`) — byte-exact with `consensus-node/protocol/consensus/src/checkpoint.rs`.

## Regenerate

```bash
cd mirror-node
go run ./internal/ingest/testdata/gen_fixtures.go   # CGO_ENABLED=1 where blst is required
ls -lh internal/ingest/testdata/
```

Or from Rust (fresh cluster):

```bash
cd consensus-node
cargo test -p consensus checkpoint -- --nocapture  # writes via stream/tests wiring
# then copy the emitted checkpoint-<round>.ckpt + round-<round>.rsf bytes
```

Do not hand-edit the binary fixtures; regenerate via the command above.
