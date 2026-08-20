# proto

Shared protobuf schemas for the JKaIN monorepo.

## Contents

- `jkain_stream.proto` — mirror stream files (`.esf` / `.rsf`) emitted by `consensus-node` into `<data>/streams/` (`consensus-node/protocol/stream`). Two file types, both chained by a running hash and accompanied by `.esf_sig` / `.rsf_sig` Ed25519 signature files. See `consensus-node/protocol/stream/README.md` for the full design.

## Usage

The schema is compiled by `consensus-node/protocol/stream/build.rs` (prost) via:

```
manifest_dir.join("../../../proto")  // consensus-node/protocol/stream -> repo root/proto
```

Future crates (mirror node, SDKs) should compile the same file rather than vendoring a copy. Any change is a wire-format break — update `STREAM_VERSION` in `protocol/stream/src/lib.rs`, keep `optional` fields for backward compat, and confirm the protobuf scope with the user per `AGENTS.md` Wire Formats.

## Adding a new schema

Add `your_service.proto` here, compile it from the consuming crate's `build.rs` pointing at `../../../proto` (or the appropriate relative path from that crate), and document its role here and in that crate's README.
