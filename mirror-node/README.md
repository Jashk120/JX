# mirror-node

Go mirror node for JKaIN. It tails the consensus node's **mirror stream files**
(`.esf` / `.rsf` + `.sig`) emitted into `<data>/streams/` and exposes a
read-only HTTP API over the verified history.

Protobuf schema: [`../proto/jkain_stream.proto`](../proto/jkain_stream.proto)
— the single shared schema, compiled directly from the repo root (no vendored
copy). The Go code is generated into `internal/stream/pb` via `make proto`
(the `go_package` is supplied with a protoc `M` flag, keeping the root schema
language-neutral).

## Layout

```
mirror-node/
  go.mod
  internal/
    config/     env + flags → Config
    stream/     running hash, file naming, readers, verifier, pb/
    store/      Store interface + MemStore (in-memory) + PGStore (PostgreSQL)
    ingest/     polls streams dir, verifies, stores
    api/        HTTP handlers (/health, /api/v1/*)
  cmd/mirrord/  binary entrypoint
```

## Build

```bash
cd mirror-node
go build ./...
go vet ./...
go test ./...          # stream hash tests, etc.

# regenerate protobuf (requires protoc + protoc-gen-go)
make proto

# run locally against a consensus data dir
go run ./cmd/mirrord --streams ../consensus-node/data/streams --addr :8080
# or via env
MIRROR_STREAMS_DIR=./data/streams MIRROR_API_ADDR=:8080 go run ./cmd/mirrord

# .env file (hand-rolled dotenv, stdlib only): copy .env.example to .env
cp .env.example .env
# real environment overrides .env, which overrides defaults; missing .env is not an error
go run ./cmd/mirrord
```

Flags override env: `--streams`, `--db`, `--addr`, `--pubkey`, `--trusted-roster-hash`, `--block-node-url`, `--version`.

## Configuration

All settings come from `internal/config` with precedence: real environment > `.env` (loaded from `./.env` at startup) > built-in defaults. `.env` is parsed with stdlib only: blank and `#` lines skipped, split on first `=`, trim spaces, strip matching single/double quotes.

| Env var | Flag | Description |
|---|---|---|
| `MIRROR_STREAMS_DIR` | `--streams` | Directory watched for `.esf`/`.rsf` files (local mode) |
| `MIRROR_DB_PATH` | `--db` | Mirror local state: any non-`postgres://` value keeps the in-memory store; a `postgres://…` DSN enables the PostgreSQL backend |
| `MIRROR_API_ADDR` | `--addr` | HTTP API listen address |
| `MIRROR_LOG_LEVEL` | — | `debug`, `info`, `warn`, `error` |
| `MIRRORD_PUBKEY` / `MIRROR_PUBKEY` | `--pubkey` | Ed25519 verifying key, 64 hex chars (required) |
| `MIRRORD_TRUSTED_ROSTER_HASH` / `MIRROR_TRUSTED_ROSTER_HASH` | `--trusted-roster-hash` | 32-byte roster hash anchor, 64 hex chars (required) |
| `MIRROR_BLOCK_NODE_URL` | `--block-node-url` | Remote block-node base URL; when set the mirror polls the block node instead of the local directory |

See `.env.example` for a templated file.

## Remote block-node mode

When `MIRROR_BLOCK_NODE_URL` is set (or `--block-node-url` is passed), the ingester polls the remote block-node HTTP service instead of scanning `MIRROR_STREAMS_DIR`.

- `GET /v1/blocks` lists files (newline-separated names; whitespace trimmed, empties dropped).
- `GET /v1/blocks/{name}` fetches a file; name validation rejects empty, `/`, or `..`; `404` maps to `ErrNotFound`.
- Each poll filters to `{.esf,.rsf,.esf_sig,.rsf_sig}`, sorts by numeric index ascending, and applies the same skip/dedupe semantics as the local scan (per-round/per-index `seen` + `in-flight` guards, chain continuity, `VerifyRecordFile`/`VerifyEventFile`, `PutRecord`/`PutEvents`). Missing companion sig defers ingestion (transient); per-file verify/store errors are logged and skipped; listing failure returns an error like the local `ReadDir` path.
- Default HTTP client timeout is 10s and context is honored.

When `MIRROR_BLOCK_NODE_URL` is empty the legacy local-directory behavior is 100% unchanged.

## API

| Endpoint | Description |
|---|---|
| `GET /health` | `{status: ok}` |
| `GET /api/v1/rounds/latest` | `{latestRound: uint64}` |
| `GET /api/v1/records` | `[{round, items}]` |
| `GET /api/v1/events` | `[{creator, seq}]` |

## Verification

Each stream file is checked before ingestion:

- **Running hash** (`SHA256(DOMAIN||"item"||item)` → `SHA256(DOMAIN||"chain"||prev||item)`,
  seed `[0;32]`) – continuity across items and `end == next.start`.
- **Signature file** (`.esf_sig`/`.rsf_sig`) – `file_signature` over `SHA256(file)`
  and `metadata_signature` over header hash, both Ed25519.
- **Checkpoint quorum** (`valid*3 > total*2` over roster snapshot) for record files.

Matches `consensus-node/protocol/stream/src/verify.rs`.

## PostgreSQL persistence

When `MIRROR_DB_PATH` / `--db` is a `postgres://` (or `postgresql://`) DSN,
mirrord stores everything in PostgreSQL instead of memory:

```bash
MIRROR_DB_PATH="postgres://mirror:mirror@localhost:5432/mirror?sslmode=disable" \
  go run ./cmd/mirrord --streams ../consensus-node/data/streams
```

- The schema (`internal/store/schema.sql`) is embedded in the binary and
  applied idempotently on every startup — no migration tool needed.
- Deduplication lives in the database: records are unique per `round`,
  events per `(creator, seq)`; re-ingesting a file is a no-op, so restarts
  replay safely.
- Writes are transactional: a record file's items and checkpoint children
  commit atomically with the file row.
- Reads reconstruct full protobuf messages; `ListEvents` preserves arrival
  order via `ingested_seq`.

Store tests run against a real database only when `MIRROR_TEST_PG_DSN` is
set, so plain `go test ./...` needs no database:

```bash
docker run --rm -d -p 5432:5432 -e POSTGRES_PASSWORD=dev postgres:16
MIRROR_TEST_PG_DSN="postgres://postgres:dev@localhost:5432/postgres?sslmode=disable" \
  go test ./internal/store/
```

## Adding another persistent store

Implement `store.Store` (see `internal/store/store.go:Store`) and select it
in `cmd/mirrord/main.go` at the backend-choice call site.

`Store` implementations must be idempotent: `PutRecord` keys on record round,
`PutEvents` on each event's `(creator, seq)`; re-ingesting stored data must be
a no-op. The ingester additionally skips files it has already verified and
stored, so a backend only ever sees each stream file once per process
lifetime.
