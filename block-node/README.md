# block-node

Dumb HTTP file store for JKaIN stream artifacts (`.esf`, `.esf_sig`, `.rsf`, `checkpoint-<round>.ckpt`). It stores opaque bytes and serves them back unchanged — **no verification, no checksum, no signature checks inside this service** (verification lives downstream in `mirror-node` per plan decision D6).

## Role

- Accepts pushes from `block-relay` (one instance per host).
- Serves files to `mirror-node` remote ingestion (todo 13).
- Plain `net/http` + `os` only (stdlib). No auth, no TLS, no cloud dependencies.

## Configuration (env-only)

| Variable | Required | Example | Description |
|---|---|---|---|
| `BLOCK_NODE_DATA_DIR` | yes | `/data/blocks` | Directory where files are stored. Created if missing. |
| `BLOCK_NODE_LISTEN_ADDR` | yes | `127.0.0.1:8080` | TCP address to listen on (`host:port`). |

Both must be set; the process exits on startup if either is missing.

## API

| Method | Path | Description |
|---|---|---|
| `PUT` | `/v1/blocks/{name}` | Store file (idempotent). If `{name}` already exists, returns `200` without rewriting. Otherwise writes atomically (temp file + rename). |
| `GET` | `/v1/blocks/{name}` | Fetch file bytes (`200`+`Content-Length`+`application/octet-stream`, or `404` if absent). |
| `HEAD` | `/v1/blocks/{name}` | Same as GET but headers only (`200`+`Content-Length` if present, `404` if absent). |
| `GET` | `/v1/blocks` | List stored names, lexicographically sorted, one per line (`text/plain`). |

Validation (`validName`):

- Rejects any name containing `/`, `\`, or `..` (including percent-encoded forms like `..%2Fescape`).
- Rejected names return `400`.
- Unknown paths return `404`; known routes with wrong method return `405`.

List format: newline-separated names, sorted lexicographically. Example body:

```
a.esf
checkpoint-10.ckpt
zebra.rsf
```

## Curl examples

Assume `BLOCK_NODE_DATA_DIR=/tmp/blocks` and `BLOCK_NODE_LISTEN_ADDR=127.0.0.1:8080`:

```bash
# start
BLOCK_NODE_DATA_DIR=/tmp/blocks BLOCK_NODE_LISTEN_ADDR=127.0.0.1:8080 go run .

# PUT (idempotent)
curl -X PUT --data-binary @./checkpoint-42.ckpt http://127.0.0.1:8080/v1/blocks/checkpoint-42.ckpt -i

# GET roundtrip
curl http://127.0.0.1:8080/v1/blocks/checkpoint-42.ckpt -o /tmp/out.ckpt
diff ./checkpoint-42.ckpt /tmp/out.ckpt && echo ok

# HEAD (check presence + size)
curl -I http://127.0.0.1:8080/v1/blocks/checkpoint-42.ckpt
# HEAD absent
curl -I http://127.0.0.1:8080/v1/blocks/missing.ckpt

# List (sorted)
curl http://127.0.0.1:8080/v1/blocks

# Traversal rejected
curl -i http://127.0.0.1:8080/v1/blocks/..%2Fescape
# -> 400
```

Atomicity: PUT writes to a temp file in the data dir (`os.CreateTemp`) then `os.Rename`, so concurrent GET/HEAD readers never observe torn content.

## Reverse-proxy note

This service intentionally ships **plain HTTP only** (no TLS, no auth). TLS termination and authentication are expected to be provided by an external reverse proxy (e.g. nginx, Caddy, Envoy) in front of `block-node`. Do not expose it directly to untrusted networks without such a proxy.

## Build / test

```bash
cd block-node
gofmt -l .          # must be empty
go vet ./...
go test ./...
```

Structure for testability: `newHandler(dataDir string) http.Handler` builds the mux so tests inject `t.TempDir()` and drive it with `net/http/httptest`.
