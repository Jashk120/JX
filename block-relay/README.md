# block-relay

Dumb pusher that polls a local `streams/` directory and pushes new files to a `block-node` HTTP endpoint.

## Deployment

One instance per host. Point it at that host's block-node URL. The relay is stateless apart from an in-memory seen-set; remote HEAD checks handle restarts.

## Environment

| Variable | Required | Default | Description |
|---|---|---|---|
| `STREAMS_DIR` | yes | — | Local streams directory to poll |
| `BLOCK_NODE_URL` | yes | — | Base URL of block-node, e.g. `http://127.0.0.1:8080` |
| `STREAM_POLL_MS` | no | `500` | Poll interval in milliseconds |

## Run

```bash
STREAMS_DIR=/data/streams BLOCK_NODE_URL=http://127.0.0.1:8080 ./block-relay
# or with custom interval
STREAMS_DIR=/data/streams BLOCK_NODE_URL=http://127.0.0.1:8080 STREAM_POLL_MS=1000 ./block-relay
```

## Behavior

- Polls `STREAMS_DIR` every 500 ms (or `STREAM_POLL_MS`).
- Pushes regular files whose suffix is in `{.esf, .rsf, .esf_sig, .ckpt}`. `.rsf_sig` is not pushed.
- For each file: `HEAD /v1/blocks/<filename>` — if 200 skip; else `PUT` the bytes.
- In-memory seen-set dedupes within a process; HEAD covers fresh restarts.
- Unreachable block-node: logs and retries next tick, never crashes.
- Files still being written: read errors are logged and retried next poll.

## Verification

This relay does **no verification** — it is a dumb pusher. Signature and content-binding verification lives downstream in `mirror-node` (plan decision D6).
