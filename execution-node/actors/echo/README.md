# echo actor

Sample guest actor used by the `actor-host` integration tests. It exports the
`jkain:actor@0.0.1/handler.handle-request` function and echoes the request
bytes back as the reply.

## Build

From this directory:

```bash
cargo build --release --target wasm32-wasip2
```

The artifact is `target/wasm32-wasip2/release/echo_actor.wasm`.
