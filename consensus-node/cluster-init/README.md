# cluster-init

Example genesis material for local deploys.

`jkaind init` generates a fresh `cluster.toml` plus one `secret-<id>.bin` per
member:

```bash
cargo run --bin jkaind -- init \
  --member 1:127.0.0.1:7000:127.0.0.1:7001 \
  --member 2:127.0.0.1:7002:127.0.0.1:7003 \
  --out ./cluster
```

The files checked in here (`cluster.toml`, `secret-1.bin`, `secret-2.bin`) are
an example stub, not production secrets. They let `cargo test` and local
two-node runs start without running `init` first. Do not reuse them in
production, regenerate with `jkaind init` for any real cluster.

Generated outputs are gitignored via `cluster-init/.gitignore` when present
(`secret-*.bin`, `cluster.toml` patterns), so a local `init --out
cluster-init` does not accidentally commit new secrets.
