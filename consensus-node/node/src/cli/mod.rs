//! Terminal-facing CLI for the `jkaind` daemon, one module per subcommand
//! family.
//!
//! ```text
//! jkaind init --member <id>:<gossip-addr>[:<reconnect-addr>] [--member ...] \
//!             --out <dir> [--force]
//! jkaind run --cluster <cluster.toml> --node-id <id> --secret <secret-<id>.bin> \
//!            [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>]
//!            [--control-socket <path>] [--sync-interval <ms>] [--sync-timeout <ms>]
//!            [--fanout <auto|1..N>] [--dedup <true|false>] [--quic <true|false>]
//!
//! jkaind status  [--socket <path>]
//! jkaind tx put    --key <k> --value <v>  [--socket <path>]
//! jkaind tx delete --key <k>              [--socket <path>]
//! jkaind add-member --node-id <id> --gossip <ip:port> [--reconnect <ip:port>] \
//!                   --key <hex> --bls-key <96 hex> (--bls-secret <path> | --pop <192 hex>) [--socket <path>]
//! jkaind member init --node-id <id> --gossip <ip:port> --reconnect <ip:port> \
//!                    --cluster <genesis cluster.toml> --out <dir> [--socket <path>]
//! ```
//!
//! `init` generates per-node secrets (64 bytes each: consensus signing seed ‖
//! TLS seed), derives each member's verifying key and TLS SPKI fingerprint
//! from them, and writes the shared `cluster.toml` plus the secret files.
//! `run` loads the config, restores from the last persisted checkpoint if one
//! exists, binds the gossip/reconnect ports plus a Unix control socket, and
//! runs until SIGINT/SIGTERM.
//!
//! The control subcommands (`status`, `tx`, `add-member`) talk to a running
//! node over its Unix socket, so transactions — including `MembershipOp::Add`
//! — can be submitted from the terminal without a restart. `member init`
//! provisions a brand-new node's secret and local `cluster.toml` (the genesis
//! `cluster.toml` itself is never rewritten; it stays the genesis snapshot).

mod args;
mod client;
mod deploy;
mod init;
mod keys;
mod member;
mod run;

use anyhow::{
    Result,
    bail,
};

/// Entry point for the `jkaind` binary: dispatches one invocation's arguments.
pub async fn run(args: Vec<String>) -> Result<()> {
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    match args[0].as_str() {
        "--version" | "-V" => {
            println!("jkaind {} ({})", env!("CARGO_PKG_VERSION"), env!("JKAIN_GIT_HASH"));
            Ok(())
        }
        "--help" | "-h" => {
            print_usage();
            Ok(())
        }
        "init" => init::init(&args[1..]),
        "run" => run::run(&args[1..]).await,
        "status" => client::status_cmd(&args[1..]).await,
        "tx" => client::tx_cmd(&args[1..]).await,
        "add-member" => client::add_member(&args[1..]).await,
        "member" => member::member_cmd(&args[1..]).await,
        "deploy" => deploy::deploy_cmd(&args[1..]),
        "keygen" => deploy::keygen(&args[1..]),
        other => bail!("unknown subcommand '{other}'"),
    }
}

fn print_usage() {
    println!(
        "jkaind {} ({}) — JKain node daemon\n\
         \n\
         Usage:\n\
         \x20 jkaind init --member <id>:<gossip-addr>[:<reconnect-addr>] [--member ...] \\\n\
         \x20            --out <dir> [--force]\n\
         \x20            [--i-understand-this-rotates-keys-and-breaks-existing-data]\n\
         \n\
         \x20   Key rotation is a membership change, not an init operation: --force writes\n\
         \x20   secrets whose keys no longer match any persisted checkpoint roster, silently\n\
         \x20   stalling every node that restores one. Refused when checkpoints are detected\n\
         \x20   locally; otherwise warn. Always wipe data/ on every node after regenerating.\n\
         \n\
         \x20 jkaind run  --cluster <cluster.toml> --node-id <id> --secret <secret-<id>.bin> \\\n\
         \x20            [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>] \\\n\
         \x20            [--control-socket <path>] [--sync-interval <ms>] [--sync-timeout <ms>] \\\n\
         \x20            [--fanout <auto|1..N>] [--dedup <true|false>] [--quic <true|false>] \\\n\
         \x20            [--log-level <trace|debug|info|warn|error>] [--log-file <path>| -]\n\
         \n\
         Control (talk to a running node over its Unix socket):\n\
         \x20 jkaind status  [--socket <path>]\n\
         \x20 jkaind tx put    --key <k> --value <v> [--socket <path>]\n\
         \x20 jkaind tx delete --key <k>             [--socket <path>]\n\
         \x20 jkaind add-member --node-id <id> --gossip <ip:port> \\\n\
         \x20                  [--reconnect <ip:port>] --key <hex> \\\n\
         \x20                  --bls-key <96 hex> (--bls-secret <path> | --pop <192 hex>) \\\n\
         \x20                  [--socket <path>]\n\
         \n\
         Provision a new member (never touches the genesis cluster.toml):\n\
         \x20 jkaind member init --node-id <id> --gossip <ip:port> --reconnect <ip:port> \\\n\
         \x20                    --cluster <genesis cluster.toml> --out <dir> [--socket <path>]\n\
         \n\
         Deploy a genesis cluster over SSH (secrets are generated on each node and\n\
         never leave it; only public keys travel):\n\
         \x20 jkaind deploy genesis --member <id>=<[user@]host>[=<advertise-ip>] \\\n\
         \x20                      [--member ...] [--binary <path>] [--gossip-port <p>] \\\n\
         \x20                      [--reconnect-port <p>] [--config-dir </etc/jkaind>] \\\n\
         \x20                      [--data-dir </var/lib/jkaind>] [--out <dir>] [--ufw] [--force]\n\
         \x20 jkaind keygen --node-id <id> [--out </etc/jkaind>] [--force]\n\
         \n\
         Examples:\n\
         \x20 jkaind init --member 1:203.0.113.5:7000:203.0.113.5:7001 \\\n\
         \x20             --member 2:203.0.113.6:7000:203.0.113.6:7001 --out ./cluster\n\
         \x20 jkaind run --cluster ./cluster/cluster.toml --node-id 1 \\\n\
         \x20            --secret ./cluster/secret-1.bin --data ./data\n\
         \x20 jkaind deploy genesis --member 1=root@203.0.113.5 --member 2=root@203.0.113.6 \\\n\
         \x20                      --binary ./target/release/jkaind --ufw\n\
         \x20 jkaind status\n\
         \x20 jkaind tx put --key balance --value 100\n\
         \x20 jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 \\\n\
         \x20                 --reconnect 203.0.113.7:7001 --key <hex-from-member-init> \\\n\
         \x20                 --bls-key <bls-hex> --bls-secret ./cluster/secret-3.bls.bin",
        env!("CARGO_PKG_VERSION"),
        env!("JKAIN_GIT_HASH"),
    );
}
