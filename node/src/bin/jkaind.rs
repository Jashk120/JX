//! `jkaind` — the JKain node daemon.
//!
//! Two subcommands, no dependencies beyond the workspace:
//!
//! ```text
//! jkaind init --member <id>:<gossip-addr>:<reconnect-addr> [--member ...] \
//!             --out <dir> [--force]
//! jkaind run --cluster <cluster.toml> --node-id <id> --secret <secret-<id>.bin> \
//!            [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>]
//!            [--sync-interval <ms>] [--sync-timeout <ms>]
//! ```
//!
//! `init` generates per-node secrets (64 bytes each: consensus signing seed ‖
//! TLS seed), derives each member's verifying key and TLS SPKI fingerprint
//! from them, and writes the shared `cluster.toml` plus the secret files.
//! `run` loads the config, restores from the last persisted checkpoint if one
//! exists, binds both ports on 0.0.0.0, and runs until SIGINT/SIGTERM.

use std::path::{
    Path,
    PathBuf,
};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use anyhow::{
    Context,
    Result,
    bail,
};
use ed25519_dalek::SigningKey;
use gossip::{
    GossipNode,
    PeerInfo,
    TlsIdentity,
};
use node::config::{
    ClusterConfigFile,
    decode_hex,
};
use node::restart::latest_for_restart;
use node::storage::Storage;
use primitives::NodeId;
use rand::RngCore;
use rand::rngs::OsRng;
use tokio::net::TcpListener;

const SECRET_LEN: usize = 64;
const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }
    match args[0].as_str() {
        "init" => init(&args[1..]),
        "run" => run(&args[1..]).await,
        other => bail!("unknown subcommand '{other}'"),
    }
}

// --- init -------------------------------------------------------------------

fn init(args: &[String]) -> Result<()> {
    let mut members = Vec::new();
    let mut out_dir: Option<PathBuf> = None;
    let mut force = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--member" => {
                let value = next_value(args, &mut i, "--member")?;
                members.push(parse_member(&value)?);
            }
            "--out" => {
                let value = next_value(args, &mut i, "--out")?;
                out_dir = Some(PathBuf::from(value));
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!("init: unknown argument '{other}'"),
        }
    }
    if members.is_empty() {
        bail!("init: at least one --member is required");
    }
    let out_dir = out_dir.context("init: --out <dir> is required")?;
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;

    let mut member_files = Vec::new();
    for &(node_id, gossip_addr, reconnect_addr) in &members {
        let secret_path = out_dir.join(format!("secret-{node_id}.bin"));
        if secret_path.exists() && !force {
            bail!(
                "{} already exists; use --force to regenerate (refusing to overwrite secrets)",
                secret_path.display()
            );
        }
        let mut secret = [0u8; SECRET_LEN];
        OsRng.fill_bytes(&mut secret);
        std::fs::write(&secret_path, secret)
            .with_context(|| format!("writing {}", secret_path.display()))?;
        let mut secret_perms = std::fs::metadata(&secret_path)
            .with_context(|| format!("stat {}", secret_path.display()))?
            .permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            secret_perms.set_mode(0o600);
            std::fs::set_permissions(&secret_path, secret_perms)
                .with_context(|| format!("chmod {}", secret_path.display()))?;
        }
        let signing_key =
            SigningKey::from_bytes(&secret[..32].try_into().expect("32-byte consensus seed"));
        let identity =
            TlsIdentity::from_seed(secret[32..].try_into().expect("32-byte TLS seed"), node_id)
                .with_context(|| format!("building TLS identity for node {node_id}"))?;
        member_files.push(node::config::MemberFile::new(
            node_id,
            gossip_addr,
            reconnect_addr,
            &signing_key.verifying_key(),
            identity.spki_fingerprint(),
        ));
    }

    let config = ClusterConfigFile { members: member_files };
    let config_path = out_dir.join("cluster.toml");
    config.save(&config_path).with_context(|| format!("writing {}", config_path.display()))?;

    print_init_summary(&out_dir, &config_path, &members);
    Ok(())
}

fn print_init_summary(
    out_dir: &Path,
    config_path: &Path,
    members: &[(u64, std::net::SocketAddr, std::net::SocketAddr)],
) {
    println!("Wrote cluster config: {}", config_path.display());
    println!("Secret files (keep each one only on its own node):");
    for (node_id, _, _) in members {
        println!("  {}", out_dir.join(format!("secret-{node_id}.bin")).display());
    }
    println!();
    println!("Copy plan (two VPSes, node 1 = VPS A, node 2 = VPS B):");
    for (node_id, _, _) in members {
        let secret = out_dir.join(format!("secret-{node_id}.bin"));
        println!(
            "  scp {} user@vps{node_id}:jkaind/ && scp {} user@vps{node_id}:jkaind/",
            secret.display(),
            config_path.display()
        );
    }
}

/// Parses `<id>:<gossip-addr>:<reconnect-addr>`. The two addresses are split
/// at the `:` that leaves both halves valid `SocketAddr`s, so IPv6 bracket
/// literals are handled.
fn parse_member(input: &str) -> Result<(u64, std::net::SocketAddr, std::net::SocketAddr)> {
    let (id_part, addrs) = input.split_once(':').with_context(|| {
        format!("invalid --member '{input}': expected <id>:<gossip>:<reconnect>")
    })?;
    let node_id: u64 = id_part
        .parse()
        .with_context(|| format!("invalid node id '{id_part}' in --member '{input}'"))?;
    for (i, ch) in addrs.char_indices() {
        if ch != ':' {
            continue;
        }
        if let (Ok(gossip), Ok(reconnect)) = (addrs[..i].parse(), addrs[i + 1..].parse()) {
            return Ok((node_id, gossip, reconnect));
        }
    }
    bail!("invalid --member '{input}': could not split gossip and reconnect addresses")
}

// --- run --------------------------------------------------------------------

async fn run(args: &[String]) -> Result<()> {
    let mut cluster_path: Option<PathBuf> = None;
    let mut node_id: Option<u64> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut gossip_port: Option<u16> = None;
    let mut reconnect_port: Option<u16> = None;
    let mut data_dir = PathBuf::from("data");
    let mut sync_interval = DEFAULT_SYNC_INTERVAL;
    let mut sync_timeout = DEFAULT_SYNC_TIMEOUT;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cluster" => {
                let value = next_value(args, &mut i, "--cluster")?;
                cluster_path = Some(PathBuf::from(value));
            }
            "--node-id" => {
                let value = next_value(args, &mut i, "--node-id")?;
                node_id =
                    Some(value.parse().with_context(|| format!("invalid --node-id '{value}'"))?);
            }
            "--secret" => {
                let value = next_value(args, &mut i, "--secret")?;
                secret_path = Some(PathBuf::from(value));
            }
            "--gossip-port" => {
                let value = next_value(args, &mut i, "--gossip-port")?;
                gossip_port = Some(parse_port(&value, "--gossip-port")?);
            }
            "--reconnect-port" => {
                let value = next_value(args, &mut i, "--reconnect-port")?;
                reconnect_port = Some(parse_port(&value, "--reconnect-port")?);
            }
            "--data" => {
                let value = next_value(args, &mut i, "--data")?;
                data_dir = PathBuf::from(value);
            }
            "--sync-interval" => {
                let value = next_value(args, &mut i, "--sync-interval")?;
                sync_interval = Duration::from_millis(parse_ms(&value, "--sync-interval")?);
            }
            "--sync-timeout" => {
                let value = next_value(args, &mut i, "--sync-timeout")?;
                sync_timeout = Duration::from_millis(parse_ms(&value, "--sync-timeout")?);
            }
            other => bail!("run: unknown argument '{other}'"),
        }
    }
    let cluster_path = cluster_path.context("run: --cluster <path> is required")?;
    let node_id = node_id.context("run: --node-id <id> is required")?;
    let secret_path = secret_path.context("run: --secret <path> is required")?;

    let opts = RunOptions {
        cluster_path,
        node_id,
        secret_path,
        gossip_port,
        reconnect_port,
        data_dir,
        sync_interval,
        sync_timeout,
    };
    run_node(&opts).await
}

/// Fully-parsed `run` options (bundled so `run_node` stays under Clippy's
/// argument-count limit).
struct RunOptions {
    cluster_path: PathBuf,
    node_id: u64,
    secret_path: PathBuf,
    gossip_port: Option<u16>,
    reconnect_port: Option<u16>,
    data_dir: PathBuf,
    sync_interval: Duration,
    sync_timeout: Duration,
}

async fn run_node(opts: &RunOptions) -> Result<()> {
    let config = ClusterConfigFile::load(&opts.cluster_path)?;
    let member = config
        .member_for(opts.node_id)
        .with_context(|| format!("cluster config has no member with node-id {}", opts.node_id))?;

    let secret = std::fs::read(&opts.secret_path)
        .with_context(|| format!("reading secret {}", opts.secret_path.display()))?;
    if secret.len() != SECRET_LEN {
        bail!("{}: expected {SECRET_LEN} bytes, got {}", opts.secret_path.display(), secret.len());
    }
    let signing_key =
        SigningKey::from_bytes(&secret[..32].try_into().expect("32-byte consensus seed"));
    let identity =
        TlsIdentity::from_seed(secret[32..].try_into().expect("32-byte TLS seed"), opts.node_id)
            .with_context(|| format!("building TLS identity for node {}", opts.node_id))?;

    // Sanity: the secret must derive the same key and TLS pin the config
    // declares for this node.
    let expected_key = decode_hex(&member.verifying_key)
        .with_context(|| format!("member {}: invalid verifying_key hex", opts.node_id))?;
    if signing_key.verifying_key().to_bytes() != expected_key {
        bail!(
            "member {}: secret does not match configured verifying_key \
             (wrong secret file?)",
            opts.node_id
        );
    }
    let expected_fingerprint = decode_hex(&member.spki_fingerprint)
        .with_context(|| format!("member {}: invalid spki_fingerprint hex", opts.node_id))?;
    if identity.spki_fingerprint() != expected_fingerprint {
        bail!(
            "member {}: secret does not match configured TLS fingerprint \
             (wrong secret file?)",
            opts.node_id
        );
    }

    let gossip_port = opts.gossip_port.unwrap_or(member.gossip_addr.port());
    let reconnect_addr = member.reconnect_addr.with_context(|| {
        format!("member {} has no reconnect_addr in cluster config", opts.node_id)
    })?;
    let reconnect_port = opts.reconnect_port.unwrap_or(reconnect_addr.port());

    let cluster = config.to_cluster_config()?;
    let registry = cluster.registry();
    let peers: Vec<PeerInfo> = cluster.peers_for(NodeId::new(opts.node_id));
    let storage = Storage::new(&opts.data_dir)?;

    eprintln!(
        "[jkaind] node {}: gossip on 0.0.0.0:{gossip_port}, reconnect on 0.0.0.0:{reconnect_port}, data in {}",
        opts.node_id,
        opts.data_dir.display()
    );

    // Restart recovery: restore from the last persisted checkpoint if one
    // exists; the node then reconnects from a live peer for the event window.
    let node = match latest_for_restart(&storage, opts.node_id)? {
        Some(response) => {
            eprintln!(
                "[jkaind] restoring from persisted checkpoint at round {}",
                response.signed_checkpoint.payload.round
            );
            let node = GossipNode::from_checkpoint(
                NodeId::new(opts.node_id),
                signing_key,
                identity,
                peers,
                opts.sync_interval,
                opts.sync_timeout,
                response,
            )
            .await?;
            node.request_reconnect();
            node
        }
        None => {
            eprintln!("[jkaind] fresh start (no persisted checkpoint)");
            GossipNode::new(
                NodeId::new(opts.node_id),
                signing_key,
                registry,
                identity,
                peers,
                opts.sync_interval,
                opts.sync_timeout,
            )
        }
    };
    let node = Arc::new(node);

    node.set_checkpoint_sink(Arc::new(storage)).await;

    let gossip_listener = std::net::TcpListener::bind(("0.0.0.0", gossip_port))
        .with_context(|| format!("binding gossip port {gossip_port}"))?;
    gossip_listener
        .set_nonblocking(true)
        .with_context(|| "setting gossip listener nonblocking".to_string())?;
    let gossip_listener =
        TcpListener::from_std(gossip_listener).context("wrapping gossip listener")?;

    let reconnect_listener = std::net::TcpListener::bind(("0.0.0.0", reconnect_port))
        .with_context(|| format!("binding reconnect port {reconnect_port}"))?;
    reconnect_listener
        .set_nonblocking(true)
        .with_context(|| "setting reconnect listener nonblocking".to_string())?;
    let reconnect_listener =
        TcpListener::from_std(reconnect_listener).context("wrapping reconnect listener")?;

    eprintln!("[jkaind] node {}: listening, waiting for shutdown (SIGINT/SIGTERM)", opts.node_id);
    run_until_shutdown(node, gossip_listener, reconnect_listener).await
}

async fn run_until_shutdown(
    node: Arc<GossipNode>,
    gossip_listener: TcpListener,
    reconnect_listener: TcpListener,
) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    let signal_task = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal_stop.store(true, Ordering::Release);
    });

    let result =
        node.run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop).await;
    signal_task.abort();
    match result {
        Ok(()) => {
            eprintln!("[jkaind] shutdown requested; sync driver drained, exiting");
            Ok(())
        }
        Err(e) => Err(e).with_context(|| "node run failed"),
    }
}

async fn wait_for_shutdown_signal() {
    let ctrl_c = tokio::signal::ctrl_c();
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("installing SIGTERM handler");
        tokio::select! {
            _ = ctrl_c => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = ctrl_c.await;
    }
}

// --- arg helpers -------------------------------------------------------------

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    let value = args.get(*i).with_context(|| format!("{flag} requires a value"))?;
    *i += 1;
    Ok(value.clone())
}

fn parse_port(value: &str, flag: &str) -> Result<u16> {
    value.parse().with_context(|| format!("{flag} must be a port 1-65535, got '{value}'"))
}

fn parse_ms(value: &str, flag: &str) -> Result<u64> {
    value.parse().with_context(|| format!("{flag} must be milliseconds, got '{value}'"))
}

fn print_usage() {
    println!(
        "jkaind — JKain node daemon\n\
         \n\
         Usage:\n\
         \x20 jkaind init --member <id>:<gossip-addr>:<reconnect-addr> [--member ...] \\\n\
         \x20            --out <dir> [--force]\n\
         \x20 jkaind run  --cluster <cluster.toml> --node-id <id> --secret <secret-<id>.bin> \\\n\
         \x20            [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>] \\\n\
         \x20            [--sync-interval <ms>] [--sync-timeout <ms>]\n\
         \n\
         Examples:\n\
         \x20 jkaind init --member 1:203.0.113.5:7000:203.0.113.5:7001 \\\n\
         \x20             --member 2:203.0.113.6:7000:203.0.113.6:7001 --out ./cluster\n\
         \x20 jkaind run --cluster ./cluster/cluster.toml --node-id 1 \\\n\
         \x20            --secret ./cluster/secret-1.bin --data ./data"
    );
}
