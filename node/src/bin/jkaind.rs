//! `jkaind` — the JKain node daemon.
//!
//! ```text
//! jkaind init --member <id>:<gossip-addr>[:<reconnect-addr>] [--member ...] \
//!             --out <dir> [--force]
//! jkaind run --cluster <cluster.toml> --node-id <id> --secret <secret-<id>.bin> \
//!            [--gossip-port <port>] [--reconnect-port <port>] [--data <dir>]
//!            [--control-socket <path>] [--sync-interval <ms>] [--sync-timeout <ms>]
//!
//! jkaind status  [--socket <path>]
//! jkaind tx put    --key <k> --value <v>  [--socket <path>]
//! jkaind tx delete --key <k>              [--socket <path>]
//! jkaind add-member --node-id <id> --gossip <ip:port> [--reconnect <ip:port>] \
//!                   --key <hex> [--socket <path>]
//! jkaind member init --node-id <id> --gossip <ip:port> --reconnect <ip:port> \
//!                    --cluster <genesis cluster.toml> --out <dir>
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

use std::net::SocketAddr;
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
use crypto::MembershipOp;
use ed25519_dalek::{
    SigningKey,
    VerifyingKey,
};
use gossip::{
    GossipNode,
    PeerInfo,
    TlsIdentity,
};
use node::config::{
    ClusterConfigFile,
    MemberFile,
    decode_hex,
    encode_hex,
};
use node::control::{
    self,
    ControlRequest,
    StatusReport,
};
use node::restart::latest_for_restart_with_log;
use node::storage::Storage;
use primitives::NodeId;
use rand::RngCore;
use rand::rngs::OsRng;
use state::Op;
use storage::EventLog;
use tokio::net::{
    TcpListener,
    UnixListener,
};

const SECRET_LEN: usize = 64;
const SINGLE_SEED_LEN: usize = 32;
const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SOCKET: &str = "data/jkaind.sock";

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
        "status" => status_cmd(&args[1..]).await,
        "tx" => tx_cmd(&args[1..]).await,
        "add-member" => add_member(&args[1..]).await,
        "member" => member_cmd(&args[1..]),
        other => bail!("unknown subcommand '{other}'"),
    }
}

// --- init -------------------------------------------------------------------

fn init(args: &[String]) -> Result<()> {
    let mut members = Vec::new();
    let mut out_dir: Option<PathBuf> = None;
    let mut force = false;
    let mut i_understand_rotation = false;

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
            "--i-understand-this-rotates-keys-and-breaks-existing-data" => {
                i_understand_rotation = true;
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

    // Key rotation is a membership change, not an init operation: a
    // `--force` regeneration writes secrets whose keys no longer match any
    // persisted checkpoint roster, and every node that restores one would
    // silently stall consensus. Refuse unless the operator confirms, and even
    // then point out that checkpoints on the VPS data dirs (which `init`
    // cannot see) are invalidated too.
    if force {
        match checkpoint_hazard(&out_dir) {
            Some(hazard) if !i_understand_rotation => {
                bail!(
                    "refusing to regenerate cluster keys: persisted checkpoints found at {} — \
                     regenerated keys will not match the checkpoint roster and every node \
                     would silently stall consensus. Wipe `data/` on every node before \
                     restarting, or pass \
                     --i-understand-this-rotates-keys-and-breaks-existing-data to override.",
                    hazard.display()
                );
            }
            Some(hazard) => {
                eprintln!(
                    "WARNING: persisted checkpoints found at {} will be incompatible with the \
                     regenerated keys. Wipe `data/` on every node before restarting.",
                    hazard.display()
                );
            }
            None => {
                eprintln!(
                    "WARNING: regenerating cluster keys invalidates any persisted checkpoints \
                     on running nodes (none found on this machine, but check each VPS's data \
                     dir). Wipe `data/` on every node before restarting."
                );
            }
        }
    }

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

/// The first location holding persisted checkpoints that regenerated keys
/// would silently break, if any. `jkaind run` writes checkpoints under
/// `<data>/checkpoints/` (default `data/checkpoints/`); `init` checks the
/// output dir and the default data dir. VPS-side data dirs cannot be seen
/// from the machine running `init`, so a clean result is advisory only.
fn checkpoint_hazard(out_dir: &Path) -> Option<PathBuf> {
    let candidates = [
        out_dir.join("data").join("checkpoints"),
        out_dir.join("checkpoints"),
        PathBuf::from("data").join("checkpoints"),
    ];
    candidates.into_iter().find(|dir| {
        dir.is_dir()
            && std::fs::read_dir(dir).map(|mut entries| entries.next().is_some()).unwrap_or(false)
    })
}

fn print_init_summary(
    out_dir: &Path,
    config_path: &Path,
    members: &[(u64, std::net::SocketAddr, Option<std::net::SocketAddr>)],
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

/// Parses `<id>:<gossip-addr>[:<reconnect-addr>]`. The reconnect address is
/// optional: without it the member has no dedicated reconnect port (gossip
/// only — such a node can pull a checkpoint from a peer but cannot serve as a
/// reconnect source). The two-address form is split at the `:` that leaves
/// both halves valid `SocketAddr`s, so IPv6 bracket literals are handled.
fn parse_member(input: &str) -> Result<(u64, std::net::SocketAddr, Option<std::net::SocketAddr>)> {
    let (id_part, addrs) = input.split_once(':').with_context(|| {
        format!("invalid --member '{input}': expected <id>:<gossip>[:<reconnect>]")
    })?;
    let node_id: u64 = id_part
        .parse()
        .with_context(|| format!("invalid node id '{id_part}' in --member '{input}'"))?;
    // Single-address form: <id>:<gossip>.
    if let Ok(gossip) = addrs.parse() {
        return Ok((node_id, gossip, None));
    }
    // Two-address form: <id>:<gossip>:<reconnect>.
    for (i, ch) in addrs.char_indices() {
        if ch != ':' {
            continue;
        }
        if let (Ok(gossip), Ok(reconnect)) = (addrs[..i].parse(), addrs[i + 1..].parse()) {
            return Ok((node_id, gossip, Some(reconnect)));
        }
    }
    bail!("invalid --member '{input}': expected <id>:<gossip> or <id>:<gossip>:<reconnect>")
}

// --- run --------------------------------------------------------------------

async fn run(args: &[String]) -> Result<()> {
    let mut cluster_path: Option<PathBuf> = None;
    let mut node_id: Option<u64> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut gossip_port: Option<u16> = None;
    let mut reconnect_port: Option<u16> = None;
    let mut data_dir = PathBuf::from("data");
    let mut control_socket: Option<PathBuf> = None;
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
            "--control-socket" => {
                let value = next_value(args, &mut i, "--control-socket")?;
                control_socket = Some(PathBuf::from(value));
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
        control_socket,
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
    control_socket: Option<PathBuf>,
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
    // Two secret formats are accepted:
    // - 64 bytes (genesis, `jkaind init`): consensus signing seed ‖ TLS seed,
    //   two independent keys.
    // - 32 bytes (dynamic member, `jkaind member init`): a single seed used
    //   for BOTH consensus signing and TLS. This is what makes the runtime
    //   add path work — an existing node pins a new peer's TLS fingerprint by
    //   deriving it from the peer's consensus key (`add_peer_from_key`), so
    //   the new node's TLS identity MUST come from that same key.
    let (signing_key, identity) = match secret.len() {
        SECRET_LEN => {
            let signing_key =
                SigningKey::from_bytes(&secret[..32].try_into().expect("32-byte consensus seed"));
            let identity = TlsIdentity::from_seed(
                secret[32..].try_into().expect("32-byte TLS seed"),
                opts.node_id,
            )
            .with_context(|| format!("building TLS identity for node {}", opts.node_id))?;
            (signing_key, identity)
        }
        SINGLE_SEED_LEN => {
            let seed: [u8; SINGLE_SEED_LEN] = secret.try_into().expect("32-byte single seed");
            let signing_key = SigningKey::from_bytes(&seed);
            let identity = TlsIdentity::from_seed(seed, opts.node_id)
                .with_context(|| format!("building TLS identity for node {}", opts.node_id))?;
            (signing_key, identity)
        }
        len => bail!(
            "{}: expected {SINGLE_SEED_LEN} or {SECRET_LEN} bytes, got {len}",
            opts.secret_path.display()
        ),
    };

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
    // A member may have no dedicated reconnect port (gossip-only). Such a node
    // can still pull a checkpoint from a peer that serves reconnect, but
    // cannot serve one itself. `--reconnect-port` overrides the configured
    // port, or forces a reconnect listener for a gossip-only member.
    let reconnect_addr = member.reconnect_addr;
    let reconnect_port = match (opts.reconnect_port, reconnect_addr) {
        (Some(port), _) => Some(port),
        (None, Some(addr)) => Some(addr.port()),
        (None, None) => None,
    };

    let cluster = config.to_cluster_config()?;
    let registry = cluster.registry();
    let peers: Vec<PeerInfo> = cluster.peers_for(NodeId::new(opts.node_id));
    let storage = Storage::new(&opts.data_dir)?;
    let event_log = Arc::new(EventLog::open(&opts.data_dir)?);

    match reconnect_port {
        Some(port) => eprintln!(
            "[jkaind] node {}: gossip on 0.0.0.0:{gossip_port}, reconnect on 0.0.0.0:{port}, data in {}",
            opts.node_id,
            opts.data_dir.display()
        ),
        None => eprintln!(
            "[jkaind] node {}: gossip on 0.0.0.0:{gossip_port}, reconnect disabled (gossip-only member), data in {}",
            opts.node_id,
            opts.data_dir.display()
        ),
    }

    // Restart recovery: restore from the last persisted checkpoint if one
    // exists, replaying the retained graph from the local event log (Phase 8)
    // so the node recovers independently — no live peer needed. When the log
    // is empty (pre-event-log data, or a checkpoint without logged events),
    // fall back to reconnecting from a live peer for the event window.
    let node = match latest_for_restart_with_log(
        &storage,
        &event_log,
        opts.node_id,
        &signing_key.verifying_key(),
    )? {
        Some(response) => {
            let replay_has_events = !response.retained.is_empty();
            eprintln!(
                "[jkaind] restoring from persisted checkpoint at round {} ({} retained events \
                 replayed from the event log)",
                response.signed_checkpoint.payload.round,
                response.retained.len()
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
            if !replay_has_events {
                node.request_reconnect();
            }
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
    node.set_event_sink(event_log.clone()).await;
    // Keep the current roster history durable (Phase 8) so a future restart
    // can replay the log and verify each event against the roster active at
    // its birth round. Idempotent — membership changes overwrite it via the
    // node's own activation path.
    let roster_bytes = {
        let hg = node.hashgraph.lock().await;
        consensus::encode_roster_history(hg.roster_history())
    };
    event_log.set_roster_history(&roster_bytes)?;

    let gossip_listener = std::net::TcpListener::bind(("0.0.0.0", gossip_port))
        .with_context(|| format!("binding gossip port {gossip_port}"))?;
    gossip_listener
        .set_nonblocking(true)
        .with_context(|| "setting gossip listener nonblocking".to_string())?;
    let gossip_listener =
        TcpListener::from_std(gossip_listener).context("wrapping gossip listener")?;

    let reconnect_listener = match reconnect_port {
        Some(port) => {
            let listener = std::net::TcpListener::bind(("0.0.0.0", port))
                .with_context(|| format!("binding reconnect port {port}"))?;
            listener
                .set_nonblocking(true)
                .with_context(|| "setting reconnect listener nonblocking".to_string())?;
            Some(TcpListener::from_std(listener).context("wrapping reconnect listener")?)
        }
        None => None,
    };

    let control_socket_path =
        opts.control_socket.clone().unwrap_or_else(|| opts.data_dir.join("jkaind.sock"));
    let control_listener = control::bind(&control_socket_path).await?;

    eprintln!(
        "[jkaind] node {}: listening, control socket {} (waiting for SIGINT/SIGTERM)",
        opts.node_id,
        control_socket_path.display()
    );
    run_until_shutdown(
        node,
        gossip_listener,
        reconnect_listener,
        control_listener,
        control_socket_path,
    )
    .await
}

async fn run_until_shutdown(
    node: Arc<GossipNode>,
    gossip_listener: TcpListener,
    reconnect_listener: Option<TcpListener>,
    control_listener: UnixListener,
    control_socket_path: PathBuf,
) -> Result<()> {
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    let signal_task = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        signal_stop.store(true, Ordering::Release);
    });

    let control_stop = stop.clone();
    let control_node = node.clone();
    let control_task = tokio::spawn(async move {
        control::serve(control_listener, control_node, control_stop).await;
    });

    let result = match reconnect_listener {
        Some(reconnect_listener) => {
            node.run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop).await
        }
        None => node.run_until_stopped(gossip_listener, stop).await,
    };
    signal_task.abort();
    control_task.abort();
    let _ = std::fs::remove_file(&control_socket_path);
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

// --- control subcommands ------------------------------------------------------

/// `jkaind status`: prints a summary of a running node's cluster view.
async fn status_cmd(args: &[String]) -> Result<()> {
    let socket = parse_socket_flag(args)?;
    let report = fetch_status(&socket).await?;
    println!(
        "node {}: ordered round {}, decided round {}, latest checkpoint round {:?}",
        report.node_id, report.ordered_round, report.decided_round, report.latest_checkpoint_round
    );
    println!("members:");
    for member in &report.members {
        println!("  node {}  key {}", member.node_id, member.verifying_key);
    }
    println!("checkpoint roster:");
    if report.checkpoint_roster.is_empty() {
        println!("  (no accepted checkpoint yet)");
    } else {
        for member in &report.checkpoint_roster {
            println!("  node {}  key {}", member.node_id, member.verifying_key);
        }
    }
    // A restored checkpoint whose roster disagrees with the live registry is
    // the silent-consensus-stall signal: the node's events no longer verify.
    let live = report
        .members
        .iter()
        .find(|m| m.node_id == report.node_id)
        .map(|m| m.verifying_key.as_str());
    let checkpoint = report
        .checkpoint_roster
        .iter()
        .find(|m| m.node_id == report.node_id)
        .map(|m| m.verifying_key.as_str());
    match (live, checkpoint) {
        (Some(live_key), Some(checkpoint_key)) if live_key != checkpoint_key => {
            println!(
                "WARNING: checkpoint roster key for this node does not match the live member \
                 key — consensus may be silently stalled. Restore the original secret or wipe \
                 data/ and re-genesis."
            );
        }
        (Some(_), None) if !report.checkpoint_roster.is_empty() => {
            println!(
                "WARNING: this node is not in the latest checkpoint roster — it may have \
                 restored an incompatible checkpoint."
            );
        }
        _ => {}
    }
    println!("peers:");
    for peer in &report.peers {
        let reconnect = peer.reconnect_addr.as_deref().unwrap_or("-");
        println!("  node {} @ {} (reconnect {reconnect})", peer.node_id, peer.gossip_addr);
    }
    Ok(())
}

/// `jkaind tx put|delete`: submits a KV transaction for consensus ordering.
async fn tx_cmd(args: &[String]) -> Result<()> {
    let sub = args.first().context("tx requires a subcommand: put or delete")?;
    match sub.as_str() {
        "put" => tx_put(&args[1..]).await,
        "delete" => tx_delete(&args[1..]).await,
        other => bail!("tx: unknown subcommand '{other}'"),
    }
}

async fn tx_put(args: &[String]) -> Result<()> {
    let mut socket = default_socket();
    let mut key: Option<String> = None;
    let mut value: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--key" => key = Some(next_value(args, &mut i, "--key")?),
            "--value" => value = Some(next_value(args, &mut i, "--value")?),
            other => bail!("tx put: unknown argument '{other}'"),
        }
    }
    let key = key.context("tx put: --key <k> is required")?;
    let value = value.context("tx put: --value <v> is required")?;
    let op = Op::Put { key: key.into_bytes(), value: value.into_bytes() };
    submit_payload(&socket, &control::kv_op_payload(&op)).await?;
    println!("put queued on {}", socket.display());
    Ok(())
}

async fn tx_delete(args: &[String]) -> Result<()> {
    let mut socket = default_socket();
    let mut key: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--key" => key = Some(next_value(args, &mut i, "--key")?),
            other => bail!("tx delete: unknown argument '{other}'"),
        }
    }
    let key = key.context("tx delete: --key <k> is required")?;
    let op = Op::Delete { key: key.into_bytes() };
    submit_payload(&socket, &control::kv_op_payload(&op)).await?;
    println!("delete queued on {}", socket.display());
    Ok(())
}

/// `jkaind add-member`: submits a `MembershipOp::Add` transaction to a running
/// node. The `--key` hex is the new member's Ed25519 verifying key (printed by
/// `jkaind member init`). After the op is ordered and activated, the existing
/// cluster can gossip with the new node; the new node itself is provisioned by
/// `member init` and its own local `cluster.toml`.
async fn add_member(args: &[String]) -> Result<()> {
    let mut socket = default_socket();
    let mut node_id: Option<u64> = None;
    let mut gossip: Option<SocketAddr> = None;
    let mut reconnect: Option<SocketAddr> = None;
    let mut key_hex: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--node-id" => {
                let value = next_value(args, &mut i, "--node-id")?;
                node_id =
                    Some(value.parse().with_context(|| format!("invalid --node-id '{value}'"))?);
            }
            "--gossip" => {
                gossip =
                    Some(parse_socket_addr(&next_value(args, &mut i, "--gossip")?, "--gossip")?)
            }
            "--reconnect" => {
                reconnect = Some(parse_socket_addr(
                    &next_value(args, &mut i, "--reconnect")?,
                    "--reconnect",
                )?);
            }
            "--key" => key_hex = Some(next_value(args, &mut i, "--key")?),
            other => bail!("add-member: unknown argument '{other}'"),
        }
    }
    let node_id = node_id.context("add-member: --node-id <id> is required")?;
    let gossip = gossip.context("add-member: --gossip <ip:port> is required")?;
    let key_hex = key_hex.context("add-member: --key <hex> is required")?;
    let key_bytes = decode_hex(&key_hex)
        .context("add-member: --key must be a 64-char hex Ed25519 verifying key")?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .context("add-member: --key is not a valid Ed25519 verifying key")?;

    let op = MembershipOp::Add {
        node: NodeId::new(node_id),
        key: Box::new(key),
        addr: gossip,
        reconnect_addr: reconnect,
    };
    let payload = control::membership_op_payload(&op);
    submit_payload(&socket, &payload).await?;
    println!(
        "node {node_id} add-member submitted; it activates one round after the op is ordered."
    );

    // Firewall convenience: print the copy/paste ufw commands for both
    // directions, using the existing peers' addresses from status.
    let report = fetch_status(&socket).await?;
    let existing: Vec<(u64, SocketAddr, Option<SocketAddr>)> = report
        .peers
        .iter()
        .filter(|peer| peer.node_id != node_id)
        .map(|peer| {
            let gossip = peer
                .gossip_addr
                .parse()
                .with_context(|| format!("peer {}: invalid gossip_addr", peer.node_id))?;
            let reconnect =
                match &peer.reconnect_addr {
                    Some(addr) => Some(addr.parse().with_context(|| {
                        format!("peer {}: invalid reconnect_addr", peer.node_id)
                    })?),
                    None => None,
                };
            Ok((peer.node_id, gossip, reconnect))
        })
        .collect::<Result<Vec<_>>>()?;
    let reconnect = reconnect.unwrap_or(gossip);
    print_firewall_plan(node_id, gossip, reconnect, &existing);
    Ok(())
}

/// `jkaind member init`: provisions a brand-new member's secret (single 32-byte
/// seed) and its own local `cluster.toml` (genesis members + the new member).
/// The shared genesis `cluster.toml` is never modified. Prints the `--key` hex
/// to pass to `add-member` on an existing node, plus firewall instructions.
fn member_cmd(args: &[String]) -> Result<()> {
    let sub = args.first().context("member requires a subcommand: init")?;
    match sub.as_str() {
        "init" => member_init(&args[1..]),
        other => bail!("member: unknown subcommand '{other}'"),
    }
}

fn member_init(args: &[String]) -> Result<()> {
    let mut node_id: Option<u64> = None;
    let mut gossip: Option<SocketAddr> = None;
    let mut reconnect: Option<SocketAddr> = None;
    let mut cluster_path: Option<PathBuf> = None;
    let mut out_dir: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--node-id" => {
                let value = next_value(args, &mut i, "--node-id")?;
                node_id =
                    Some(value.parse().with_context(|| format!("invalid --node-id '{value}'"))?);
            }
            "--gossip" => {
                gossip =
                    Some(parse_socket_addr(&next_value(args, &mut i, "--gossip")?, "--gossip")?);
            }
            "--reconnect" => {
                reconnect = Some(parse_socket_addr(
                    &next_value(args, &mut i, "--reconnect")?,
                    "--reconnect",
                )?);
            }
            "--cluster" => {
                cluster_path = Some(PathBuf::from(next_value(args, &mut i, "--cluster")?))
            }
            "--out" => out_dir = Some(PathBuf::from(next_value(args, &mut i, "--out")?)),
            other => bail!("member init: unknown argument '{other}'"),
        }
    }
    let node_id = node_id.context("member init: --node-id <id> is required")?;
    let gossip = gossip.context("member init: --gossip <ip:port> is required")?;
    let reconnect = reconnect.context("member init: --reconnect <ip:port> is required")?;
    let cluster_path =
        cluster_path.context("member init: --cluster <genesis cluster.toml> is required")?;
    let out_dir = out_dir.context("member init: --out <dir> is required")?;

    let genesis = ClusterConfigFile::load(&cluster_path)?;
    if genesis.member_for(node_id).is_some() {
        bail!("member init: node-id {node_id} is already a member of the genesis cluster");
    }
    std::fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;

    // Single 32-byte seed: consensus signing AND TLS identity derive from it,
    // so the fingerprint an existing node pins via add_peer_from_key matches
    // this node's real TLS cert.
    let mut seed = [0u8; SINGLE_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let identity = TlsIdentity::from_seed(seed, node_id)
        .with_context(|| format!("building TLS identity for node {node_id}"))?;

    let secret_path = out_dir.join(format!("secret-{node_id}.bin"));
    std::fs::write(&secret_path, seed)
        .with_context(|| format!("writing {}", secret_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&secret_path)
            .with_context(|| format!("stat {}", secret_path.display()))?
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&secret_path, perms)
            .with_context(|| format!("chmod {}", secret_path.display()))?;
    }

    // The new member's LOCAL cluster.toml = genesis members + itself, written
    // under a node-specific filename so it can never clobber the shared
    // genesis `cluster.toml`, even when `--out` is the genesis directory.
    // Nodes in the genesis set keep their own cluster.toml unchanged; they
    // learn about this member through the add-member transaction.
    let mut members = genesis.members.clone();
    members.push(MemberFile::new(
        node_id,
        gossip,
        Some(reconnect),
        &signing_key.verifying_key(),
        identity.spki_fingerprint(),
    ));
    let config = ClusterConfigFile { members };
    let config_path = out_dir.join(format!("cluster-{node_id}.toml"));
    config.save(&config_path).with_context(|| format!("writing {}", config_path.display()))?;

    println!("Wrote node {node_id} local cluster config: {}", config_path.display());
    println!("Secret (keep on node {node_id} only): {}", secret_path.display());
    println!();
    println!("This local config is for node {node_id} ONLY — the genesis cluster.toml");
    println!("on nodes 1 and 2 is left untouched and must not be replaced with this file.");
    println!();
    println!("On an existing node, add this member with:");
    println!(
        "  jkaind add-member --node-id {node_id} --gossip {gossip} --reconnect {reconnect} --key {}",
        encode_hex(&signing_key.verifying_key().to_bytes())
    );
    println!();
    println!("Copy plan (run on the new member's VPS):");
    println!(
        "  scp {} user@vps:jkaind/ && scp {} user@vps:jkaind/",
        secret_path.display(),
        config_path.display()
    );
    println!();

    let existing: Vec<(u64, SocketAddr, Option<SocketAddr>)> = genesis
        .members
        .iter()
        .map(|member| (member.node_id, member.gossip_addr, member.reconnect_addr))
        .collect();
    print_firewall_plan(node_id, gossip, reconnect, &existing);
    Ok(())
}

/// Fetches the `status` report from a running node over the control socket.
async fn fetch_status(socket: &Path) -> Result<StatusReport> {
    let response = control::request(socket, &ControlRequest::Status).await?;
    control::ensure_ok(&response)?;
    let result = response.result.context("status response carries no result")?;
    serde_json::from_value(result).context("parsing status report")
}

/// Submits a raw transaction payload (already encoded) through the control
/// socket and fails on a non-ok response.
async fn submit_payload(socket: &Path, payload: &[u8]) -> Result<()> {
    let request = ControlRequest::SubmitTx { payload_hex: encode_hex(payload) };
    let response = control::request(socket, &request).await?;
    control::ensure_ok(&response)?;
    Ok(())
}

/// Prints the copy/paste `ufw` commands to open the gossip and reconnect ports
/// in both directions. The node cannot configure another VPS's firewall; this
/// is a convenience for the operator.
fn print_firewall_plan(
    new_node: u64,
    new_gossip: SocketAddr,
    new_reconnect: SocketAddr,
    existing: &[(u64, SocketAddr, Option<SocketAddr>)],
) {
    let new_ip = new_gossip.ip();
    println!("Firewall (run on the VPSes — these are the ports to open in both directions):");
    println!();
    println!(
        "  On the new member's VPS (node {new_node}), allow the existing members to reach it:"
    );
    for (id, gossip, _) in existing {
        println!(
            "    sudo ufw allow from {} to any port {} proto tcp   # node {id} gossip",
            gossip.ip(),
            new_gossip.port()
        );
        println!(
            "    sudo ufw allow from {} to any port {} proto tcp   # node {id} reconnect",
            gossip.ip(),
            new_reconnect.port()
        );
    }
    println!();
    println!("  On each existing member's VPS, allow the new member (IP {new_ip}) to reach it:");
    for (id, gossip, reconnect) in existing {
        println!(
            "    sudo ufw allow from {new_ip} to any port {} proto tcp   # node {id} gossip",
            gossip.port()
        );
        if let Some(reconnect) = reconnect {
            println!(
                "    sudo ufw allow from {new_ip} to any port {} proto tcp   # node {id} reconnect",
                reconnect.port()
            );
        }
    }
    println!();
}

fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

/// Extracts `--socket <path>` (default `data/jkaind.sock`) for the client
/// subcommands that take only that flag.
fn parse_socket_flag(args: &[String]) -> Result<PathBuf> {
    let mut socket = default_socket();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            other => bail!("unknown argument '{other}' (expected --socket <path>)"),
        }
    }
    Ok(socket)
}

fn parse_socket_addr(value: &str, flag: &str) -> Result<SocketAddr> {
    value.parse().with_context(|| format!("{flag} must be <ip>:<port>, got '{value}'"))
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
         \x20            [--control-socket <path>] [--sync-interval <ms>] [--sync-timeout <ms>]\n\
         \n\
         Control (talk to a running node over its Unix socket):\n\
         \x20 jkaind status  [--socket <path>]\n\
         \x20 jkaind tx put    --key <k> --value <v> [--socket <path>]\n\
         \x20 jkaind tx delete --key <k>             [--socket <path>]\n\
         \x20 jkaind add-member --node-id <id> --gossip <ip:port> \\\n\
         \x20                  [--reconnect <ip:port>] --key <hex> [--socket <path>]\n\
         \n\
         Provision a new member (never touches the genesis cluster.toml):\n\
         \x20 jkaind member init --node-id <id> --gossip <ip:port> --reconnect <ip:port> \\\n\
         \x20                    --cluster <genesis cluster.toml> --out <dir>\n\
         \n\
         Examples:\n\
         \x20 jkaind init --member 1:203.0.113.5:7000:203.0.113.5:7001 \\\n\
         \x20             --member 2:203.0.113.6:7000:203.0.113.6:7001 --out ./cluster\n\
         \x20 jkaind run --cluster ./cluster/cluster.toml --node-id 1 \\\n\
         \x20            --secret ./cluster/secret-1.bin --data ./data\n\
         \x20 jkaind status\n\
         \x20 jkaind tx put --key balance --value 100\n\
         \x20 jkaind add-member --node-id 3 --gossip 203.0.113.7:7000 \\\n\
         \x20                 --reconnect 203.0.113.7:7001 --key <hex-from-member-init>"
    );
}
