//! `jkaind run` — the daemon itself: config/secret loading, restart recovery,
//! listener binding, and the shutdown path.

use std::path::PathBuf;
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
    SyncTiming,
    TlsIdentity,
};
use primitives::NodeId;
use state::StateDb;
use storage::EventLog;
use stream::{
    EventStreamWriter,
    RecordStreamWriter,
};
use tokio::net::{
    TcpListener,
    UnixListener,
};
use tracing_subscriber::EnvFilter;

use crate::cli::args::{
    next_value,
    parse_ms,
    parse_port,
};
use crate::cli::keys::{
    SECRET_LEN,
    SINGLE_SEED_LEN,
};
use crate::config::{
    ClusterConfigFile,
    decode_bls_hex,
    decode_hex,
    encode_hex,
};

// T10 (PLAN-2.4 Wave 6): prod default stays 500ms (safe). 5ms gap is
// allowed only via `--sync-interval 5` after W1-W3 green (hot-peer QUIC +
// fanout proven) and G6 bench passes. Operator must abort 5ms runs if
// `k10temp > 85°C` (thermal throttle — expect p50 ~0.12s at 5ms, fanout=4,
// only when cool). See protocol/test-support SYNC_INTERVAL (still 25ms until
// D1 lifted).
const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_millis(500);
const DEFAULT_SYNC_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_FANOUT: &str = "auto";

pub(crate) async fn run(args: &[String]) -> Result<()> {
    let mut cluster_path: Option<PathBuf> = None;
    let mut node_id: Option<u64> = None;
    let mut secret_path: Option<PathBuf> = None;
    let mut gossip_port: Option<u16> = None;
    let mut reconnect_port: Option<u16> = None;
    let mut data_dir = PathBuf::from("data");
    let mut control_socket: Option<PathBuf> = None;
    let mut sync_interval = DEFAULT_SYNC_INTERVAL;
    let mut sync_timeout = DEFAULT_SYNC_TIMEOUT;
    let mut fanout_str = DEFAULT_FANOUT.to_string();
    let mut log_level = "info".to_string();
    let mut log_file: Option<String> = None;

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
                let ms = parse_ms(&value, "--sync-interval")?;
                if !(5..=5000).contains(&ms) {
                    bail!("run: invalid --sync-interval '{value}' (expected 5..5000)");
                }
                sync_interval = Duration::from_millis(ms);
            }
            "--sync-timeout" => {
                let value = next_value(args, &mut i, "--sync-timeout")?;
                sync_timeout = Duration::from_millis(parse_ms(&value, "--sync-timeout")?);
            }
            "--log-level" => {
                log_level = next_value(args, &mut i, "--log-level")?;
            }
            "--log-file" => {
                log_file = Some(next_value(args, &mut i, "--log-file")?);
            }
            "--fanout" => {
                fanout_str = next_value(args, &mut i, "--fanout")?;
            }
            other => bail!("run: unknown argument '{other}'"),
        }
    }
    let cluster_path = cluster_path.context("run: --cluster <path> is required")?;
    let node_id = node_id.context("run: --node-id <id> is required")?;
    let secret_path = secret_path.context("run: --secret <path> is required")?;

    let fanout = gossip::FanoutMode::parse(&fanout_str)
        .with_context(|| format!("invalid --fanout '{fanout_str}' (expected auto or integer)"))?;
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
        fanout,
        log_level,
        log_file,
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
    fanout: gossip::FanoutMode,
    log_level: String,
    log_file: Option<String>,
}

fn bls_path_for(secret_path: &std::path::Path) -> PathBuf {
    let file_name = secret_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if let Some(stripped) = file_name.strip_suffix(".bin") {
        let mut p = secret_path.to_path_buf();
        p.set_file_name(format!("{stripped}.bls.bin"));
        p
    } else {
        let mut p = secret_path.to_path_buf();
        p.set_extension("bls.bin");
        p
    }
}

async fn run_node(opts: &RunOptions) -> Result<()> {
    let default_log_path = opts.data_dir.join("logs").join("jkaind.log");
    let log_path = match opts.log_file.as_deref() {
        Some("-") => None,
        Some(p) => Some(PathBuf::from(p)),
        None => Some(default_log_path),
    };
    if let Some(ref path) = log_path
        && let Some(parent) = path.parent()
    {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating log dir {}", parent.display()))?;
    }
    let filter = EnvFilter::try_new(&opts.log_level).context("invalid log level")?;
    let _guard = match log_path {
        Some(path) => {
            let file_appender = tracing_appender::rolling::daily(
                path.parent().unwrap_or(&PathBuf::from(".")),
                path.file_name().unwrap_or_default(),
            );
            let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(non_blocking)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            Some(guard)
        }
        None => {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .finish();
            let _ = tracing::subscriber::set_global_default(subscriber);
            None
        }
    };

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

    let bls_secret_path = bls_path_for(&opts.secret_path);
    let bls_bytes = std::fs::read(&bls_secret_path)
        .with_context(|| format!("missing BLS identity file at {}", bls_secret_path.display()))?;
    if bls_bytes.len() != 32 {
        bail!(
            "BLS identity file at {} has invalid length: expected 32, got {}",
            bls_secret_path.display(),
            bls_bytes.len()
        );
    }
    let bls_ikm: [u8; 32] = bls_bytes.try_into().expect("32-byte BLS IKM");
    let bls_identity = crypto::BlsIdentity::from_ikm(&bls_ikm).with_context(|| {
        format!("failed to derive BLS identity from {}", bls_secret_path.display())
    })?;
    let derived_bls_hex = encode_hex(&bls_identity.public.to_bytes());
    let expected_bls = decode_bls_hex(&member.bls_verifying_key)
        .with_context(|| format!("member {}: invalid bls_verifying_key hex", opts.node_id))?;
    let expected_bls_hex = member.bls_verifying_key.to_ascii_lowercase();
    if bls_identity.public.to_bytes() != expected_bls {
        bail!(
            "BLS identity mismatch for member {}: derived {} != configured {}",
            opts.node_id,
            derived_bls_hex,
            expected_bls_hex
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

    let roster_ids: Vec<u64> = config.members.iter().map(|m| m.node_id).collect();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        git_hash = env!("JKAIN_GIT_HASH"),
        node_id = opts.node_id,
        roster_count = roster_ids.len(),
        roster_ids = ?roster_ids,
        "jkaind starting"
    );

    // Refuse to open any storage against a data dir written by an
    // incompatible binary version (self-enforcing wipe on breaking format
    // changes, e.g. the Merkle-root checkpoint commitment).
    crate::format::check_or_init_data_dir(&opts.data_dir)
        .with_context(|| format!("checking data dir {}", opts.data_dir.display()))?;

    let storage = crate::storage::Storage::new(&opts.data_dir)?;
    let event_log = Arc::new(EventLog::open(&opts.data_dir)?);
    let state_db = Arc::new(StateDb::open(&opts.data_dir)?);

    // Mirror streams (Phase 8): the stream files need their own copy of the
    // consensus signing key — the one handed to `GossipNode` is moved in.
    let stream_signing_key = signing_key.clone();

    match reconnect_port {
        Some(port) => tracing::info!(
            node_id = opts.node_id,
            gossip_port,
            reconnect_port = port,
            data_dir = %opts.data_dir.display(),
            "node configured"
        ),
        None => tracing::info!(
            node_id = opts.node_id,
            gossip_port,
            reconnect_disabled = true,
            data_dir = %opts.data_dir.display(),
            "node configured (gossip-only member)"
        ),
    }

    // Restart recovery: restore from the last persisted checkpoint if one
    // exists, replaying the retained graph from the local event log (Phase 8)
    // so the node recovers independently — no live peer needed. When the log
    // is empty (pre-event-log data, or a checkpoint without logged events),
    // fall back to reconnecting from a live peer for the event window.
    let node = match crate::restart::latest_for_restart_with_log(
        &storage,
        &event_log,
        &state_db,
        opts.node_id,
        &signing_key.verifying_key(),
    )? {
        Some(response) => {
            let replay_has_events = !response.retained.is_empty();
            tracing::info!(
                round = response.signed_checkpoint.payload.round,
                retained_events = response.retained.len(),
                "restoring from persisted checkpoint"
            );
            let node = GossipNode::from_checkpoint_with_bls(
                NodeId::new(opts.node_id),
                signing_key,
                bls_identity,
                identity,
                peers,
                SyncTiming::new(opts.sync_interval, opts.sync_timeout),
                response,
                state_db.clone(),
            )
            .await?;
            if !replay_has_events {
                node.request_reconnect();
            }
            node
        }
        None => {
            tracing::info!("fresh start (no persisted checkpoint)");
            GossipNode::new_with_bls(
                NodeId::new(opts.node_id),
                signing_key,
                bls_identity,
                registry,
                identity,
                peers,
                SyncTiming::new(opts.sync_interval, opts.sync_timeout),
                state_db.clone(),
            )
        }
    };
    let mut node = node;
    node.set_fanout(opts.fanout);
    let node = Arc::new(node);

    node.set_event_sink(event_log.clone()).await;
    let streams_dir = opts.data_dir.join(stream::STREAMS_SUBDIR);
    let event_stream = Arc::new(EventStreamWriter::open(
        &streams_dir,
        stream_signing_key.clone(),
        stream::DEFAULT_EVENTS_PER_FILE,
    )?);
    let record_stream = Arc::new(RecordStreamWriter::open(
        &streams_dir,
        stream_signing_key,
        node.hashgraph.clone(),
    )?);
    node.set_event_stream_sink(event_stream).await;
    node.set_record_sink(record_stream).await;
    let ckpt_sink = crate::storage::CkptSink::new(&streams_dir)?;
    let composite = crate::storage::CompositeCheckpointSink::new(storage, ckpt_sink);
    node.set_checkpoint_sink(Arc::new(composite)).await;
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
    let control_listener = crate::control::bind(&control_socket_path).await?;

    tracing::info!(
        node_id = opts.node_id,
        control_socket = %control_socket_path.display(),
        "listening, waiting for SIGINT/SIGTERM"
    );
    run_until_shutdown(
        node,
        gossip_listener,
        reconnect_listener,
        control_listener,
        control_socket_path,
        opts.data_dir.clone(),
    )
    .await
}

async fn run_until_shutdown(
    node: Arc<GossipNode>,
    gossip_listener: TcpListener,
    reconnect_listener: Option<TcpListener>,
    control_listener: UnixListener,
    control_socket_path: PathBuf,
    data_dir: PathBuf,
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
        crate::control::serve(control_listener, control_node, control_stop).await;
    });

    let diagnosis_stop = stop.clone();
    let diagnosis_node = node.clone();
    let diagnosis_path = data_dir.join("logs").join("diagnosis.log");
    let diagnosis_task = tokio::spawn(async move {
        spawn_diagnosis_logger(diagnosis_node, diagnosis_path, diagnosis_stop).await;
    });

    let result = match reconnect_listener {
        Some(reconnect_listener) => {
            node.clone()
                .run_until_stopped_with_reconnect(gossip_listener, reconnect_listener, stop.clone())
                .await
        }
        None => node.clone().run_until_stopped(gossip_listener, stop.clone()).await,
    };
    let flush_timeout = Duration::from_secs(5);
    if !node.flush_streams(flush_timeout).await {
        tracing::warn!("stream flush timed out after {:?}", flush_timeout);
    }
    signal_task.abort();
    control_task.abort();
    diagnosis_task.abort();
    let _ = std::fs::remove_file(&control_socket_path);
    match result {
        Ok(()) => {
            tracing::info!("shutdown requested; sync driver drained, exiting");
            Ok(())
        }
        Err(e) => Err(e).with_context(|| "node run failed"),
    }
}

async fn spawn_diagnosis_logger(node: Arc<GossipNode>, path: PathBuf, stop: Arc<AtomicBool>) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        if stop.load(Ordering::Acquire) {
            break;
        }
        let m = node.gossip_metrics_snapshot().await;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis().to_string())
            .unwrap_or_else(|_| "0".to_string());
        let line = serde_json::json!({
            "ts": ts,
            "sync_attempts": m.sync_attempts,
            "sync_success": m.sync_success,
            "sync_failures": m.sync_failures,
            "success_rate": m.success_rate(),
            "p50_rtt_ms": m.p50_rtt_ms,
            "p95_rtt_ms": m.p95_rtt_ms,
            "delta_bytes_per_sync": m.delta_bytes_per_sync,
            "cache_hit_rate": m.cache_hit_rate,
            "backoff_peers": 0,
        });
        let text = format!("{}\n", line);
        if let Ok(mut file) =
            tokio::fs::OpenOptions::new().create(true).append(true).open(&path).await
        {
            use tokio::io::AsyncWriteExt;
            let _ = file.write_all(text.as_bytes()).await;
        }
        tracing::info!(
            sync_attempts = m.sync_attempts,
            sync_success = m.sync_success,
            success_rate = m.success_rate(),
            p50_rtt_ms = m.p50_rtt_ms,
            p95_rtt_ms = m.p95_rtt_ms,
            delta_bytes_per_sync = m.delta_bytes_per_sync,
            cache_hit_rate = m.cache_hit_rate,
            "diagnosis gossip metrics"
        );
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
