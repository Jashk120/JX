//! `jkaind member` — provisioning subcommands for members added after genesis.

use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{
    Context,
    Result,
    bail,
};
use ed25519_dalek::SigningKey;
use gossip::TlsIdentity;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::cli::args::{
    next_value,
    parse_socket_addr,
};
use crate::cli::client::print_firewall_plan;
use crate::cli::keys::{
    SINGLE_SEED_LEN,
    write_secret_bytes,
};
use crate::config::{
    ClusterConfigFile,
    MemberFile,
    encode_hex,
};

/// `jkaind member init`: provisions a brand-new member's secret (single 32-byte
/// seed) and its own local `cluster.toml` (genesis members + the new member).
/// The shared genesis `cluster.toml` is never modified. Prints the `--key` hex
/// to pass to `add-member` on an existing node, plus firewall instructions.
pub(crate) fn member_cmd(args: &[String]) -> Result<()> {
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
    let mut force = false;

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
            "--force" => {
                force = true;
                i += 1;
            }
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

    // BLS identity: separate 32-byte IKM, derives the BLS public key for checkpoints.
    let mut bls_ikm = [0u8; 32];
    OsRng.fill_bytes(&mut bls_ikm);
    let bls_identity = crypto::BlsIdentity::from_ikm(&bls_ikm)
        .with_context(|| format!("generating BLS identity for node {node_id}"))?;
    let bls_pub = bls_identity.public.to_bytes();

    let secret_path = out_dir.join(format!("secret-{node_id}.bin"));
    let bls_path = out_dir.join(format!("secret-{node_id}.bls.bin"));
    if (secret_path.exists() || bls_path.exists()) && !force {
        let existing = if secret_path.exists() {
            secret_path.display().to_string()
        } else {
            bls_path.display().to_string()
        };
        bail!(
            "{existing} already exists; use --force to regenerate (refusing to overwrite secrets)"
        );
    }
    write_secret_bytes(&secret_path, &seed)
        .with_context(|| format!("writing {}", secret_path.display()))?;
    write_secret_bytes(&bls_path, &bls_ikm)
        .with_context(|| format!("writing {}", bls_path.display()))?;

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
        bls_pub,
    ));
    let config = ClusterConfigFile { members };
    let config_path = out_dir.join(format!("cluster-{node_id}.toml"));
    config.save(&config_path).with_context(|| format!("writing {}", config_path.display()))?;

    tracing::info!(
        node_id,
        config = %config_path.display(),
        "wrote local cluster config"
    );
    tracing::info!(
        node_id,
        secret = %secret_path.display(),
        "secret file written"
    );
    tracing::info!(
        node_id,
        secret = %bls_path.display(),
        "BLS secret file written"
    );
    tracing::info!(
        node_id,
        gossip = %gossip,
        reconnect = %reconnect,
        key = encode_hex(&signing_key.verifying_key().to_bytes()),
        bls_key = encode_hex(&bls_pub),
        "add-member command"
    );
    tracing::info!(
        node_id,
        secret = %secret_path.display(),
        config = %config_path.display(),
        "copy to VPS"
    );

    let existing: Vec<(u64, SocketAddr, Option<SocketAddr>)> = genesis
        .members
        .iter()
        .map(|member| (member.node_id, member.gossip_addr, member.reconnect_addr))
        .collect();
    print_firewall_plan(node_id, gossip, reconnect, &existing);
    Ok(())
}
