//! `jkaind init` — genesis cluster provisioning: per-node secrets plus the
//! shared `cluster.toml`.

use std::path::{
    Path,
    PathBuf,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use ed25519_dalek::SigningKey;
use gossip::TlsIdentity;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::cli::args::next_value;
use crate::cli::keys::{
    SECRET_LEN,
    write_secret_bytes,
};
use crate::config::{
    ClusterConfigFile,
    MemberFile,
};

pub(crate) fn init(args: &[String]) -> Result<()> {
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
                tracing::warn!(
                    hazard = %hazard.display(),
                    "persisted checkpoints found; regenerated keys will be incompatible — wipe data/ on every node before restarting"
                );
            }
            None => {
                tracing::warn!(
                    "regenerating cluster keys invalidates any persisted checkpoints \
                     on running nodes (none found locally). Wipe data/ on every node before restarting."
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
        write_secret_bytes(&secret_path, &secret)
            .with_context(|| format!("writing {}", secret_path.display()))?;
        let signing_key =
            SigningKey::from_bytes(&secret[..32].try_into().expect("32-byte consensus seed"));
        let identity =
            TlsIdentity::from_seed(secret[32..].try_into().expect("32-byte TLS seed"), node_id)
                .with_context(|| format!("building TLS identity for node {node_id}"))?;
        member_files.push(MemberFile::new(
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
    tracing::info!(config = %config_path.display(), "wrote cluster config");
    for (node_id, _, _) in members {
        tracing::info!(
            secret = %out_dir.join(format!("secret-{node_id}.bin")).display(),
            "secret file written"
        );
    }
    for (node_id, _, _) in members {
        let secret = out_dir.join(format!("secret-{node_id}.bin"));
        tracing::info!(
            node_id,
            secret = %secret.display(),
            config = %config_path.display(),
            "copy to VPS"
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
