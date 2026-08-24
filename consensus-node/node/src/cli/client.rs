//! Control-socket client subcommands: `status`, `tx put|delete`, and
//! `add-member` — they talk to a running node over its Unix socket.

use std::net::SocketAddr;
use std::path::{
    Path,
    PathBuf,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use crypto::MembershipOp;
use ed25519_dalek::VerifyingKey;
use primitives::NodeId;
use state::Op;

use crate::cli::args::{
    default_socket,
    next_value,
    parse_socket_addr,
    parse_socket_flag,
};
use crate::config::{
    decode_hex,
    encode_hex,
};
use crate::control::{
    self,
    ControlRequest,
    StatusReport,
};

/// `jkaind status`: prints a summary of a running node's cluster view.
pub(crate) async fn status_cmd(args: &[String]) -> Result<()> {
    let socket = parse_socket_flag(args)?;
    let report = fetch_status(&socket).await?;
    tracing::info!(
        node_id = report.node_id,
        ordered_round = report.ordered_round,
        decided_round = report.decided_round,
        latest_checkpoint_round = ?report.latest_checkpoint_round,
        "node status"
    );
    for member in &report.members {
        tracing::info!(
            node_id = member.node_id,
            key = %member.verifying_key,
            "member"
        );
    }
    if report.checkpoint_roster.is_empty() {
        tracing::info!("checkpoint roster: (no accepted checkpoint yet)");
    } else {
        for member in &report.checkpoint_roster {
            tracing::info!(
                node_id = member.node_id,
                key = %member.verifying_key,
                "checkpoint roster member"
            );
        }
    }
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
            tracing::warn!(
                "checkpoint roster key for this node does not match the live member key — \
                 consensus may be silently stalled. Restore the original secret or wipe \
                 data/ and re-genesis."
            );
        }
        (Some(_), None) if !report.checkpoint_roster.is_empty() => {
            tracing::warn!(
                "this node is not in the latest checkpoint roster — it may have \
                 restored an incompatible checkpoint."
            );
        }
        _ => {}
    }
    for peer in &report.peers {
        let reconnect = peer.reconnect_addr.as_deref().unwrap_or("-");
        tracing::info!(
            node_id = peer.node_id,
            gossip_addr = %peer.gossip_addr,
            reconnect,
            "peer"
        );
    }
    Ok(())
}

/// `jkaind tx put|delete`: submits a KV transaction for consensus ordering.
pub(crate) async fn tx_cmd(args: &[String]) -> Result<()> {
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
    tracing::info!(socket = %socket.display(), "put queued");
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
    tracing::info!(socket = %socket.display(), "delete queued");
    Ok(())
}

/// `jkaind add-member`: submits a `MembershipOp::Add` transaction to a running
/// node. The `--key` hex is the new member's Ed25519 verifying key (printed by
/// `jkaind member init`). After the op is ordered and activated, the existing
/// cluster can gossip with the new node; the new node itself is provisioned by
/// `member init` and its own local `cluster.toml`.
pub(crate) async fn add_member(args: &[String]) -> Result<()> {
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
    tracing::info!(node_id, "add-member submitted; activates one round after the op is ordered");

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

/// Fetches the `status` report from a running node over the control socket.
pub(crate) async fn fetch_status(socket: &Path) -> Result<StatusReport> {
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
pub(crate) fn print_firewall_plan(
    _new_node: u64,
    new_gossip: SocketAddr,
    new_reconnect: SocketAddr,
    existing: &[(u64, SocketAddr, Option<SocketAddr>)],
) {
    let new_ip = new_gossip.ip();
    for (id, gossip, _) in existing {
        tracing::info!(
            from = %gossip.ip(),
            to_port = new_gossip.port(),
            proto = "tcp",
            rule = "ufw allow",
            comment = format!("node {id} gossip"),
            "firewall rule"
        );
        tracing::info!(
            from = %gossip.ip(),
            to_port = new_reconnect.port(),
            proto = "tcp",
            rule = "ufw allow",
            comment = format!("node {id} reconnect"),
            "firewall rule"
        );
    }
    for (id, gossip, reconnect) in existing {
        tracing::info!(
            from = %new_ip,
            to_port = gossip.port(),
            proto = "tcp",
            rule = "ufw allow",
            comment = format!("node {id} gossip"),
            "firewall rule"
        );
        if let Some(reconnect) = reconnect {
            tracing::info!(
                from = %new_ip,
                to_port = reconnect.port(),
                proto = "tcp",
                rule = "ufw allow",
                comment = format!("node {id} reconnect"),
                "firewall rule"
            );
        }
    }
}
