//! Control-socket client subcommands: `status`, `tx
//! put|delete|did|sub-actor|rebind`, and `add-member` — they talk to a running
//! node over its Unix socket.

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
use primitives::{
    NodeId,
    Signature,
};
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

/// `jkaind tx put|delete|did|sub-actor|rebind`: submits a transaction for
/// consensus ordering.
pub(crate) async fn tx_cmd(args: &[String]) -> Result<()> {
    let sub =
        args.first().context("tx requires a subcommand: put, delete, did, sub-actor, or rebind")?;
    match sub.as_str() {
        "put" => tx_put(&args[1..]).await,
        "delete" => tx_delete(&args[1..]).await,
        "did" => tx_did(&args[1..]).await,
        "sub-actor" => tx_sub_actor(&args[1..]).await,
        "rebind" => tx_rebind(&args[1..]).await,
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

/// Raw `--network/--alias/--uuid` flag values identifying a root DID. Shared
/// by the actor subcommands so the root id is parsed one way everywhere.
struct RootIdFlags {
    network: Option<String>,
    alias: Option<String>,
    uuid_hex: Option<String>,
}

fn parse_root_did(cmd: &str, flags: &RootIdFlags) -> Result<state::DidId> {
    let network =
        flags.network.clone().with_context(|| format!("{cmd}: --network <s> is required"))?;
    let alias = flags.alias.clone().with_context(|| format!("{cmd}: --alias <s> is required"))?;
    let uuid_hex =
        flags.uuid_hex.clone().with_context(|| format!("{cmd}: --uuid <32 hex> is required"))?;
    let uuid = decode_uuid(&uuid_hex, cmd)?;
    state::DidId::new(network, alias, uuid).map_err(|_| {
        anyhow::anyhow!("{cmd}: invalid DID id (--network/--alias must not contain ':')")
    })
}

fn decode_uuid(hex: &str, cmd: &str) -> Result<[u8; 16]> {
    let bytes = crate::config::decode_hex_bytes(hex)
        .with_context(|| format!("{cmd}: --uuid must be 32 hex chars (16 bytes)"))?;
    if bytes.len() != 16 {
        bail!("{cmd}: --uuid must be 32 hex chars (16 bytes), got {} bytes", bytes.len());
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    Ok(uuid)
}

fn decode_verifying_key(hex: &str, flag: &str, cmd: &str) -> Result<VerifyingKey> {
    let bytes = decode_hex(hex)
        .with_context(|| format!("{cmd}: {flag} must be 64 hex chars (32 bytes)"))?;
    VerifyingKey::from_bytes(&bytes)
        .with_context(|| format!("{cmd}: {flag} is not a valid Ed25519 verifying key"))
}

fn decode_signature(hex: &str, flag: &str, cmd: &str) -> Result<Signature> {
    let bytes = crate::config::decode_hex_bytes(hex)
        .with_context(|| format!("{cmd}: {flag} must be hex"))?;
    if bytes.len() != 64 {
        bail!("{cmd}: {flag} must be 128 hex chars (64 bytes), got {} bytes", bytes.len());
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(Signature::new(arr))
}

fn decode_hash(hex: &str, flag: &str, cmd: &str) -> Result<state::Hash> {
    decode_hex(hex).with_context(|| format!("{cmd}: {flag} must be 64 hex chars (32 bytes)"))
}

fn parse_signed_by(signed_by: Option<&String>, cmd: &str) -> Result<u8> {
    let value = signed_by.with_context(|| format!("{cmd}: --signed-by <u8> is required"))?;
    value.parse().with_context(|| format!("{cmd}: invalid --signed-by '{value}'"))
}

fn parse_tag(value: &str, cmd: &str) -> Result<state::Tag> {
    match value {
        "defi" => Ok(state::Tag::Defi),
        "messenger" => Ok(state::Tag::Messenger),
        "game" => Ok(state::Tag::Game),
        "generic" => Ok(state::Tag::Generic),
        other => bail!("{cmd}: unknown --tag '{other}' (expected defi|messenger|game|generic)"),
    }
}

fn parse_method(value: &str, cmd: &str) -> Result<state::VerificationMethod> {
    let (kind, hex) = value.split_once(':').with_context(|| {
        format!("{cmd}: invalid --method '{value}' (expected ed25519:<64 hex> or x25519:<64 hex>)")
    })?;
    let bytes = decode_hex(hex)
        .with_context(|| format!("{cmd}: invalid --method '{value}' (key must be 64 hex chars)"))?;
    match kind {
        "ed25519" => {
            Ok(state::VerificationMethod::Signing(VerifyingKey::from_bytes(&bytes).with_context(
                || format!("{cmd}: invalid --method '{value}' (not an Ed25519 point)"),
            )?))
        }
        "x25519" => Ok(state::VerificationMethod::Agreement(x25519_dalek::PublicKey::from(bytes))),
        other => bail!("{cmd}: unknown --method kind '{other}' (expected ed25519 or x25519)"),
    }
}

fn parse_index(index: Option<&String>, cmd: &str) -> Result<u32> {
    let value = index.with_context(|| format!("{cmd}: --index <u32> is required"))?;
    value.parse().with_context(|| format!("{cmd}: invalid --index '{value}'"))
}

/// `jkaind tx did`: submits a `DidOp` (`0x03`) transaction to a running node.
/// `--create` marks a creation (else an update); `--deactivate` tombstones the
/// DID and is mutually exclusive with `--create`.
async fn tx_did(args: &[String]) -> Result<()> {
    const CMD: &str = "tx did";
    let mut socket = default_socket();
    let mut id_flags = RootIdFlags { network: None, alias: None, uuid_hex: None };
    let mut control_key_hex: Option<String> = None;
    let mut methods: Vec<String> = Vec::new();
    let mut signature_hex: Option<String> = None;
    let mut signed_by: Option<String> = None;
    let mut create = false;
    let mut deactivate = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--network" => id_flags.network = Some(next_value(args, &mut i, "--network")?),
            "--alias" => id_flags.alias = Some(next_value(args, &mut i, "--alias")?),
            "--uuid" => id_flags.uuid_hex = Some(next_value(args, &mut i, "--uuid")?),
            "--control-key" => control_key_hex = Some(next_value(args, &mut i, "--control-key")?),
            "--method" => methods.push(next_value(args, &mut i, "--method")?),
            "--signature" => signature_hex = Some(next_value(args, &mut i, "--signature")?),
            "--signed-by" => signed_by = Some(next_value(args, &mut i, "--signed-by")?),
            "--create" => {
                create = true;
                i += 1;
            }
            "--deactivate" => {
                deactivate = true;
                i += 1;
            }
            other => bail!("tx did: unknown argument '{other}'"),
        }
    }
    if create && deactivate {
        bail!("tx did: --create and --deactivate are mutually exclusive");
    }
    let id = parse_root_did(CMD, &id_flags)?;
    let control_hex =
        control_key_hex.with_context(|| format!("{CMD}: --control-key <64 hex> is required"))?;
    let control_key = decode_verifying_key(&control_hex, "--control-key", CMD)?;
    if methods.is_empty() {
        bail!("tx did: at least one --method <ed25519:64hex|x25519:64hex> is required");
    }
    let mut parsed_methods = Vec::with_capacity(methods.len());
    for method in &methods {
        parsed_methods.push(parse_method(method, CMD)?);
    }
    if !parsed_methods.iter().any(|m| matches!(m, state::VerificationMethod::Signing(_))) {
        bail!("tx did: at least one --method must be ed25519 (signing)");
    }
    let document = state::DidDocument::new(control_key, parsed_methods, deactivate)
        .with_context(|| format!("{CMD}: invalid document"))?;
    let sig_hex =
        signature_hex.with_context(|| format!("{CMD}: --signature <128 hex> is required"))?;
    let signature = decode_signature(&sig_hex, "--signature", CMD)?;
    let signed_by = parse_signed_by(signed_by.as_ref(), CMD)?;
    let op = state::DidOp::new(id, document, signature, signed_by, create);
    submit_payload(&socket, &control::did_op_payload(&op)).await?;
    tracing::info!(socket = %socket.display(), "did queued");
    Ok(())
}

/// `jkaind tx sub-actor`: submits a `SubActorOp` (`0x04`) transaction to a
/// running node. Both proofs travel as hex of their canonical encodings.
async fn tx_sub_actor(args: &[String]) -> Result<()> {
    const CMD: &str = "tx sub-actor";
    let mut socket = default_socket();
    let mut id_flags = RootIdFlags { network: None, alias: None, uuid_hex: None };
    let mut tag: Option<String> = None;
    let mut index: Option<String> = None;
    let mut control_key_hex: Option<String> = None;
    let mut operating_key_hex: Option<String> = None;
    let mut new_root_hex: Option<String> = None;
    let mut consistency_hex: Option<String> = None;
    let mut inclusion_hex: Option<String> = None;
    let mut signature_hex: Option<String> = None;
    let mut signed_by: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--network" => id_flags.network = Some(next_value(args, &mut i, "--network")?),
            "--alias" => id_flags.alias = Some(next_value(args, &mut i, "--alias")?),
            "--uuid" => id_flags.uuid_hex = Some(next_value(args, &mut i, "--uuid")?),
            "--tag" => tag = Some(next_value(args, &mut i, "--tag")?),
            "--index" => index = Some(next_value(args, &mut i, "--index")?),
            "--control-key" => control_key_hex = Some(next_value(args, &mut i, "--control-key")?),
            "--operating-key" => {
                operating_key_hex = Some(next_value(args, &mut i, "--operating-key")?);
            }
            "--new-root" => new_root_hex = Some(next_value(args, &mut i, "--new-root")?),
            "--consistency-proof" => {
                consistency_hex = Some(next_value(args, &mut i, "--consistency-proof")?);
            }
            "--inclusion-proof" => {
                inclusion_hex = Some(next_value(args, &mut i, "--inclusion-proof")?);
            }
            "--signature" => signature_hex = Some(next_value(args, &mut i, "--signature")?),
            "--signed-by" => signed_by = Some(next_value(args, &mut i, "--signed-by")?),
            other => bail!("tx sub-actor: unknown argument '{other}'"),
        }
    }
    let root_did = parse_root_did(CMD, &id_flags)?;
    let tag_value =
        tag.with_context(|| format!("{CMD}: --tag <defi|messenger|game|generic> is required"))?;
    let tag = parse_tag(&tag_value, CMD)?;
    let index = parse_index(index.as_ref(), CMD)?;
    let control_hex =
        control_key_hex.with_context(|| format!("{CMD}: --control-key <64 hex> is required"))?;
    let control_key = decode_verifying_key(&control_hex, "--control-key", CMD)?;
    let operating_hex = operating_key_hex
        .with_context(|| format!("{CMD}: --operating-key <64 hex> is required"))?;
    let operating_key = decode_verifying_key(&operating_hex, "--operating-key", CMD)?;
    let root_hex =
        new_root_hex.with_context(|| format!("{CMD}: --new-root <64 hex> is required"))?;
    let new_root = decode_hash(&root_hex, "--new-root", CMD)?;
    let consistency_value =
        consistency_hex.with_context(|| format!("{CMD}: --consistency-proof <hex> is required"))?;
    let consistency_bytes = crate::config::decode_hex_bytes(&consistency_value)
        .with_context(|| format!("{CMD}: --consistency-proof must be hex"))?;
    let consistency_proof = state::ConsistencyProof::decode(&consistency_bytes)
        .with_context(|| format!("{CMD}: --consistency-proof does not decode"))?;
    let inclusion_value =
        inclusion_hex.with_context(|| format!("{CMD}: --inclusion-proof <hex> is required"))?;
    let inclusion_bytes = crate::config::decode_hex_bytes(&inclusion_value)
        .with_context(|| format!("{CMD}: --inclusion-proof must be hex"))?;
    let inclusion_proof = state::InclusionProof::decode(&inclusion_bytes)
        .with_context(|| format!("{CMD}: --inclusion-proof does not decode"))?;
    let sig_hex =
        signature_hex.with_context(|| format!("{CMD}: --signature <128 hex> is required"))?;
    let signature = decode_signature(&sig_hex, "--signature", CMD)?;
    let signed_by = parse_signed_by(signed_by.as_ref(), CMD)?;
    let op = state::SubActorOp::new(state::SubActorOpParams {
        root_did,
        tag,
        index,
        control_key,
        operating_key,
        new_root,
        consistency_proof,
        inclusion_proof,
        signature,
        signed_by,
    });
    submit_payload(&socket, &control::sub_actor_op_payload(&op)).await?;
    tracing::info!(socket = %socket.display(), "sub-actor queued");
    Ok(())
}

/// `jkaind tx rebind`: submits a `RebindOp` (`0x05`) transaction to a running
/// node, rotating a sub-actor's operating key under root control.
async fn tx_rebind(args: &[String]) -> Result<()> {
    const CMD: &str = "tx rebind";
    let mut socket = default_socket();
    let mut id_flags = RootIdFlags { network: None, alias: None, uuid_hex: None };
    let mut tag: Option<String> = None;
    let mut index: Option<String> = None;
    let mut new_key_hex: Option<String> = None;
    let mut pop_hex: Option<String> = None;
    let mut auth_hex: Option<String> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            "--network" => id_flags.network = Some(next_value(args, &mut i, "--network")?),
            "--alias" => id_flags.alias = Some(next_value(args, &mut i, "--alias")?),
            "--uuid" => id_flags.uuid_hex = Some(next_value(args, &mut i, "--uuid")?),
            "--tag" => tag = Some(next_value(args, &mut i, "--tag")?),
            "--index" => index = Some(next_value(args, &mut i, "--index")?),
            "--new-operating-key" => {
                new_key_hex = Some(next_value(args, &mut i, "--new-operating-key")?);
            }
            "--proof-of-possession" => {
                pop_hex = Some(next_value(args, &mut i, "--proof-of-possession")?);
            }
            "--authorizing-signature" => {
                auth_hex = Some(next_value(args, &mut i, "--authorizing-signature")?);
            }
            other => bail!("tx rebind: unknown argument '{other}'"),
        }
    }
    let root_did = parse_root_did(CMD, &id_flags)?;
    let tag_value =
        tag.with_context(|| format!("{CMD}: --tag <defi|messenger|game|generic> is required"))?;
    let tag = parse_tag(&tag_value, CMD)?;
    let index = parse_index(index.as_ref(), CMD)?;
    let key_hex =
        new_key_hex.with_context(|| format!("{CMD}: --new-operating-key <64 hex> is required"))?;
    let new_operating_key = decode_verifying_key(&key_hex, "--new-operating-key", CMD)?;
    let pop_value =
        pop_hex.with_context(|| format!("{CMD}: --proof-of-possession <128 hex> is required"))?;
    let proof_of_possession = decode_signature(&pop_value, "--proof-of-possession", CMD)?;
    let auth_value = auth_hex
        .with_context(|| format!("{CMD}: --authorizing-signature <128 hex> is required"))?;
    let authorizing_signature = decode_signature(&auth_value, "--authorizing-signature", CMD)?;
    let actor_id = state::ActorId::Sub { root_did, tag, index };
    let op = state::RebindOp::new(
        actor_id,
        new_operating_key,
        proof_of_possession,
        authorizing_signature,
    );
    submit_payload(&socket, &control::rebind_op_payload(&op)).await?;
    tracing::info!(socket = %socket.display(), "rebind queued");
    Ok(())
}

/// `jkaind add-member`: submits a `MembershipOp::Add` transaction to a running
/// node. The `--key` hex is the new member's Ed25519 verifying key (printed by
/// `jkaind member init`). `--bls-key` and one of `--bls-secret` or `--pop`
/// are required for the BLS proof-of-possession. After the op is ordered and
/// activated, the existing cluster can gossip with the new node; the new node
/// itself is provisioned by `member init` and its own local `cluster.toml`.
pub(crate) async fn add_member(args: &[String]) -> Result<()> {
    let mut socket = default_socket();
    let mut node_id: Option<u64> = None;
    let mut gossip: Option<SocketAddr> = None;
    let mut reconnect: Option<SocketAddr> = None;
    let mut key_hex: Option<String> = None;
    let mut bls_key_hex: Option<String> = None;
    let mut bls_secret_path: Option<PathBuf> = None;
    let mut pop_hex: Option<String> = None;
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
            "--bls-key" => bls_key_hex = Some(next_value(args, &mut i, "--bls-key")?),
            "--bls-secret" => {
                bls_secret_path = Some(PathBuf::from(next_value(args, &mut i, "--bls-secret")?));
            }
            "--pop" => pop_hex = Some(next_value(args, &mut i, "--pop")?),
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
    let bls_key_hex = bls_key_hex.context("add-member: --bls-key <96 hex chars> is required")?;
    let bls_key = crate::config::decode_bls_hex(&bls_key_hex)
        .context("add-member: --bls-key must be 96 hex chars (48 bytes)")?;

    let has_bls_secret = bls_secret_path.is_some();
    let has_pop = pop_hex.is_some();
    if has_bls_secret == has_pop {
        bail!(
            "add-member: exactly one of --bls-secret <path> or --pop <hex> is required when --bls-key is present"
        );
    }
    let pop: [u8; 96] = if let Some(path) = bls_secret_path {
        let ikm_bytes = std::fs::read(&path)
            .with_context(|| format!("add-member: reading --bls-secret {}", path.display()))?;
        if ikm_bytes.len() != 32 {
            bail!(
                "add-member: --bls-secret file must be exactly 32 bytes (IKM), got {}",
                ikm_bytes.len()
            );
        }
        let ikm: [u8; 32] = ikm_bytes.try_into().expect("32 bytes");
        let identity = crypto::BlsIdentity::from_ikm(&ikm)
            .context("add-member: --bls-secret is not a valid BLS IKM")?;
        let derived_bls = identity.public.to_bytes();
        if derived_bls != bls_key {
            bail!(
                "add-member: --bls-secret derives a different bls_key than --bls-key (cross-check failed)"
            );
        }
        crypto::sign_pop(&identity).to_bytes()
    } else {
        let hex = pop_hex.expect("one pop source required");
        let bytes =
            crate::config::decode_hex_bytes(&hex).context("add-member: --pop must be hex")?;
        if bytes.len() != 96 {
            bail!("add-member: --pop must be 192 hex chars (96 bytes), got {} bytes", bytes.len());
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        arr
    };

    let op = MembershipOp::Add {
        node: NodeId::new(node_id),
        key: Box::new(key),
        bls_key,
        pop,
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
