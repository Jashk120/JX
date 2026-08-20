//! Unix-socket control plane for a running `jkaind` node.
//!
//! `jkaind run` opens a Unix domain socket (default `<data>/jkaind.sock`,
//! mode `0600`) and serves line-delimited JSON requests, one request line in,
//! exactly one response line out. The client subcommands (`jkaind status`,
//! `jkaind tx`, `jkaind add-member`) are thin wrappers over the same
//! protocol, so a running node can be inspected and told to submit
//! transactions (KV ops and `MembershipOp::Add`) without a restart.
//!
//! The socket carries no secrets and no authentication beyond its `0600`
//! file permissions — the same trust model as the `secret-<id>.bin` files.

use std::path::Path;
use std::sync::Arc;

use anyhow::{
    Context,
    Result,
    bail,
};
use gossip::GossipNode;
use serde::{
    Deserialize,
    Serialize,
};
use serde_json::{
    Value,
    json,
};
use tokio::io::{
    AsyncBufReadExt,
    AsyncWriteExt,
    BufReader,
};
use tokio::net::{
    UnixListener,
    UnixStream,
};

use crate::config::{
    decode_hex_bytes,
    encode_hex,
};

/// One request line on the control socket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Cluster + node status snapshot.
    Status,
    /// The known peer set.
    Peers,
    /// Queues a raw transaction payload (hex) for consensus ordering.
    SubmitTx {
        /// Hex-encoded transaction payload.
        payload_hex: String,
    },
}

/// The single response line for a [`ControlRequest`].
#[derive(Debug, Serialize, Deserialize)]
pub struct ControlResponse {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// The `status` report: node identity, current roster, known peers, and the
/// ordering/checkpoint watermarks.
#[derive(Debug, Serialize, Deserialize)]
pub struct StatusReport {
    pub node_id: u64,
    pub members: Vec<MemberReport>,
    pub peers: Vec<PeerReport>,
    pub ordered_round: u64,
    pub decided_round: u64,
    pub latest_checkpoint_round: Option<u64>,
    /// The roster embedded in the highest accepted checkpoint. Differs from
    /// `members` when a node restored a checkpoint written under keys that no
    /// longer match the live registry — the silent-stall signal.
    pub checkpoint_roster: Vec<MemberReport>,
}

/// One consensus member in the `status` report.
#[derive(Debug, Serialize, Deserialize)]
pub struct MemberReport {
    pub node_id: u64,
    /// Hex-encoded Ed25519 verifying key.
    pub verifying_key: String,
}

/// One known peer in the `status` report.
#[derive(Debug, Serialize, Deserialize)]
pub struct PeerReport {
    pub node_id: u64,
    pub gossip_addr: String,
    pub reconnect_addr: Option<String>,
    /// Hex-encoded TLS SPKI fingerprint the peer is pinned to.
    pub spki_fingerprint: String,
}

/// Binds the control socket at `path`, replacing a stale socket file and
/// setting `0600` permissions. Callers should remove the socket file on
/// shutdown (a fresh `bind` on the same path removes it anyway).
pub async fn bind(path: &Path) -> Result<UnixListener> {
    if path.exists() {
        std::fs::remove_file(path)
            .with_context(|| format!("removing stale control socket {}", path.display()))?;
    }
    let listener = UnixListener::bind(path)
        .with_context(|| format!("binding control socket {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("chmod control socket {}", path.display()))?;
    }
    Ok(listener)
}

/// Runs the control server until `stop` is set. Each accepted connection is
/// handled on its own task; a malformed request gets an error response rather
/// than closing the connection.
pub async fn serve(
    listener: UnixListener,
    node: Arc<GossipNode>,
    stop: Arc<std::sync::atomic::AtomicBool>,
) {
    loop {
        if stop.load(std::sync::atomic::Ordering::Acquire) {
            break;
        }
        let (stream, _) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                eprintln!("control accept error: {e}");
                continue;
            }
        };
        let node = node.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, node).await {
                eprintln!("control connection error: {e}");
            }
        });
    }
}

/// Sends one [`ControlRequest`] to the daemon and returns its response.
pub async fn request(socket_path: &Path, request: &ControlRequest) -> Result<ControlResponse> {
    let mut stream = UnixStream::connect(socket_path)
        .await
        .with_context(|| format!("connecting to control socket {}", socket_path.display()))?;
    let mut payload = serde_json::to_vec(request).context("serializing control request")?;
    payload.push(b'\n');
    stream
        .write_all(&payload)
        .await
        .with_context(|| format!("writing to control socket {}", socket_path.display()))?;
    stream.flush().await.context("flushing control request")?;
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.context("reading control response")?;
    serde_json::from_str(&line).context("parsing control response")
}

async fn handle_connection(stream: UnixStream, node: Arc<GossipNode>) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Some(line) = lines.next_line().await? {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let request: ControlRequest = match serde_json::from_str(line) {
            Ok(request) => request,
            Err(e) => {
                let response = error_response(format!("malformed request: {e}"));
                write_response(&mut write_half, &response).await?;
                continue;
            }
        };
        let response = dispatch(request, &node).await;
        write_response(&mut write_half, &response).await?;
    }
    Ok(())
}

async fn write_response(
    write_half: &mut tokio::net::unix::OwnedWriteHalf,
    response: &ControlResponse,
) -> Result<()> {
    let mut payload = serde_json::to_vec(response).context("serializing control response")?;
    payload.push(b'\n');
    write_half.write_all(&payload).await.context("writing control response")?;
    write_half.flush().await.context("flushing control response")
}

async fn dispatch(request: ControlRequest, node: &GossipNode) -> ControlResponse {
    match request {
        ControlRequest::Status => status_response(node).await,
        ControlRequest::Peers => peers_response(node).await,
        ControlRequest::SubmitTx { payload_hex } => submit_tx(node, &payload_hex).await,
    }
}

async fn status_response(node: &GossipNode) -> ControlResponse {
    let node_id = node.node_id.get();
    let peers = node.peers().await;
    let (ordered_round, decided_round) = {
        let hg = node.hashgraph.lock().await;
        (hg.max_ordered_round(), hg.highest_decided_round())
    };
    // The live member set (structural, matching `is_consensus_member`): a
    // member shows up here as soon as its add op activates, consistent with
    // the peer list. A round-indexed roster lookup would lag by the one round
    // the new roster is scheduled to activate.
    let members = node
        .members()
        .await
        .into_iter()
        .map(|(id, key)| MemberReport {
            node_id: id.get(),
            verifying_key: encode_hex(&key.to_bytes()),
        })
        .collect();
    let peers = peers
        .into_iter()
        .map(|peer| PeerReport {
            node_id: peer.node_id.get(),
            gossip_addr: peer.addr.to_string(),
            reconnect_addr: peer.reconnect_addr.map(|addr| addr.to_string()),
            spki_fingerprint: encode_hex(&peer.expected_spki_fingerprint),
        })
        .collect();
    let latest_checkpoint_round = node.latest_accepted_checkpoint_round().await;
    let checkpoint_roster = match node.latest_signed_checkpoint().await {
        Some(checkpoint) => checkpoint
            .payload
            .roster_snapshot
            .member_ids()
            .into_iter()
            .filter_map(|id| {
                let key = checkpoint.payload.roster_snapshot.key_for(&id).ok()?;
                Some(MemberReport { node_id: id.get(), verifying_key: encode_hex(&key.to_bytes()) })
            })
            .collect(),
        None => Vec::new(),
    };
    ok_response(json!(StatusReport {
        node_id,
        members,
        peers,
        ordered_round,
        decided_round,
        latest_checkpoint_round,
        checkpoint_roster,
    }))
}

async fn peers_response(node: &GossipNode) -> ControlResponse {
    let peers = node
        .peers()
        .await
        .into_iter()
        .map(|peer| {
            json!({
                "node_id": peer.node_id.get(),
                "gossip_addr": peer.addr.to_string(),
                "reconnect_addr": peer.reconnect_addr.map(|addr| addr.to_string()),
                "spki_fingerprint": encode_hex(&peer.expected_spki_fingerprint),
            })
        })
        .collect::<Vec<_>>();
    ok_response(json!({ "peers": peers }))
}

async fn submit_tx(node: &GossipNode, payload_hex: &str) -> ControlResponse {
    let payload = match decode_hex_bytes(payload_hex) {
        Some(payload) => payload,
        None => {
            return error_response("payload_hex is not valid hex".to_string());
        }
    };
    node.submit_transaction(payload).await;
    ok_response(json!({ "queued": true }))
}

fn ok_response(result: Value) -> ControlResponse {
    ControlResponse { ok: true, result: Some(result), error: None }
}

fn error_response(error: String) -> ControlResponse {
    ControlResponse { ok: false, result: None, error: Some(error) }
}

/// The payload encoding that wraps a [`crypto::MembershipOp`] in the `0x02`
/// transaction tag the executor recognizes (`state::DecodedOp::Membership`).
/// Shared by the `add-member` CLI and tests so the wire bytes are always
/// produced in one place.
pub fn membership_op_payload(op: &crypto::MembershipOp) -> Vec<u8> {
    let mut payload = vec![0x02];
    payload.extend_from_slice(&op.encode());
    payload
}

/// The payload encoding for a [`state::Op`] KV transaction.
pub fn kv_op_payload(op: &state::Op) -> Vec<u8> {
    op.encode()
}

// --- errors -----------------------------------------------------------------

/// Convenience for client code: `bail!`s unless the response says `ok`.
pub fn ensure_ok(response: &ControlResponse) -> Result<()> {
    if response.ok {
        Ok(())
    } else {
        bail!("control request failed: {}", response.error.as_deref().unwrap_or("unknown error"))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{
        AtomicBool,
        Ordering,
    };

    use crypto::{
        MembershipOp,
        MembershipRegistry,
    };
    use ed25519_dalek::SigningKey;
    use primitives::NodeId;
    use tokio::io::{
        AsyncBufReadExt,
        AsyncWriteExt,
        BufReader,
    };
    use tokio::net::UnixStream;

    use super::*;

    fn test_node() -> Arc<GossipNode> {
        let seed = [7u8; 32];
        let mut registry = MembershipRegistry::new();
        registry.register(NodeId::new(1), SigningKey::from_bytes(&seed).verifying_key());
        Arc::new(GossipNode::new(
            NodeId::new(1),
            SigningKey::from_bytes(&seed),
            registry,
            gossip::TlsIdentity::from_seed(seed, 1).expect("identity builds"),
            Vec::new(),
            gossip::SyncTiming::new(test_support::SYNC_INTERVAL, test_support::SYNC_TIMEOUT),
            temp_state_db(),
        ))
    }

    fn temp_state_db() -> Arc<state::StateDb> {
        let dir = tempfile::tempdir().expect("temp dir");
        Arc::new(state::StateDb::open(dir.path()).expect("state db opens"))
    }

    async fn serve_on(path: &Path, node: Arc<GossipNode>) -> Arc<AtomicBool> {
        let listener = UnixListener::bind(path).expect("bind control socket");
        let stop = Arc::new(AtomicBool::new(false));
        let serve_stop = stop.clone();
        let serve_node = node.clone();
        tokio::spawn(async move {
            serve(listener, serve_node, serve_stop).await;
        });
        stop
    }

    #[tokio::test]
    async fn status_request_reports_members_and_peers() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ctl.sock");
        let stop = serve_on(&path, test_node()).await;

        let response = request(&path, &ControlRequest::Status).await.expect("request");
        assert!(response.ok, "status ok: {:?}", response.error);
        let report: StatusReport =
            serde_json::from_value(response.result.expect("result")).expect("parse");
        assert_eq!(report.node_id, 1);
        assert_eq!(report.members.len(), 1);
        assert_eq!(report.members[0].node_id, 1);
        assert!(report.peers.is_empty());

        stop.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn submit_tx_queues_payload_and_rejects_bad_hex() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ctl.sock");
        let stop = serve_on(&path, test_node()).await;

        let payload = state::Op::Put { key: b"k".to_vec(), value: b"v".to_vec() }.encode();
        let ok = request(
            &path,
            &ControlRequest::SubmitTx { payload_hex: crate::config::encode_hex(&payload) },
        )
        .await
        .expect("request");
        assert!(ok.ok, "valid hex is queued: {:?}", ok.error);

        let bad = request(&path, &ControlRequest::SubmitTx { payload_hex: "zz".to_string() })
            .await
            .expect("request");
        assert!(!bad.ok, "invalid hex is rejected");

        stop.store(true, Ordering::Release);
    }

    #[tokio::test]
    async fn malformed_request_line_gets_an_error_response() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("ctl.sock");
        let stop = serve_on(&path, test_node()).await;

        let mut stream = UnixStream::connect(&path).await.expect("connect");
        stream.write_all(b"{not json}\n").await.expect("write");
        stream.flush().await.expect("flush");
        let mut reader = BufReader::new(stream);
        let mut line = String::new();
        reader.read_line(&mut line).await.expect("read");
        let response: ControlResponse = serde_json::from_str(&line).expect("response parses");
        assert!(!response.ok);
        assert!(response.error.expect("error").contains("malformed request"));

        stop.store(true, Ordering::Release);
    }

    #[test]
    fn membership_op_payload_matches_executor_encoding() {
        let op = MembershipOp::Add {
            node: NodeId::new(3),
            key: Box::new(SigningKey::from_bytes(&[3u8; 32]).verifying_key()),
            addr: "127.0.0.1:7000".parse().expect("addr"),
            reconnect_addr: Some("127.0.0.1:7001".parse().expect("addr")),
        };
        let payload = membership_op_payload(&op);
        assert_eq!(payload[0], 0x02, "executor's membership tag");
        assert_eq!(
            state::DecodedOp::decode(&payload),
            Ok(state::DecodedOp::Membership(op)),
            "payload decodes to the same op on the executor side"
        );
    }
}
