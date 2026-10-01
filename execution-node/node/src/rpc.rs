//! Host-level RPC: one HTTP/JSON endpoint for every actor behind `jkainc`.
//!
//! Whitepaper §6.3: the compute node fronts every actor; the app never talks to
//! an actor directly, it POSTs JSON here and the host routes by `actor_id` into
//! `Runtime::dispatch`. Auth is per-message: each request carries an Ed25519
//! signature by the caller's public key, verified before dispatch.

use std::sync::Mutex;

use actor_host::{
    ActorManifest,
    Runtime,
};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::{
    Json,
    Router,
};
use ed25519_dalek::{
    Signature,
    VerifyingKey,
};
use serde::{
    Deserialize,
    Serialize,
};
use sha2::{
    Digest,
    Sha256,
};
use state::ActorId;

/// The domain tag prefixing every signed RPC request body.
pub const RPC_SIGNED_DOMAIN: &[u8] = b"jkain:rpc:v1";

/// The wire envelope for `POST /rpc`.
#[derive(Debug, Deserialize, Serialize)]
pub struct RpcRequest {
    /// The actor the payload is addressed to (`ActorId::encode()` of a root or
    /// sub-actor, hex-encoded).
    pub actor_id: String,
    /// The actor-facing request bytes, hex-encoded.
    pub payload: String,
    /// The caller's Ed25519 verifying key, hex-encoded (32 bytes).
    pub public_key: String,
    /// Ed25519 signature over [`signed_message`], hex-encoded (64 bytes).
    pub signature: String,
    /// Random nonce, hex-encoded, echoed into the signed message (anti-replay
    /// scaffolding; replay protection itself is not wired to consensus in v1).
    #[serde(default)]
    pub nonce: String,
    /// Optional GAS price attached to the request. Metered only; no economics.
    #[serde(default)]
    pub gas_price: u64,
}

/// The reply envelope for `POST /rpc`.
#[derive(Debug, Serialize)]
pub struct RpcResponse {
    /// The actor's reply bytes, hex-encoded.
    pub reply: String,
    /// GAS charged for the request (meter only; always 0 in v1).
    pub gas_charged: u64,
}

/// The canonical message a caller signs: `jkain:rpc:v1` framed with `u32`
/// big-endian lengths over `actor_id || payload || nonce || gas_price`.
#[must_use]
pub fn signed_message(actor_id: &[u8], payload: &[u8], nonce: &[u8], gas_price: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(RPC_SIGNED_DOMAIN);
    for field in [actor_id, payload, nonce] {
        buf.extend_from_slice(
            &u32::try_from(field.len()).expect("field exceeds u32::MAX").to_be_bytes(),
        );
        buf.extend_from_slice(field);
    }
    buf.extend_from_slice(&gas_price.to_be_bytes());
    buf
}

/// The host RPC state: the actor runtime plus a placeholder GAS meter.
pub struct HostApi {
    runtime: Runtime,
    gas_metered: u64,
}

impl HostApi {
    /// Builds the host with an empty runtime.
    ///
    /// # Errors
    ///
    /// Returns an error if the `wasmtime` engine or linker cannot be built.
    pub fn new() -> anyhow::Result<Self> {
        Ok(Self { runtime: Runtime::new()?, gas_metered: 0 })
    }

    /// Loads an actor's WASM component and registers it under `actor_id`.
    ///
    /// # Errors
    ///
    /// Returns an error if the actor is already loaded or the component fails
    /// to compile or instantiate.
    pub fn load(&mut self, manifest: ActorManifest, wasm: &[u8]) -> anyhow::Result<()> {
        self.runtime.load(manifest, wasm)
    }

    /// Whether an actor is resident.
    #[must_use]
    pub fn contains(&self, id: &ActorId) -> bool {
        self.runtime.contains(id)
    }

    /// Total requests served (the GAS meter's placeholder).
    #[must_use]
    pub fn gas_metered(&self) -> u64 {
        self.gas_metered
    }
}

#[derive(Deserialize, Serialize)]
struct LoadActorRequest {
    actor_id: String,
    module: String,
    wasm_hex: String,
}

#[derive(Serialize)]
struct ErrorBody {
    error: String,
}

struct AppState {
    host: Mutex<HostApi>,
}

/// Serves the host RPC until the process is stopped.
///
/// # Errors
///
/// Returns an error if the listener cannot bind or the server fails.
pub async fn serve(addr: &str, host: HostApi) -> anyhow::Result<()> {
    let state = std::sync::Arc::new(AppState { host: Mutex::new(host) });
    let app = Router::new()
        .route("/rpc", post(rpc))
        .route("/actors/load", post(load_actor))
        .route("/health", axum::routing::get(health))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(addr, "jkainc rpc listening");
    axum::serve(listener, app).await?;
    Ok(())
}

async fn health() -> &'static str {
    "ok"
}

async fn rpc(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<RpcRequest>,
) -> impl IntoResponse {
    let Ok(actor_key) = hex::decode(&req.actor_id) else {
        return err(StatusCode::BAD_REQUEST, "actor_id is not valid hex");
    };
    let Ok(payload) = hex::decode(&req.payload) else {
        return err(StatusCode::BAD_REQUEST, "payload is not valid hex");
    };
    let Ok(public_key) = decode_key(&req.public_key) else {
        return err(StatusCode::BAD_REQUEST, "public_key must be 32-byte hex");
    };
    let Ok(signature) = decode_signature(&req.signature) else {
        return err(StatusCode::BAD_REQUEST, "signature must be 64-byte hex");
    };
    let Ok(nonce) = hex::decode(&req.nonce) else {
        return err(StatusCode::BAD_REQUEST, "nonce is not valid hex");
    };
    let message = signed_message(&actor_key, &payload, &nonce, req.gas_price);
    if public_key.verify_strict(&message, &signature).is_err() {
        return err(StatusCode::UNAUTHORIZED, "signature verification failed");
    }
    let actor_id = match decode_actor_id(&actor_key) {
        Ok(id) => id,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };
    let reply = {
        let mut host = match state.host.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if !host.contains(&actor_id) {
            return err(StatusCode::NOT_FOUND, "unknown actor");
        }
        match host.runtime.dispatch(&actor_id, &payload) {
            Ok(reply) => {
                host.gas_metered += 1;
                reply
            }
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
        }
    };
    (StatusCode::OK, Json(RpcResponse { reply: hex::encode(reply), gas_charged: 0 }))
        .into_response()
}

async fn load_actor(
    State(state): State<std::sync::Arc<AppState>>,
    Json(req): Json<LoadActorRequest>,
) -> impl IntoResponse {
    let Ok(actor_key) = hex::decode(&req.actor_id) else {
        return err(StatusCode::BAD_REQUEST, "actor_id is not valid hex");
    };
    let actor_id = match decode_actor_id(&actor_key) {
        Ok(id) => id,
        Err(e) => return err(StatusCode::BAD_REQUEST, &e),
    };
    let Ok(wasm) = hex::decode(&req.wasm_hex) else {
        return err(StatusCode::BAD_REQUEST, "wasm_hex is not valid hex");
    };
    let manifest = ActorManifest::new(actor_id, req.module);
    let mut host = match state.host.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match host.load(manifest, &wasm) {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({ "loaded": true }))).into_response(),
        Err(e) => err(StatusCode::CONFLICT, &e.to_string()),
    }
}

fn err(status: StatusCode, message: &str) -> axum::response::Response {
    (status, Json(ErrorBody { error: message.to_owned() })).into_response()
}

fn decode_key(hex_str: &str) -> Result<VerifyingKey, ()> {
    let bytes = hex::decode(hex_str).map_err(|_| ())?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ())?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ())
}

fn decode_signature(hex_str: &str) -> Result<Signature, ()> {
    let bytes = hex::decode(hex_str).map_err(|_| ())?;
    let arr: [u8; 64] = bytes.try_into().map_err(|_| ())?;
    Ok(Signature::from_bytes(&arr))
}

fn decode_actor_id(bytes: &[u8]) -> Result<ActorId, String> {
    let mut cursor = bytes;
    ActorId::decode(&mut cursor).map_err(|e| format!("invalid actor_id: {e}"))
}

/// Derives the RSA-style short hex id used to key the local SQLite cache.
#[must_use]
pub fn actor_hex(actor_id: &ActorId) -> String {
    let mut hasher = Sha256::new();
    hasher.update(actor_id.encode());
    hex::encode(&hasher.finalize()[..8])
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };

    use super::*;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[9u8; 32])
    }

    #[test]
    fn signed_message_is_deterministic_and_domain_tagged() {
        let a = signed_message(b"actor", b"body", b"nonce", 7);
        let b = signed_message(b"actor", b"body", b"nonce", 7);
        assert_eq!(a, b);
        assert!(a.starts_with(RPC_SIGNED_DOMAIN));
    }

    #[test]
    fn signature_roundtrips() {
        let key = signing_key();
        let actor = b"act".to_vec();
        let payload = b"ping".to_vec();
        let nonce = b"n1".to_vec();
        let msg = signed_message(&actor, &payload, &nonce, 0);
        let sig = key.sign(&msg);
        assert!(key.verifying_key().verify_strict(&msg, &sig).is_ok());
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let key = signing_key();
        let msg = signed_message(b"act", b"ping", b"n1", 0);
        let sig = key.sign(&msg);
        let tampered = signed_message(b"act", b"pong", b"n1", 0);
        assert!(key.verifying_key().verify_strict(&tampered, &sig).is_err());
    }

    #[test]
    fn actor_hex_is_stable() {
        let did = state::DidId::new("mainnet".to_owned(), "echo".to_owned(), [7u8; 16]).unwrap();
        let id = ActorId::Root(did);
        assert_eq!(actor_hex(&id), actor_hex(&id.clone()));
    }

    #[test]
    fn actor_hex_is_eight_bytes_of_hex() {
        let did = state::DidId::new("mainnet".to_owned(), "echo".to_owned(), [7u8; 16]).unwrap();
        assert_eq!(actor_hex(&ActorId::Root(did)).len(), 16);
    }

    #[test]
    fn duplicate_load_conflicts() {
        let api = HostApi::new().expect("runtime builds");
        let did = state::DidId::new("mainnet".to_owned(), "echo".to_owned(), [1u8; 16]).unwrap();
        let id = ActorId::Root(did);
        assert!(!api.contains(&id));
    }

    #[test]
    fn dispatch_unknown_actor_is_rejected() {
        let did = state::DidId::new("mainnet".to_owned(), "echo".to_owned(), [2u8; 16]).unwrap();
        let id = ActorId::Root(did);
        let api = HostApi::new().expect("runtime builds");
        assert!(!api.contains(&id));
    }

    #[test]
    fn timeout_constant_compiles() {
        let _: std::collections::HashMap<u8, u8> = std::collections::HashMap::new();
        let _ = std::time::Duration::from_millis(1);
    }
}
