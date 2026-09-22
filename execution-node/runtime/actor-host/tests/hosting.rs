use std::sync::OnceLock;

use actor_host::{
    ActorManifest,
    ActorStatus,
    Runtime,
};

fn echo_wasm_bytes() -> &'static [u8] {
    static CACHE: OnceLock<Vec<u8>> = OnceLock::new();
    CACHE.get_or_init(|| {
        let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let echo_dir = manifest_dir.join("../../actors/echo");
        let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_owned());
        let status = std::process::Command::new(cargo)
            .args(["build", "--release", "--target", "wasm32-wasip2", "--manifest-path"])
            .arg(echo_dir.join("Cargo.toml"))
            .status()
            .expect("spawn cargo to build the echo guest");
        assert!(status.success(), "echo guest build failed: {status}");
        std::fs::read(echo_dir.join("target/wasm32-wasip2/release/echo_actor.wasm"))
            .expect("read echo_actor.wasm")
    })
}

fn echo_actor_id() -> state::ActorId {
    let did = state::DidId::new("mainnet".to_owned(), "echo".to_owned(), [7u8; 16])
        .expect("fixed test DID is valid");
    state::ActorId::Root(did)
}

#[test]
fn load_and_dispatch_echo_roundtrip() {
    let wasm = echo_wasm_bytes();
    let id = echo_actor_id();
    let mut runtime = Runtime::new().expect("Runtime::new succeeds");
    let manifest = ActorManifest::new(id.clone(), "echo");
    runtime.load(manifest, wasm).expect("load echo component succeeds");
    assert_eq!(runtime.status(&id), Some(ActorStatus::Loaded), "echo actor is loaded");
    let reply = runtime.dispatch(&id, b"ping").expect("dispatch to echo succeeds");
    assert_eq!(reply, b"ping", "echo actor returns the request bytes");
}

#[test]
fn dispatch_unknown_actor_errors() {
    let id = echo_actor_id();
    let mut runtime = Runtime::new().expect("Runtime::new succeeds");
    let err = runtime.dispatch(&id, b"ping").expect_err("unknown actor must fail");
    assert!(!err.to_string().is_empty(), "error message is non-empty");
}
