//! CLI tests for `jkaind init`: secret/config generation, derivation
//! consistency, and overwrite protection.

use std::process::Command;

use ed25519_dalek::SigningKey;
use gossip::TlsIdentity;
use node::config::{
    ClusterConfigFile,
    MemberFile,
    decode_hex,
};
use primitives::NodeId;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_jkaind")
}

fn init_args(out: &std::path::Path, force: bool) -> Command {
    let mut cmd = Command::new(binary());
    cmd.arg("init")
        .arg("--member")
        .arg("1:127.0.0.1:7000:127.0.0.1:7001")
        .arg("--member")
        .arg("2:127.0.0.1:8000:127.0.0.1:8001")
        .arg("--out")
        .arg(out);
    if force {
        cmd.arg("--force");
    }
    cmd
}

#[test]
fn init_writes_config_and_secrets_consistent_with_derivation() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let out = tmp.path().join("cluster");

    let status = init_args(&out, false).status().expect("init runs");
    assert!(status.success(), "init exits 0");

    let config_path = out.join("cluster.toml");
    let config = ClusterConfigFile::load(&config_path).expect("cluster.toml loads");
    assert_eq!(config.members.len(), 2);
    assert_eq!(config.member_for(1).map(|m| m.node_id), Some(1));
    assert_eq!(config.member_for(2).map(|m| m.node_id), Some(2));

    // Each secret must be 64 bytes (consensus seed ‖ TLS seed) and derive the
    // exact verifying_key and SPKI fingerprint the config declares — the same
    // cross-check `jkaind run` performs.
    for member in &config.members {
        let secret = std::fs::read(out.join(format!("secret-{}.bin", member.node_id)))
            .expect("secret file exists");
        assert_eq!(secret.len(), 64, "secret is 64 bytes");
        let signing_key = SigningKey::from_bytes(secret[..32].try_into().expect("seed"));
        let identity =
            TlsIdentity::from_seed(secret[32..].try_into().expect("tls seed"), member.node_id)
                .expect("identity builds");
        assert_eq!(
            decode_hex(&member.verifying_key).expect("key hex"),
            signing_key.verifying_key().to_bytes(),
            "verifying_key matches secret for node {}",
            member.node_id
        );
        assert_eq!(
            decode_hex(&member.spki_fingerprint).expect("fingerprint hex"),
            identity.spki_fingerprint(),
            "spki_fingerprint matches secret for node {}",
            member.node_id
        );
    }

    // The config converts cleanly into the gossip-layer cluster config.
    let cluster = config.to_cluster_config().expect("converts");
    assert!(cluster.registry().key_for(&NodeId::new(1)).is_ok());
    assert!(cluster.registry().key_for(&NodeId::new(2)).is_ok());
}

#[test]
fn init_refuses_to_overwrite_secrets_without_force() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let out = tmp.path().join("cluster");

    assert!(init_args(&out, false).status().expect("first init").success());
    let secret_before = std::fs::read(out.join("secret-1.bin")).expect("secret 1");

    // A second run must refuse to overwrite existing secrets.
    let status = init_args(&out, false).status().expect("second init");
    assert!(!status.success(), "init refuses overwrite without --force");
    let secret_after = std::fs::read(out.join("secret-1.bin")).expect("secret 1 still there");
    assert_eq!(secret_before, secret_after, "secret untouched without --force");

    // With --force it regenerates.
    let status = init_args(&out, true).status().expect("forced init");
    assert!(status.success(), "init with --force succeeds");
}

#[test]
fn init_rejects_bad_member_spec() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let out = tmp.path().join("cluster");
    let status = Command::new(binary())
        .arg("init")
        .arg("--member")
        .arg("not-a-member")
        .arg("--out")
        .arg(&out)
        .status()
        .expect("init runs");
    assert!(!status.success(), "malformed --member is rejected");
}

/// Derivation from a fixed secret is deterministic: the same seed always
/// yields the same key and fingerprint, and `MemberFile` hex round-trips them.
#[test]
fn derivation_from_fixed_secret_is_stable_and_round_trips() {
    let secret = [7u8; 64];
    let key = SigningKey::from_bytes(secret[..32].try_into().expect("seed"));
    let identity = TlsIdentity::from_seed(secret[32..].try_into().expect("tls seed"), 1)
        .expect("identity builds");

    let again_key = SigningKey::from_bytes(secret[..32].try_into().expect("seed"));
    let again_identity = TlsIdentity::from_seed(secret[32..].try_into().expect("tls seed"), 1)
        .expect("identity builds");
    assert_eq!(again_key.verifying_key().to_bytes(), key.verifying_key().to_bytes());
    assert_eq!(again_identity.spki_fingerprint(), identity.spki_fingerprint());

    let member = MemberFile::new(
        1,
        "127.0.0.1:7000".parse().expect("addr"),
        "127.0.0.1:7001".parse().expect("addr"),
        &key.verifying_key(),
        identity.spki_fingerprint(),
    );
    assert_eq!(decode_hex(&member.verifying_key).expect("key hex"), key.verifying_key().to_bytes());
    assert_eq!(
        decode_hex(&member.spki_fingerprint).expect("fingerprint hex"),
        identity.spki_fingerprint()
    );
}
