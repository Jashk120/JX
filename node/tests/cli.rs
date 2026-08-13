//! CLI tests for `jkaind init`: secret/config generation, derivation
//! consistency, and overwrite protection.

use std::process::Command;

use ed25519_dalek::SigningKey;
use gossip::{
    PeerManager,
    TlsIdentity,
};
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

/// `jkaind member init` provisions a new member with a 32-byte single seed and
/// its own local cluster.toml (genesis + self). The critical assertion is the
/// exact bug this feature exists to prevent: an existing node pins a
/// runtime-added peer's TLS fingerprint by deriving it from the peer's
/// consensus key, so the new member's TLS identity must present exactly that
/// fingerprint. A test that merely checked "both secret lengths are accepted"
/// would pass even if the single-seed derivation were subtly wrong.
#[test]
fn member_init_single_seed_secret_pins_match_and_leaves_genesis_untouched() {
    let tmp = tempfile::tempdir().expect("temp dir");
    let genesis_out = tmp.path().join("genesis");
    assert!(init_args(&genesis_out, false).status().expect("genesis init").success());

    let member_out = tmp.path().join("member3");
    let status = Command::new(binary())
        .arg("member")
        .arg("init")
        .arg("--node-id")
        .arg("3")
        .arg("--gossip")
        .arg("203.0.113.7:7000")
        .arg("--reconnect")
        .arg("203.0.113.7:7001")
        .arg("--cluster")
        .arg(genesis_out.join("cluster.toml"))
        .arg("--out")
        .arg(&member_out)
        .status()
        .expect("member init runs");
    assert!(status.success(), "member init exits 0");

    // A dynamic member's secret is a single 32-byte seed.
    let secret = std::fs::read(member_out.join("secret-3.bin")).expect("secret file");
    assert_eq!(secret.len(), 32, "single-seed secret is 32 bytes");
    let seed: [u8; 32] = secret.try_into().expect("32 bytes");

    // Derive exactly like `jkaind run` does for a single-seed secret.
    let signing_key = SigningKey::from_bytes(&seed);
    let identity = TlsIdentity::from_seed(seed, 3).expect("identity builds");

    // The member's local cluster.toml (node-specific filename, so the shared
    // genesis cluster.toml can never be clobbered) lists genesis + itself, and
    // its own entry is self-consistent with the secret (so `run`'s sanity
    // checks pass).
    let config = ClusterConfigFile::load(&member_out.join("cluster-3.toml")).expect("loads");
    assert_eq!(config.members.len(), 3, "genesis 1,2 + new member 3");
    let member3 = config.member_for(3).expect("member 3 present");
    assert_eq!(
        decode_hex(&member3.verifying_key).expect("key hex"),
        signing_key.verifying_key().to_bytes(),
        "member 3's configured key matches its secret"
    );
    assert_eq!(
        decode_hex(&member3.spki_fingerprint).expect("fingerprint hex"),
        identity.spki_fingerprint(),
        "member 3's configured TLS pin matches its secret"
    );

    // THE EXACT BUG: a peer that node 1 (or 2) pins via add_peer_from_key
    // derives the SPKI fingerprint from node 3's consensus key. That pinned
    // value must equal node 3's actual TLS identity fingerprint, or node 1's
    // TLS connections to node 3 would always be rejected.
    let mut manager = PeerManager::new(Vec::new());
    assert!(manager.add_peer_from_key(
        NodeId::new(3),
        &signing_key.verifying_key(),
        member3.gossip_addr,
        member3.reconnect_addr,
    ));
    let peer = manager.peer(NodeId::new(3)).expect("peer pinned");
    assert_eq!(
        peer.expected_spki_fingerprint,
        identity.spki_fingerprint(),
        "existing-node TLS pin matches the new member's real certificate"
    );
    assert_eq!(
        peer.reconnect_addr, member3.reconnect_addr,
        "the pinned peer carries the new member's reconnect address"
    );

    // The shared genesis cluster.toml must NOT be rewritten by member init.
    let genesis =
        ClusterConfigFile::load(&genesis_out.join("cluster.toml")).expect("genesis loads");
    assert_eq!(genesis.members.len(), 2, "genesis cluster.toml stays the original snapshot");
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
