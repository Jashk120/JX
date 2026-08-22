//! One-command genesis cluster deployment over plain SSH.
//!
//! [`deploy_cmd`] implements `jkaind deploy genesis`: given a list of
//! `--member <id>=<[user@]host>[=<advertise-ip>]` targets it installs the
//! daemon binary, provisions the service user and directories, generates
//! every member's secret **on its own node** ([`keygen`] runs remotely, so a
//! secret never exists outside the machine it belongs to), assembles the
//! shared `cluster.toml` centrally from the returned public keys, pushes it,
//! installs a systemd unit mirroring `RUNBOOK.md`, optionally opens the mesh
//! firewall rules, starts every node, and waits until each control socket
//! answers.
//!
//! Only public key material travels over SSH and only the public
//! `cluster.toml` is kept locally under `--out`; post-genesis membership
//! changes remain consensus transactions (`jkaind add-member`), untouched by
//! this module.

use std::io::Write;
use std::net::{
    IpAddr,
    SocketAddr,
};
use std::path::{
    Path,
    PathBuf,
};
use std::process::{
    Command,
    Stdio,
};
use std::time::{
    Duration,
    Instant,
};
use std::{
    fs,
    thread,
};

use anyhow::{
    Context,
    Result,
    bail,
};
use ed25519_dalek::{
    SigningKey,
    VerifyingKey,
};
use gossip::TlsIdentity;
use rand::RngCore;
use rand::rngs::OsRng;

use crate::config::{
    ClusterConfigFile,
    MemberFile,
    decode_hex,
    encode_hex,
};

/// Genesis secrets use the unified single-seed format: 32 bytes seed both
/// consensus signing and TLS identity, exactly like `jkaind member init`.
const GENESIS_SEED_LEN: usize = 32;

/// Default gossip port for deployed members.
pub const DEFAULT_GOSSIP_PORT: u16 = 7000;

/// Default reconnect port for deployed members.
pub const DEFAULT_RECONNECT_PORT: u16 = 7001;

/// Remote directory holding `cluster.toml` and the per-node secret files.
pub const DEFAULT_CONFIG_DIR: &str = "/etc/jkaind";

/// Remote checkpoint/state directory handed to `jkaind run --data`.
pub const DEFAULT_DATA_DIR: &str = "/var/lib/jkaind";

/// Where the daemon binary is installed on every node.
pub const REMOTE_BINARY: &str = "/usr/local/bin/jkaind";

/// Systemd unit path written on every node.
const UNIT_PATH: &str = "/etc/systemd/system/jkaind.service";

/// Unprivileged service account the units run under (mirrors `RUNBOOK.md`).
const SERVICE_USER: &str = "jkaind";

const SSH_OPTS: &[&str] = &["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"];

const HEALTH_TIMEOUT: Duration = Duration::from_secs(90);
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Machine-readable marker line printed by [`keygen`] on stdout.
const KEYGEN_LINE_PREFIX: &str = "JKAIN_KEYGEN ";

// --- entry points ------------------------------------------------------------

/// Routes `jkaind deploy ...`.
pub fn deploy_cmd(args: &[String]) -> Result<()> {
    let sub = args.first().context("deploy requires a subcommand: genesis")?;
    match sub.as_str() {
        "genesis" => run_genesis(parse_genesis_args(&args[1..])?),
        other => bail!("deploy: unknown subcommand '{other}' (expected 'genesis')"),
    }
}

/// `jkaind keygen`: generates one member's secret **on the machine running
/// this command** and prints `JKAIN_KEYGEN <verifying-key-hex>
/// <spki-fingerprint-hex>` on stdout for `deploy genesis` to collect. The
/// secret never appears in the output.
pub fn keygen(args: &[String]) -> Result<()> {
    let mut node_id: Option<u64> = None;
    let mut out_dir = PathBuf::from(DEFAULT_CONFIG_DIR);
    let mut force = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--node-id" => {
                let value = next_value(args, &mut i, "--node-id")?;
                node_id =
                    Some(value.parse().with_context(|| format!("invalid --node-id '{value}'"))?);
            }
            "--out" => out_dir = PathBuf::from(next_value(args, &mut i, "--out")?),
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!("keygen: unknown argument '{other}'"),
        }
    }
    let node_id = node_id.context("keygen: --node-id <id> is required")?;

    let secret_path = out_dir.join(format!("secret-{node_id}.bin"));
    if secret_path.exists() && !force {
        bail!(
            "{} already exists; refusing to overwrite an existing secret \
             (pass --force only when regenerating a broken deployment)",
            secret_path.display()
        );
    }
    fs::create_dir_all(&out_dir)
        .with_context(|| format!("creating output dir {}", out_dir.display()))?;

    let (seed, verifying_key, fingerprint) = generate_member_material(node_id)?;
    write_secret_file(&secret_path, &seed)?;

    println!("{KEYGEN_LINE_PREFIX}{} {}", encode_hex(&verifying_key), encode_hex(&fingerprint));
    eprintln!(
        "keygen: wrote {} (mode 0600); only the public keys above were printed",
        secret_path.display()
    );
    Ok(())
}

// --- argument parsing --------------------------------------------------------

/// One `--member` target: `<id>=<[user@]host[:ssh-port]>[=<advertise-ip>]`.
///
/// `ssh_target` is passed verbatim to ssh/scp; `advertise` is the IP written
/// into `cluster.toml`. It defaults to the host part of the target, which
/// therefore must be an IP literal unless an explicit advertise address is
/// supplied (DNS names cannot appear in `cluster.toml` — same constraint as
/// `jkaind init`). Custom SSH users/ports are best expressed through the
/// operator's `~/.ssh/config` aliases; the inline `:port` suffix is supported
/// for convenience.
#[derive(Clone, Debug)]
pub struct MemberTarget {
    pub id: u64,
    pub ssh_target: String,
    pub advertise: IpAddr,
}

fn parse_member_spec(value: &str) -> Result<MemberTarget> {
    let mut parts = value.splitn(3, '=');
    let id_part = parts.next().context("member spec is empty")?;
    let id = id_part
        .parse()
        .with_context(|| format!("member '{value}' must start with <node-id>=, got '{id_part}'"))?;
    let ssh_target = parts
        .next()
        .filter(|t| !t.is_empty())
        .with_context(|| format!("member '{value}' is missing <[user@]host> after the id"))?
        .to_owned();
    let advertise = match parts.next() {
        Some(explicit) => explicit.parse().with_context(|| {
            format!("member '{value}' advertise address '{explicit}' is not an IP")
        })?,
        None => host_part(&ssh_target).parse().with_context(|| {
            format!(
                "member '{value}' host '{}' is not an IP literal; \
                     append '=<'advertise-ip>' to name the address for cluster.toml",
                host_part(&ssh_target)
            )
        })?,
    };
    Ok(MemberTarget { id, ssh_target, advertise })
}

/// The host portion of an ssh target: drops a leading `user@` and a trailing
/// numeric `:port`. IPv6 literals are not supported here (supply an explicit
/// advertise address instead); ssh config aliases resolve locally anyway.
fn host_part(ssh_target: &str) -> &str {
    let without_user = match ssh_target.rsplit_once('@') {
        Some((_, host)) => host,
        None => ssh_target,
    };
    match without_user.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => without_user,
    }
}

#[derive(Debug)]
struct GenesisPlan {
    members: Vec<MemberTarget>,
    /// Local binary pushed to `REMOTE_BINARY`; `None` skips installation.
    binary: Option<PathBuf>,
    gossip_port: u16,
    reconnect_port: u16,
    config_dir: String,
    data_dir: String,
    /// Local directory receiving the public `cluster.toml` copy.
    out_dir: PathBuf,
    ufw: bool,
    force: bool,
}

fn parse_genesis_args(args: &[String]) -> Result<GenesisPlan> {
    let mut members = Vec::new();
    let mut binary: Option<PathBuf> = None;
    let mut gossip_port = DEFAULT_GOSSIP_PORT;
    let mut reconnect_port: Option<u16> = None;
    let mut config_dir = DEFAULT_CONFIG_DIR.to_owned();
    let mut data_dir = DEFAULT_DATA_DIR.to_owned();
    let mut out_dir = PathBuf::from("./jkaind-deploy");
    let mut ufw = false;
    let mut force = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--member" => {
                let value = next_value(args, &mut i, "--member")?;
                members.push(parse_member_spec(&value)?);
            }
            "--binary" => binary = Some(PathBuf::from(next_value(args, &mut i, "--binary")?)),
            "--gossip-port" => {
                let value = next_value(args, &mut i, "--gossip-port")?;
                gossip_port = value.parse().context("--gossip-port must be 1-65535")?;
            }
            "--reconnect-port" => {
                let value = next_value(args, &mut i, "--reconnect-port")?;
                reconnect_port = Some(value.parse().context("--reconnect-port must be 1-65535")?);
            }
            "--config-dir" => config_dir = next_value(args, &mut i, "--config-dir")?,
            "--data-dir" => data_dir = next_value(args, &mut i, "--data-dir")?,
            "--out" => out_dir = PathBuf::from(next_value(args, &mut i, "--out")?),
            "--ufw" => {
                ufw = true;
                i += 1;
            }
            "--force" => {
                force = true;
                i += 1;
            }
            other => bail!("deploy genesis: unknown argument '{other}'"),
        }
    }

    if members.is_empty() {
        bail!("deploy genesis: at least one --member is required");
    }
    let mut seen = std::collections::HashSet::new();
    for member in &members {
        if !seen.insert(member.id) {
            bail!("deploy genesis: duplicate node id {}", member.id);
        }
    }

    Ok(GenesisPlan {
        members,
        binary,
        gossip_port,
        reconnect_port: reconnect_port.unwrap_or(gossip_port.saturating_add(1)),
        config_dir,
        data_dir,
        out_dir,
        ufw,
        force,
    })
}

// --- orchestration -----------------------------------------------------------

struct KeyMaterial {
    id: u64,
    verifying_key: VerifyingKey,
    spki_fingerprint: [u8; 32],
}

fn run_genesis(plan: GenesisPlan) -> Result<()> {
    println!(
        "deploy: {} member(s), gossip {}, reconnect {}, binary {}",
        plan.members.len(),
        plan.gossip_port,
        plan.reconnect_port,
        plan.binary
            .as_deref()
            .map_or_else(|| "<pre-installed>".into(), |p| p.display().to_string())
    );

    let mut materials = Vec::with_capacity(plan.members.len());
    for member in &plan.members {
        println!("==> [{}] provisioning node {}", member.ssh_target, member.id);
        if let Some(binary) = &plan.binary {
            install_binary(member, binary)
                .with_context(|| format!("node {}: installing binary", member.id))?;
        }
        prepare_host(&plan, member).with_context(|| {
            format!("node {}: creating service user and directories", member.id)
        })?;
        let material = keygen_remote(&plan, member)
            .with_context(|| format!("node {}: generating member keys", member.id))?;
        materials.push(material);
    }

    let config_path = assemble_config(&plan, &materials)?;
    println!("deploy: wrote public cluster config {}", config_path.display());

    for member in &plan.members {
        push_config(&plan, member)
            .with_context(|| format!("node {}: pushing cluster.toml", member.id))?;
        install_service(&plan, member)
            .with_context(|| format!("node {}: installing systemd unit", member.id))?;
    }
    for member in &plan.members {
        start_service(member)
            .with_context(|| format!("node {}: starting jkaind.service", member.id))?;
    }

    await_cluster_healthy(&plan)?;
    print_summary(&plan, &config_path);
    Ok(())
}

/// Copies the release binary to each node and installs it at
/// [`REMOTE_BINARY`].
fn install_binary(member: &MemberTarget, binary: &Path) -> Result<()> {
    let staging = format!("/tmp/jkaind.genesis.{}", member.id);
    scp_to(&member.ssh_target, binary, &staging)?;
    let script = format!(
        "install -m 0755 '{}' '{}' && rm -f '{}'",
        shell_quote(&staging),
        shell_quote(REMOTE_BINARY),
        shell_quote(&staging)
    );
    ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-c", &script], None).map(drop)
}

/// Idempotently creates the service account plus config/data directories.
fn prepare_host(plan: &GenesisPlan, member: &MemberTarget) -> Result<()> {
    let script = format!(
        "id '{user}' >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin '{user}'\n\
         install -d '{config_dir}'\n\
         install -d -o '{user}' -g '{user}' '{data_dir}'\n",
        user = shell_quote(SERVICE_USER),
        config_dir = shell_quote(&plan.config_dir),
        data_dir = shell_quote(&plan.data_dir),
    );
    ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-s"], Some(script.as_bytes())).map(drop)
}

/// Refuses unsafe pre-existing state, then runs [`keygen`] remotely and
/// collects the public keys it prints.
fn keygen_remote(plan: &GenesisPlan, member: &MemberTarget) -> Result<KeyMaterial> {
    let secret_path = format!("{}/secret-{}.bin", plan.config_dir, member.id);
    if !plan.force {
        let absent = format!("test ! -e '{}'", shell_quote(&secret_path));
        ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-c", &absent], None)
            .map(drop)
            .with_context(|| {
                format!(
                    "node {}: {} already exists; pass --force to regenerate \
                     (invalidates any checkpoints on this node)",
                    member.id, secret_path
                )
            })?;
        let checkpoints_dir = format!("{}/checkpoints", plan.data_dir);
        let no_checkpoints =
            format!("test -z \"$(ls -A '{}' 2>/dev/null)\"", shell_quote(&checkpoints_dir));
        ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-c", &no_checkpoints], None)
            .map(drop)
            .with_context(|| {
                format!(
                    "node {}: persisted checkpoints found under {}; a fresh genesis \
                     would silently conflict with them — wipe the data dir or pass --force",
                    member.id, plan.data_dir
                )
            })?;
    }

    let node_id = member.id.to_string();
    let stdout = ssh_capture(
        &member.ssh_target,
        &["sudo", "-n", REMOTE_BINARY, "keygen", "--node-id", &node_id, "--out", &plan.config_dir],
        None,
    )?;
    let (vk_hex, fp_hex) = parse_keygen_output(&stdout)
        .with_context(|| format!("node {}: unexpected keygen output", member.id))?;
    let chown = format!("chown '{SERVICE_USER}:{SERVICE_USER}' '{}'", shell_quote(&secret_path));
    ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-c", &chown], None).map(drop)?;

    let verifying_key_bytes = decode_hex(&vk_hex)
        .with_context(|| format!("node {}: keygen returned invalid verifying key", member.id))?;
    let verifying_key = VerifyingKey::from_bytes(&verifying_key_bytes)
        .map_err(|e| anyhow::anyhow!("node {}: invalid Ed25519 key: {e}", member.id))?;
    let spki_fingerprint = decode_hex(&fp_hex)
        .with_context(|| format!("node {}: keygen returned invalid SPKI fingerprint", member.id))?;
    Ok(KeyMaterial { id: member.id, verifying_key, spki_fingerprint })
}

/// Assembles the shared `cluster.toml` from the collected public keys and
/// writes the public copy under `--out` (secrets never exist locally).
fn assemble_config(plan: &GenesisPlan, materials: &[KeyMaterial]) -> Result<PathBuf> {
    let mut members = Vec::with_capacity(materials.len());
    for material in materials {
        let gossip_addr = advertise_addr(&material_advertise(plan, material)?, plan.gossip_port)?;
        let reconnect_addr =
            Some(advertise_addr(&material_advertise(plan, material)?, plan.reconnect_port)?);
        members.push(MemberFile::new(
            material.id,
            gossip_addr,
            reconnect_addr,
            &material.verifying_key,
            material.spki_fingerprint,
        ));
    }
    let config = ClusterConfigFile { members };
    fs::create_dir_all(&plan.out_dir)
        .with_context(|| format!("creating {}", plan.out_dir.display()))?;
    let path = plan.out_dir.join("cluster.toml");
    config.save(&path).with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

fn material_advertise(plan: &GenesisPlan, material: &KeyMaterial) -> Result<IpAddr> {
    plan.members
        .iter()
        .find(|m| m.id == material.id)
        .map(|m| m.advertise)
        .context("member vanished mid-deployment")
}

fn advertise_addr(ip: &IpAddr, port: u16) -> Result<SocketAddr> {
    format!("{ip}:{port}")
        .parse()
        .with_context(|| format!("building advertised address {ip}:{port}"))
}

/// Pushes the assembled `cluster.toml` to one node.
fn push_config(plan: &GenesisPlan, member: &MemberTarget) -> Result<()> {
    let local = plan.out_dir.join("cluster.toml");
    let staging = format!("/tmp/cluster.toml.genesis.{}", member.id);
    scp_to(&member.ssh_target, &local, &staging)?;
    let script = format!(
        "install -m 0644 '{}' '{}/cluster.toml' && rm -f '{}'",
        shell_quote(&staging),
        shell_quote(&plan.config_dir),
        shell_quote(&staging)
    );
    ssh_capture(&member.ssh_target, &["sudo", "-n", "sh", "-c", &script], None).map(drop)
}

/// Writes the systemd unit, opens the optional mesh firewall rules, and
/// reloads systemd. Starting happens separately so every unit file exists
/// before any node boots.
fn install_service(plan: &GenesisPlan, member: &MemberTarget) -> Result<()> {
    let unit = render_unit(member.id, &plan.config_dir, &plan.data_dir);
    ssh_capture(&member.ssh_target, &["sudo", "-n", "tee", UNIT_PATH], Some(unit.as_bytes()))
        .map(drop)?;

    if plan.ufw {
        for peer in &plan.members {
            if peer.id == member.id {
                continue;
            }
            for port in [plan.gossip_port, plan.reconnect_port] {
                let rule =
                    format!("ufw allow from {} to any port {} proto tcp", peer.advertise, port);
                ssh_capture(&member.ssh_target, &["sudo", "-n", &rule], None)
                    .map(drop)
                    .with_context(|| format!("node {}: applying ufw rule", member.id))?;
            }
        }
    }

    ssh_capture(&member.ssh_target, &["sudo", "-n", "systemctl", "daemon-reload"], None).map(drop)
}

fn start_service(member: &MemberTarget) -> Result<()> {
    ssh_capture(
        &member.ssh_target,
        &["sudo", "-n", "systemctl", "enable", "--now", "jkaind.service"],
        None,
    )
    .map(drop)
}

/// Polls every node's control socket through SSH until all answer or the
/// deadline passes.
fn await_cluster_healthy(plan: &GenesisPlan) -> Result<()> {
    let deadline = Instant::now() + HEALTH_TIMEOUT;
    let mut pending: Vec<&MemberTarget> = plan.members.iter().collect();
    while !pending.is_empty() {
        pending.retain(|member| {
            ssh_capture(
                &member.ssh_target,
                &[REMOTE_BINARY, "status", "--socket", &format!("{}/jkaind.sock", plan.data_dir)],
                None,
            )
            .is_ok()
        });
        if pending.is_empty() {
            break;
        }
        if Instant::now() >= deadline {
            let ids: Vec<String> = pending.iter().map(|m| m.id.to_string()).collect();
            bail!(
                "nodes [{}] did not become healthy within {}s; inspect with \
                 journalctl -u jkaind on the respective hosts",
                ids.join(", "),
                HEALTH_TIMEOUT.as_secs()
            );
        }
        let ids: Vec<String> = pending.iter().map(|m| m.id.to_string()).collect();
        println!("deploy: waiting for node(s) [{}] …", ids.join(", "));
        thread::sleep(HEALTH_POLL_INTERVAL);
    }
    println!("deploy: all nodes report healthy");
    Ok(())
}

fn print_summary(plan: &GenesisPlan, config_path: &Path) {
    println!("deploy: cluster is up");
    for member in &plan.members {
        println!(
            "\x20 node {} @ {} — journalctl -u jkaind -f (via ssh {})",
            member.id, member.advertise, member.ssh_target
        );
    }
    println!(
        "deploy: public cluster.toml copy at {} (safe to commit; no secrets were ever stored locally)",
        config_path.display()
    );
    println!(
        "deploy: grow the cluster later with `jkaind member init` + `jkaind add-member` — membership changes flow through consensus, not this tool"
    );
}

// --- key material ------------------------------------------------------------

/// Generates one member's unified 32-byte seed plus derived keys.
/// Returns `(seed, verifying_key, spki_fingerprint)`.
fn generate_member_material(node_id: u64) -> Result<([u8; GENESIS_SEED_LEN], [u8; 32], [u8; 32])> {
    let mut seed = [0u8; GENESIS_SEED_LEN];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let identity = TlsIdentity::from_seed(seed, node_id)
        .with_context(|| format!("node {node_id}: building TLS identity"))?;
    Ok((seed, signing_key.verifying_key().to_bytes(), identity.spki_fingerprint()))
}

fn write_secret_file(path: &Path, seed: &[u8]) -> Result<()> {
    fs::write(path, seed).with_context(|| format!("writing {}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms =
            fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

fn parse_keygen_output(stdout: &str) -> Result<(String, String)> {
    let line = stdout
        .lines()
        .rev()
        .find(|line| line.starts_with(KEYGEN_LINE_PREFIX))
        .with_context(|| format!("no {KEYGEN_LINE_PREFIX:?} line in keygen output"))?;
    let mut fields = line[KEYGEN_LINE_PREFIX.len()..].split_whitespace();
    let vk = fields.next().context("keygen line missing verifying key")?;
    let fp = fields.next().context("keygen line missing SPKI fingerprint")?;
    Ok((vk.to_owned(), fp.to_owned()))
}

// --- templates ---------------------------------------------------------------

/// The systemd unit from `RUNBOOK.md`, parameterized per node.
fn render_unit(node_id: u64, config_dir: &str, data_dir: &str) -> String {
    format!(
        "[Unit]\n\
         Description=JKain node {node_id}\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart={REMOTE_BINARY} run --cluster {config_dir}/cluster.toml --node-id {node_id} --secret {config_dir}/secret-{node_id}.bin --data {data_dir}\n\
         Restart=on-failure\n\
         RestartSec=2\n\
         User={SERVICE_USER}\n\
         Group={SERVICE_USER}\n\
         LimitNOFILE=65536\n\
         KillSignal=SIGTERM\n\
         TimeoutStopSec=20\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n"
    )
}

/// Single-quotes a string for safe interpolation into a POSIX shell command.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', r"'\''"))
}

// --- process helpers ---------------------------------------------------------

fn ssh_capture(target: &str, remote_args: &[&str], stdin: Option<&[u8]>) -> Result<String> {
    let mut command = Command::new("ssh");
    command.args(SSH_OPTS).arg(target).args(remote_args);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() });

    let mut child =
        command.spawn().with_context(|| format!("spawning ssh to {target} (is ssh installed?)"))?;
    if let Some(bytes) = stdin {
        let mut handle = child.stdin.take().context("ssh stdin unavailable")?;
        handle.write_all(bytes).with_context(|| format!("writing stdin to ssh {target}"))?;
    }
    let output = child.wait_with_output().context("waiting for ssh")?;
    if !output.status.success() {
        bail!(
            "ssh {target} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn scp_to(target: &str, source: &Path, remote_dest: &str) -> Result<()> {
    let mut command = Command::new("scp");
    command.args(SSH_OPTS).arg(source).arg(format!("{target}:{remote_dest}"));
    let output = command
        .output()
        .with_context(|| format!("spawning scp to {target} (is scp installed?)"))?;
    if !output.status.success() {
        bail!(
            "scp to {target} failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    let value = args.get(*i).with_context(|| format!("{flag} requires a value"))?;
    *i += 1;
    Ok(value.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(value: &str) -> Result<MemberTarget> {
        parse_member_spec(value)
    }

    #[test]
    fn member_spec_parses_bare_ip() {
        let m = spec("1=203.0.113.5").expect("parses");
        assert_eq!(m.id, 1);
        assert_eq!(m.ssh_target, "203.0.113.5");
        assert_eq!(m.advertise.to_string(), "203.0.113.5");
    }

    #[test]
    fn member_spec_parses_user_and_ssh_port_with_explicit_advertise() {
        let m = spec("2=curator@vps-b.internal:2222=198.51.100.6").expect("parses");
        assert_eq!(m.id, 2);
        assert_eq!(m.ssh_target, "curator@vps-b.internal:2222");
        assert_eq!(m.advertise.to_string(), "198.51.100.6");
    }

    #[test]
    fn member_spec_rejects_missing_pieces_and_bad_ips() {
        assert!(spec("").is_err(), "empty spec");
        assert!(spec("x=203.0.113.5").is_err(), "non-numeric id");
        assert!(spec("3=").is_err(), "missing host");
        assert!(spec("4=vps-d.internal").is_err(), "DNS host needs explicit advertise");
        assert!(spec("5=203.0.113.5=not-an-ip").is_err(), "bad advertise");
        assert!(spec("6==203.0.113.9").is_err(), "empty host");
    }

    #[test]
    fn duplicate_ids_are_rejected_before_any_ssh_runs() {
        let args: Vec<String> = ["--member", "1=203.0.113.5", "--member", "1=203.0.113.6"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let err = parse_genesis_args(&args).expect_err("duplicate id rejected");
        assert!(err.to_string().contains("duplicate node id 1"), "{err}");
    }

    #[test]
    fn reconnect_defaults_next_to_gossip() {
        let args: Vec<String> = ["--member", "1=203.0.113.5", "--gossip-port", "8000"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        let plan = parse_genesis_args(&args).expect("parses");
        assert_eq!(plan.gossip_port, 8000);
        assert_eq!(plan.reconnect_port, 8001);
    }

    #[test]
    fn unit_matches_runbook_shape() {
        let unit = render_unit(7, "/etc/jkaind", "/var/lib/jkaind");
        assert!(unit.contains("Description=JKain node 7"), "{unit}");
        assert!(unit.contains("--node-id 7"), "{unit}");
        assert!(unit.contains("/etc/jkaind/secret-7.bin"), "{unit}");
        assert!(unit.contains("--data /var/lib/jkaind"), "{unit}");
        assert!(unit.contains("KillSignal=SIGTERM"), "{unit}");
        assert!(unit.contains(&format!("User={SERVICE_USER}")), "{unit}");
    }

    #[test]
    fn shell_quote_survives_hostile_input() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
    }

    #[test]
    fn keygen_line_round_trips() {
        let stdout = "some log noise\nJKAIN_KEYGEN aa..bb cc..dd\n";
        let (vk, fp) = parse_keygen_output(stdout).expect("parses");
        assert_eq!(vk, "aa..bb");
        assert_eq!(fp, "cc..dd");
        assert!(parse_keygen_output("nothing here").is_err());
    }

    #[test]
    fn advertise_addresses_combine_ip_and_ports() {
        let ip: IpAddr = "203.0.113.5".parse().expect("ip");
        assert_eq!(advertise_addr(&ip, 7000).expect("addr").to_string(), "203.0.113.5:7000");
        assert_eq!(advertise_addr(&ip, 7001).expect("addr").to_string(), "203.0.113.5:7001");
    }
}
