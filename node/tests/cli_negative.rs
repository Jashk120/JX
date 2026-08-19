//! Negative tests for `jkaind` CLI argument handling: invalid flags, invalid
//! values, unknown subcommands, and the `--version`/`--help` smoke tests.

use std::process::Command;

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_jkaind")
}

// ---------------------------------------------------------------------------
// run: invalid --log-level
// ---------------------------------------------------------------------------

#[test]
fn run_rejects_invalid_log_level() {
    let status = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--log-level",
            "not-a-level",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "--log-level with invalid value must fail");
}

// ---------------------------------------------------------------------------
// run: --log-file pointed at an uncreatable directory
// ---------------------------------------------------------------------------

#[test]
fn run_rejects_log_file_under_nonexistent_root() {
    let status = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--log-file",
            "/nonexistent_root_xyz/jkaind.log",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "--log-file whose parent dir can't be created must fail");
}

// ---------------------------------------------------------------------------
// run: --sync-interval / --sync-timeout with non-numeric or zero values
// ---------------------------------------------------------------------------

#[test]
fn run_rejects_non_numeric_sync_interval() {
    let status = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--sync-interval",
            "abc",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "--sync-interval with non-numeric value must fail");
}

#[test]
fn run_rejects_non_numeric_sync_timeout() {
    let status = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--sync-timeout",
            "not-a-number",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "--sync-timeout with non-numeric value must fail");
}

#[test]
fn run_accepts_zero_sync_interval() {
    // Zero is a valid u64; Duration::from_millis(0) is permitted.
    // The binary fails later (missing secret), not at parse time.
    let output = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--sync-interval",
            "0",
        ])
        .output()
        .expect("binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("must be milliseconds"),
        "zero --sync-interval must not be rejected at parse time: {stderr}"
    );
}

#[test]
fn run_accepts_zero_sync_timeout() {
    let output = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--sync-timeout",
            "0",
        ])
        .output()
        .expect("binary runs");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("must be milliseconds"),
        "zero --sync-timeout must not be rejected at parse time: {stderr}"
    );
}

// ---------------------------------------------------------------------------
// run: unknown flag
// ---------------------------------------------------------------------------

#[test]
fn run_rejects_unknown_flag() {
    let status = Command::new(binary())
        .args([
            "run",
            "--cluster",
            "/dev/null",
            "--node-id",
            "1",
            "--secret",
            "/dev/null",
            "--bogus-flag",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "unknown flag to run must be rejected");
}

// ---------------------------------------------------------------------------
// init: unknown argument
// ---------------------------------------------------------------------------

#[test]
fn init_rejects_unknown_argument() {
    let status = Command::new(binary())
        .args([
            "init",
            "--member",
            "1:127.0.0.1:7000",
            "--out",
            "/tmp/jkaind-cli-negative-test",
            "--something-else",
        ])
        .status()
        .expect("binary runs");
    assert!(!status.success(), "unknown argument to init must be rejected");
}

// ---------------------------------------------------------------------------
// status: unknown flag
// ---------------------------------------------------------------------------

#[test]
fn status_rejects_unknown_flag() {
    let status =
        Command::new(binary()).args(["status", "--not-a-flag"]).status().expect("binary runs");
    assert!(!status.success(), "unknown flag to status must be rejected");
}

// ---------------------------------------------------------------------------
// version / help (smoke)
// ---------------------------------------------------------------------------

#[test]
fn version_flag_succeeds() {
    let output = Command::new(binary()).arg("--version").output().expect("binary runs");
    assert!(output.status.success(), "--version must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("jkaind"), "--version output mentions jkaind");
}

#[test]
fn help_flag_succeeds() {
    let output = Command::new(binary()).arg("--help").output().expect("binary runs");
    assert!(output.status.success(), "--help must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage"), "--help output mentions Usage");
}

// ---------------------------------------------------------------------------
// top-level: unknown subcommand
// ---------------------------------------------------------------------------

#[test]
fn unknown_subcommand_is_rejected() {
    let status = Command::new(binary()).args(["does-not-exist"]).status().expect("binary runs");
    assert!(!status.success(), "unknown subcommand must be rejected");
}
