//! Shared argument-parsing helpers for the `jkaind` subcommands.

use std::path::PathBuf;

use anyhow::{
    Context,
    Result,
    bail,
};

/// Default control-socket path for the client subcommands.
pub(crate) const DEFAULT_SOCKET: &str = "data/jkaind.sock";

pub(crate) fn default_socket() -> PathBuf {
    PathBuf::from(DEFAULT_SOCKET)
}

/// Consumes the value of the flag at `args[*i]` and advances past it.
pub(crate) fn next_value(args: &[String], i: &mut usize, flag: &str) -> Result<String> {
    *i += 1;
    let value = args.get(*i).with_context(|| format!("{flag} requires a value"))?;
    *i += 1;
    Ok(value.clone())
}

pub(crate) fn parse_port(value: &str, flag: &str) -> Result<u16> {
    let port: u16 =
        value.parse().with_context(|| format!("{flag} must be a port 1-65535, got '{value}'"))?;
    if port == 0 {
        bail!("{flag} must be a port 1-65535, got '{value}'");
    }
    Ok(port)
}

pub(crate) fn parse_ms(value: &str, flag: &str) -> Result<u64> {
    let ms: u64 =
        value.parse().with_context(|| format!("{flag} must be milliseconds, got '{value}'"))?;
    if ms == 0 {
        bail!("{flag} must be milliseconds, got '{value}'");
    }
    Ok(ms)
}

/// Extracts `--socket <path>` (default `data/jkaind.sock`) for the client
/// subcommands that take only that flag.
pub(crate) fn parse_socket_flag(args: &[String]) -> Result<PathBuf> {
    let mut socket = default_socket();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--socket" => socket = PathBuf::from(next_value(args, &mut i, "--socket")?),
            other => bail!("unknown argument '{other}' (expected --socket <path>)"),
        }
    }
    Ok(socket)
}

pub(crate) fn parse_socket_addr(value: &str, flag: &str) -> Result<std::net::SocketAddr> {
    value.parse().with_context(|| format!("{flag} must be <ip>:<port>, got '{value}'"))
}
