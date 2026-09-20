//! The `jkainc` daemon: a compute node that hosts off-chain actors.
//!
//! The counterpart to `jkaind` (the consensus daemon). It does not participate
//! in consensus; it reads from and writes to L1 only for coordination
//! (whitepaper §6.3). See `ARCHITECTURE.md` in this project for the layout.

/// Parses argv and runs the daemon.
///
/// Scaffold only: the real entry point needs a config surface (listen address,
/// data dir, the L1 endpoint) before it can do anything.
pub fn run() -> anyhow::Result<()> {
    anyhow::bail!("jkainc: not implemented yet (scaffold only)")
}
