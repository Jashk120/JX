//! `jkaind` — the JKain node daemon binary.
//!
//! All subcommand implementations live in the library crate under
//! [`node::cli`]; this binary only forwards `argv` to the dispatcher.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    node::cli::run(std::env::args().skip(1).collect()).await
}
