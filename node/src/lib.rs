//! The `jkaind` daemon crate.
//!
//! Owns the terminal-facing CLI (`jkaind init` / `jkaind run`), the shared
//! `cluster.toml` configuration, and the checkpoint persistence layer for a
//! real multi-VPS JKain cluster. The consensus logic itself lives in
//! `protocol/gossip`; this crate only wires it to the filesystem and the
//! process lifecycle.

pub mod config;
pub mod restart;
pub mod storage;

pub use config::ClusterConfigFile;
pub use restart::build_reconnect_response;
pub use storage::Storage;
