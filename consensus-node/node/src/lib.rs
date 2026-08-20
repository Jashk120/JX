//! The `jkaind` daemon crate.
//!
//! Owns the terminal-facing CLI (`jkaind init` / `jkaind run`), the shared
//! `cluster.toml` configuration, and the checkpoint persistence layer for a
//! real multi-VPS JKain cluster. The consensus logic itself lives in
//! `protocol/gossip`; this crate only wires it to the filesystem and the
//! process lifecycle.

pub mod config;
pub mod control;
pub mod format;
pub mod restart;
pub mod storage;

pub use config::ClusterConfigFile;
pub use control::{
    ControlRequest,
    ControlResponse,
    StatusReport,
};
pub use format::{
    CURRENT_FORMAT,
    check_or_init_data_dir,
};
pub use restart::{
    build_reconnect_response,
    latest_for_restart,
    latest_for_restart_with_log,
    replay_response,
    restore_state,
    verify_persisted,
};
pub use storage::Storage;
