//! Gossip-about-gossip network layer for JKain.
//!
//! Implements Consensus Spec §5: nodes periodically pick a random peer,
//! exchange event deltas over a pinned TLS connection, and fold the newly
//! received events into a locally-created event of their own. Depends on
//! `primitives` for the value types, `crypto` for hashing/signing/identity,
//! and `consensus` for the hashgraph that stores and orders the events.
//!
//! Transport is raw TCP with TLS 1.3 (rustls) and length-prefixed canonical
//! frames — the conservative, well-understood transport the whitepaper
//! (§2.2) deliberately chooses for the consensus-hot path. QUIC is deferred
//! to a later optimization phase.

pub mod cluster_config;
pub mod error;
pub mod frontier;
pub mod node;
pub mod peer;
pub mod peer_manager;
pub mod proto;
pub mod reconnect;
pub mod sync;
pub mod tls;
pub mod transport;

pub use cluster_config::{
    ClusterConfig,
    MemberEntry,
};
pub use error::{
    GossipError,
    Result,
};
pub use node::{
    CheckpointSink,
    GossipNode,
    SyncTiming,
};
pub use peer::PeerInfo;
pub use peer_manager::PeerManager;
pub use proto::{
    Frame,
    ReconnectRequest,
    ReconnectResponse,
    SyncRequest,
    SyncResponse,
};
pub use reconnect::{
    fetch_checkpoint,
    verify_signed_checkpoint,
};
pub use sync::run_sync;
pub use tls::TlsIdentity;
pub use transport::{
    SyncTransport,
    TcpTransport,
};
