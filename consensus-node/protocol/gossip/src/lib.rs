//! Gossip-about-gossip network layer for JKain.
//!
//! Implements Consensus Spec §5: nodes periodically fan out to `k =
//! FanoutMode::effective_k(N)` peers concurrently (`JoinSet`+`Semaphore(k)`,
//! ratio `0.6@N<=10` to `0.3@N>=30`, `k_max 4@N<=6, 17@7<=N<=99 Hedera cap,
//! 12@N>=100`, `LruCache` hot-pool `10@N=6, 30@N=100`, per-peer `DedupState`
//! `1000/250/3000 ms` via `filter_likely_duplicates`, `GossipMetrics`),
//! exchange event deltas over pinned TLS connections, and fold the newly
//! received events into a locally-created event of their own. Depends on
//! `primitives` for the value types, `crypto` for hashing, signing, and
//! membership, and `consensus` for the hashgraph that stores and orders events.
//!
//! Transport is `SyncTransport` over raw TCP with TLS 1.3 (rustls) and
//! length-prefixed canonical frames, the conservative transport the whitepaper
//! (section 2.2) chooses for the consensus hot path, plus `QuicTransport` via
//! `quinn`+`rustls` SPKI verifier (same `spki_fingerprint` pin, single
//! `gossip_addr` as QUIC endpoint, `TcpTransport` fallback, `Frame`
//! `[tag:u8][len:u32BE][payload]` unchanged over QUIC bidi streams).
//! `SyncTransport` stays abstract so `TcpTransport` remains as benchmark and
//! fallback. Bounded fanout, `LruCache` hot-pool, per-peer dedup and
//! `GossipMetrics` are implemented (T12) per `docs/OPTIMIZATION.md:3.4`
//! (G-track G1 to G6).

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
pub use frontier::{
    DedupState,
    SyncConfig,
};
pub use node::{
    CheckpointSink,
    GossipNode,
    SyncTiming,
};
pub use peer::PeerInfo;
pub use peer_manager::{
    FanoutMode,
    PeerManager,
    PeerScore,
};
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
    QuicTransport,
    SyncTransport,
    TcpTransport,
};
