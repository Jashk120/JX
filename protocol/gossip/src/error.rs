use thiserror::Error;

/// Errors produced by the gossip layer.
#[derive(Debug, Error)]
pub enum GossipError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("connection closed")]
    Closed,

    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),

    #[error("certificate verification failed: {0}")]
    CertificateVerification(String),

    #[error("failed to build TLS identity: {0}")]
    Identity(String),

    #[error("malformed frame: {0}")]
    Framing(String),

    #[error("unexpected frame type: expected {expected}, got {got}")]
    UnexpectedFrame { expected: &'static str, got: &'static str },

    #[error("consensus rejected an event: {0}")]
    Consensus(#[from] consensus::ConsensusError),

    #[error("crypto error while verifying an event: {0}")]
    Crypto(#[from] crypto::CryptoError),

    #[error("sync failed: {0}")]
    Sync(String),

    #[error("reconnect failed: {0}")]
    Reconnect(String),
}

pub type Result<T> = std::result::Result<T, GossipError>;

impl GossipError {
    pub(crate) fn framing(message: impl Into<String>) -> Self {
        Self::Framing(message.into())
    }
}
