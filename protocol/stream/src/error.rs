//! Errors produced by the mirror stream crate.

use thiserror::Error;

/// Errors produced by the stream file writers, readers, and verifier.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("stream file has an unknown version {0}")]
    BadVersion(u32),

    #[error("signature file has an unknown version {0:#04x}")]
    BadSigFileVersion(u8),

    #[error("failed to decode a stream file message: {0}")]
    Decode(#[from] prost::DecodeError),

    #[error("failed to encode a stream file message: {0}")]
    Encode(#[from] prost::EncodeError),

    #[error("malformed stream file: {0}")]
    Malformed(String),

    #[error("running-hash chain is discontinuous at file {0}")]
    ChainDiscontinuity(String),

    #[error("file signature did not verify")]
    BadSignature,

    #[error("metadata signature did not verify")]
    BadMetadataSignature,

    #[error("the embedded checkpoint does not reach the 2/3 quorum")]
    BadQuorum,

    #[error("the file's start_running_hash is not the chain seed at the first file")]
    BadChainStart,

    #[error("unexpected trailing bytes after the signature file version byte")]
    TrailingBytes,

    #[error("no signature file for {0}")]
    MissingSignature(String),

    #[error("the stream directory is empty")]
    EmptyDirectory,
}

/// Result alias for the stream crate.
pub type Result<T> = std::result::Result<T, StreamError>;
