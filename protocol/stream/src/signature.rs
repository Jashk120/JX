//! Per-file Ed25519 signature files (`.esf_sig` / `.rsf_sig`), mirroring
//! Hiero's `SignatureWriterV6` layout (Phase 8, §2.1 / §3.1):
//!
//! ```text
//! [1 byte: version] [protobuf SignatureFile]
//! ```
//!
//! `SignatureFile = { file_signature, metadata_signature }`, both Ed25519
//! (JKaIN-native, unlike Hiero's RSA):
//!
//! - `file_signature` is over the SHA-256 digest of the *whole* stream file
//!   bytes.
//! - `metadata_signature` is over the SHA-256 digest of the file metadata:
//!   `[version u32 BE] || start_running_hash || end_running_hash` for event
//!   files, plus the `round` (u64 BE) for record files.
//!
//! The signature file is written *before* its stream file (both atomically),
//! so a crash mid-pair leaves at worst an orphaned signature — never a stream
//! file without its signature.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{
    Signer,
    SigningKey,
    VerifyingKey,
};
use prost::Message;
use sha2::{
    Digest,
    Sha256,
};

use crate::error::{
    Result,
    StreamError,
};
use crate::pb;

/// The single version byte prefixing every signature file.
pub const SIG_FILE_VERSION: u8 = 1;

/// `HashObject.algorithm` for SHA-256.
pub const HASH_ALGORITHM_SHA256: u32 = 0;
/// `HashObject.length` for a SHA-256 digest.
pub const HASH_LENGTH_SHA256: u32 = 32;
/// `SignatureObject.type` for Ed25519.
pub const SIGNATURE_TYPE_ED25519: u32 = 0;
/// `SignatureObject.length` for an Ed25519 signature.
pub const SIGNATURE_LENGTH_ED25519: u32 = 64;

/// The digest `SignatureObject` carries.
fn hash_object(digest: [u8; 32]) -> pb::HashObject {
    pb::HashObject {
        algorithm: HASH_ALGORITHM_SHA256,
        length: HASH_LENGTH_SHA256,
        hash: digest.to_vec(),
    }
}

/// One signed digest: the Ed25519 signature over `digest`, self-described.
fn signature_object(digest: [u8; 32], key: &SigningKey) -> pb::SignatureObject {
    let signature = key.sign(&digest);
    pb::SignatureObject {
        r#type: SIGNATURE_TYPE_ED25519,
        length: SIGNATURE_LENGTH_ED25519,
        signature: signature.to_bytes().to_vec(),
        hash_object: Some(hash_object(digest)),
    }
}

/// The bytes the `metadata_signature` commits to:
/// `[version u32 BE] || start (32) || end (32)` plus `round` (8 BE) for
/// record files.
pub fn metadata_bytes(
    version: u32,
    start: &[u8; 32],
    end: &[u8; 32],
    round: Option<u64>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(68 + round.map_or(0, |_| 8));
    bytes.extend_from_slice(&version.to_be_bytes());
    bytes.extend_from_slice(start);
    bytes.extend_from_slice(end);
    if let Some(round) = round {
        bytes.extend_from_slice(&round.to_be_bytes());
    }
    bytes
}

/// Builds the `SignatureFile` for a completed stream file.
pub fn build_signature_file(
    file_bytes: &[u8],
    metadata: &[u8],
    key: &SigningKey,
) -> pb::SignatureFile {
    let file_digest: [u8; 32] = Sha256::digest(file_bytes).into();
    let metadata_digest: [u8; 32] = Sha256::digest(metadata).into();
    pb::SignatureFile {
        file_signature: Some(signature_object(file_digest, key)),
        metadata_signature: Some(signature_object(metadata_digest, key)),
    }
}

/// Writes a signature file atomically: `[version byte][encoded SignatureFile]`.
pub fn write_signature_file(path: &Path, signature_file: &pb::SignatureFile) -> Result<()> {
    let mut bytes = Vec::new();
    bytes.push(SIG_FILE_VERSION);
    signature_file.encode(&mut bytes)?;
    write_atomic(path, &bytes)
}

/// Parses a signature file: validates the leading version byte, decodes the
/// `SignatureFile` message, and rejects trailing bytes.
pub fn read_signature_file(bytes: &[u8]) -> Result<pb::SignatureFile> {
    let (&version, rest) =
        bytes.split_first().ok_or(StreamError::Malformed("signature file is empty".into()))?;
    if version != SIG_FILE_VERSION {
        return Err(StreamError::BadSigFileVersion(version));
    }
    let signature_file = pb::SignatureFile::decode(rest)?;
    if signature_file.encoded_len() != rest.len() {
        // prost tolerates trailing bytes; a mirror must not.
        return Err(StreamError::TrailingBytes);
    }
    if signature_file
        .file_signature
        .as_ref()
        .is_none_or(|signature| signature.hash_object.is_none())
        || signature_file
            .metadata_signature
            .as_ref()
            .is_none_or(|signature| signature.hash_object.is_none())
    {
        return Err(StreamError::Malformed(
            "signature file is missing a signature or its hash object".into(),
        ));
    }
    Ok(signature_file)
}

/// Verifies both signatures of `signature_file` against `key`: the file
/// signature over the SHA-256 of `file_bytes`, and the metadata signature over
/// the SHA-256 of `metadata`.
pub fn verify_signature_file(
    signature_file: &pb::SignatureFile,
    file_bytes: &[u8],
    metadata: &[u8],
    key: &VerifyingKey,
) -> bool {
    let Some(file_signature) = &signature_file.file_signature else { return false };
    let Some(metadata_signature) = &signature_file.metadata_signature else { return false };
    let file_digest: [u8; 32] = Sha256::digest(file_bytes).into();
    let metadata_digest: [u8; 32] = Sha256::digest(metadata).into();
    verify_signature_object(file_signature, &file_digest, key)
        && verify_signature_object(metadata_signature, &metadata_digest, key)
}

/// Verifies one `SignatureObject`: its `hash_object` must commit the expected
/// digest and its Ed25519 signature must verify over that digest.
pub(crate) fn verify_signature_object(
    signature_object: &pb::SignatureObject,
    expected_digest: &[u8; 32],
    key: &VerifyingKey,
) -> bool {
    let Some(hash_object) = &signature_object.hash_object else { return false };
    if hash_object.algorithm != HASH_ALGORITHM_SHA256 || hash_object.length != HASH_LENGTH_SHA256 {
        return false;
    }
    if hash_object.hash.as_slice() != expected_digest {
        return false;
    }
    if signature_object.r#type != SIGNATURE_TYPE_ED25519
        || signature_object.length != SIGNATURE_LENGTH_ED25519
    {
        return false;
    }
    let Ok(signature_bytes) = signature_object.signature.clone().try_into() else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);
    key.verify_strict(expected_digest, &signature).is_ok()
}

/// Writes `bytes` to `path` atomically: a uniquely-named temp file in the
/// same directory is written, flushed to disk, and renamed over the target.
/// A crash leaves either the old file or the new file, never a torn one.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = path.parent().ok_or_else(|| {
        StreamError::Malformed(format!("path {} has no parent directory", path.display()))
    })?;
    let tmp = dir.join(format!(
        ".tmp-{}-{}",
        std::process::id(),
        path.file_name().and_then(|name| name.to_str()).unwrap_or("out")
    ));
    let mut file = File::create(&tmp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    use super::*;

    #[test]
    fn signature_file_round_trips_and_verifies() {
        let key = SigningKey::generate(&mut OsRng);
        let verifying_key = key.verifying_key();
        let file_bytes = b"the whole stream file";
        let metadata = metadata_bytes(1, &[1; 32], &[2; 32], Some(7));

        let signature_file = build_signature_file(file_bytes, &metadata, &key);
        let mut encoded = vec![SIG_FILE_VERSION];
        signature_file.encode(&mut encoded).expect("encodes");

        let decoded = read_signature_file(&encoded).expect("decodes");
        assert!(verify_signature_file(&decoded, file_bytes, &metadata, &verifying_key));
    }

    #[test]
    fn signature_file_rejects_tampering() {
        let key = SigningKey::generate(&mut OsRng);
        let verifying_key = key.verifying_key();
        let file_bytes = b"the whole stream file";
        let metadata = metadata_bytes(1, &[1; 32], &[2; 32], None);

        let signature_file = build_signature_file(file_bytes, &metadata, &key);
        let decoded = read_signature_file(&{
            let mut encoded = vec![SIG_FILE_VERSION];
            signature_file.encode(&mut encoded).expect("encodes");
            encoded
        })
        .expect("decodes");

        let mut tampered = file_bytes.to_vec();
        tampered[0] ^= 0xff;
        assert!(!verify_signature_file(&decoded, &tampered, &metadata, &verifying_key));

        let mut tampered_metadata = metadata.clone();
        tampered_metadata[0] ^= 0xff;
        assert!(!verify_signature_file(&decoded, file_bytes, &tampered_metadata, &verifying_key));

        let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
        assert!(!verify_signature_file(&decoded, file_bytes, &metadata, &wrong_key));
    }

    #[test]
    fn read_rejects_bad_version_and_trailing_bytes() {
        let key = SigningKey::generate(&mut OsRng);
        let signature_file = build_signature_file(b"x", b"y", &key);
        let mut encoded = vec![SIG_FILE_VERSION + 1];
        signature_file.encode(&mut encoded).expect("encodes");
        assert!(matches!(read_signature_file(&encoded), Err(StreamError::BadSigFileVersion(_))));

        let mut encoded = vec![SIG_FILE_VERSION];
        signature_file.encode(&mut encoded).expect("encodes");
        encoded.push(0);
        assert!(
            read_signature_file(&encoded).is_err(),
            "trailing bytes after the signature file must be rejected"
        );
    }

    #[test]
    fn metadata_bytes_are_fixed_shape() {
        assert_eq!(metadata_bytes(1, &[0; 32], &[1; 32], None).len(), 4 + 32 + 32);
        assert_eq!(metadata_bytes(1, &[0; 32], &[1; 32], Some(9)).len(), 4 + 32 + 32 + 8);
    }
}
