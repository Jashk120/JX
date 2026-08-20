//! The DID operation wire format (`did:jkain`).
//!
//! DID operations become a `Transaction` payload so they inherit consensus's
//! existing ordering and agreement machinery. A `Transaction`'s payload bytes
//! decode into exactly one [`DidOp`]; the executor applies it to the state by
//! storing the [`DidDocument`] under the [`DidId`] key.
//!
//! The format mirrors the executor's `Op` encoding:
//!
//! ```text
//! [opcode: u8]
//! [field: u32 (big-endian) byte length + raw bytes]
//! ```
//!
//! The opcode `0x03` is consumed by [`DecodedOp`](crate::op::DecodedOp);
//! the body is decoded by [`DidOp::decode`]:
//!
//! ```text
//! [network_len: u32 BE][network bytes]
//! [alias_len: u32 BE][alias bytes]
//! [uuid: 16 bytes]
//! [num_keys: u8]
//! [key_0: 32 bytes]...[key_N: 32 bytes]
//! [deactivated: u8 (0 or 1)]
//! [signature: 64 bytes]
//! [signed_by: u8]
//! [is_creation: u8 (0 or 1)]
//! ```
//!
//! `num_keys` must be in 1..=5; `signed_by` is an index into the
//! authorizing document's verification methods. `is_creation` distinguishes
//! a DID creation (must target an absent identifier) from an update or
//! deactivation (must target an existing identifier). The signed payload is
//! `DidId::encode() || DidDocument::encode()`.
//!
//! Decode-time deterministic rejects: more than 5 verification methods,
//! empty list, truncated fields — same pattern as
//! [`ExecutorError::Truncated`](crate::error::ExecutorError::Truncated).

use ed25519_dalek::VerifyingKey;
use primitives::Signature;

use crate::error::{
    ExecutorError,
    Result,
};

const MAX_VERIFICATION_METHODS: usize = 5;
const UUID_LEN: usize = 16;

/// A `did:jkain` identifier: network, alias, and a 16-byte UUID.
///
/// String representation: `did:jkain:<network>:<alias>:<uuid-hex>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidId {
    network: String,
    alias: String,
    uuid: [u8; UUID_LEN],
}

impl DidId {
    pub fn new(network: String, alias: String, uuid: [u8; UUID_LEN]) -> Self {
        Self { network, alias, uuid }
    }

    pub fn network(&self) -> &str {
        &self.network
    }

    pub fn alias(&self) -> &str {
        &self.alias
    }

    pub fn uuid(&self) -> &[u8; UUID_LEN] {
        &self.uuid
    }

    /// Parses `did:jkain:<network>:<alias>:<uuid-hex>`.
    pub fn parse(s: &str) -> std::result::Result<Self, DidParseError> {
        let rest = s.strip_prefix("did:jkain:").ok_or(DidParseError::MissingPrefix)?;
        let (network, rest) = rest.split_once(':').ok_or(DidParseError::MissingSeparator)?;
        let (alias, uuid_hex) = rest.split_once(':').ok_or(DidParseError::MissingSeparator)?;
        if uuid_hex.len() != UUID_LEN * 2 {
            return Err(DidParseError::InvalidUuid);
        }
        let mut uuid = [0u8; UUID_LEN];
        hex_decode_to(uuid_hex, &mut uuid).map_err(|()| DidParseError::InvalidUuid)?;
        Ok(Self { network: network.to_owned(), alias: alias.to_owned(), uuid })
    }

    /// Binary encoding for use as a state key.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        write_bytes(&mut buf, self.network.as_bytes());
        write_bytes(&mut buf, self.alias.as_bytes());
        buf.extend_from_slice(&self.uuid);
        buf
    }

    /// Decodes a `DidId` from its binary encoding.
    pub fn decode(cursor: &mut &[u8]) -> std::result::Result<Self, ExecutorError> {
        let network_bytes = take_bytes(cursor)?;
        let alias_bytes = take_bytes(cursor)?;
        let uuid_bytes = take_exact(cursor, UUID_LEN)?;
        let network = String::from_utf8(network_bytes).map_err(|_| ExecutorError::Truncated)?;
        let alias = String::from_utf8(alias_bytes).map_err(|_| ExecutorError::Truncated)?;
        let uuid: [u8; UUID_LEN] = uuid_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        Ok(Self { network, alias, uuid })
    }
}

impl std::fmt::Display for DidId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:jkain:{}:{}:{}", self.network, self.alias, hex_encode(&self.uuid))
    }
}

/// A DID document containing verification methods and a deactivated flag.
///
/// The verification method list is capped at 5 entries and must be non-empty,
/// enforced at decode time. The `deactivated` flag is a tombstone: when true
/// the DID is considered retired but the state key remains present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidDocument {
    verification_methods: Vec<VerifyingKey>,
    deactivated: bool,
}

impl DidDocument {
    pub fn new(
        verification_methods: Vec<VerifyingKey>,
        deactivated: bool,
    ) -> std::result::Result<Self, ExecutorError> {
        if verification_methods.is_empty() || verification_methods.len() > MAX_VERIFICATION_METHODS
        {
            return Err(ExecutorError::Truncated);
        }
        Ok(Self { verification_methods, deactivated })
    }

    pub fn verification_methods(&self) -> &[VerifyingKey] {
        &self.verification_methods
    }

    pub fn deactivated(&self) -> bool {
        self.deactivated
    }

    /// Binary encoding for use as a state value.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.verification_methods.len() as u8);
        for key in &self.verification_methods {
            buf.extend_from_slice(&key.to_bytes());
        }
        buf.push(u8::from(self.deactivated));
        buf
    }

    /// Decodes a `DidDocument` from its binary encoding.
    pub fn decode(cursor: &mut &[u8]) -> std::result::Result<Self, ExecutorError> {
        let num_keys = take_exact(cursor, 1)?[0] as usize;
        if num_keys == 0 || num_keys > MAX_VERIFICATION_METHODS {
            return Err(ExecutorError::Truncated);
        }
        let mut verification_methods = Vec::with_capacity(num_keys);
        for _ in 0..num_keys {
            let key_bytes = take_exact(cursor, 32)?;
            let arr: [u8; 32] = key_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
            let key = VerifyingKey::from_bytes(&arr).map_err(|_| ExecutorError::Truncated)?;
            verification_methods.push(key);
        }
        let deactivated_byte = take_exact(cursor, 1)?[0];
        let deactivated = deactivated_byte != 0;
        Ok(Self { verification_methods, deactivated })
    }
}

/// A DID operation decoded from a `Transaction` payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidOp {
    id: DidId,
    document: DidDocument,
    signature: Signature,
    signed_by: u8,
    is_creation: bool,
}

impl DidOp {
    pub fn new(
        id: DidId,
        document: DidDocument,
        signature: Signature,
        signed_by: u8,
        is_creation: bool,
    ) -> Self {
        Self { id, document, signature, signed_by, is_creation }
    }

    pub fn id(&self) -> &DidId {
        &self.id
    }

    pub fn document(&self) -> &DidDocument {
        &self.document
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signed_by(&self) -> u8 {
        self.signed_by
    }

    pub fn is_creation(&self) -> bool {
        self.is_creation
    }

    /// Decodes `payload` (the body after the `0x03` opcode) into a `DidOp`.
    pub fn decode(payload: &[u8]) -> Result<DidOp> {
        let mut cursor = payload;
        let id = DidId::decode(&mut cursor)?;
        let document = DidDocument::decode(&mut cursor)?;
        let sig_bytes = take_exact(&mut cursor, 64)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let signature = Signature::new(sig_arr);
        let signed_by = take_exact(&mut cursor, 1)?[0];
        let is_creation = take_exact(&mut cursor, 1)?[0] != 0;
        reject_trailing(cursor)?;
        Ok(Self { id, document, signature, signed_by, is_creation })
    }

    /// The canonical encoding of this operation — the inverse of
    /// [`DidOp::decode`]. `decode(&op.encode())` returns `Ok(op)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.id.encode());
        buf.extend_from_slice(&self.document.encode());
        buf.extend_from_slice(self.signature.as_bytes());
        buf.push(self.signed_by);
        buf.push(u8::from(self.is_creation));
        buf
    }

    /// The signed payload: `id.encode() || document.encode()`.
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut buf = self.id.encode();
        buf.extend_from_slice(&self.document.encode());
        buf
    }
}

/// Errors from parsing a DID identifier string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DidParseError {
    MissingPrefix,
    MissingSeparator,
    InvalidUuid,
}

// --- Private helpers ---

fn take_exact<'a>(
    cursor: &mut &'a [u8],
    len: usize,
) -> std::result::Result<&'a [u8], ExecutorError> {
    let head = cursor.get(..len).ok_or(ExecutorError::Truncated)?;
    *cursor = &cursor[len..];
    Ok(head)
}

fn take_bytes(cursor: &mut &[u8]) -> std::result::Result<Vec<u8>, ExecutorError> {
    let head = cursor.get(..4).ok_or(ExecutorError::Truncated)?;
    let len = u32::from_be_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let end = 4usize.checked_add(len).ok_or(ExecutorError::Truncated)?;
    let body = cursor.get(4..end).ok_or(ExecutorError::Truncated)?;
    let bytes = body.to_vec();
    *cursor = &cursor[end..];
    Ok(bytes)
}

fn reject_trailing(cursor: &[u8]) -> Result<()> {
    if cursor.is_empty() { Ok(()) } else { Err(ExecutorError::TrailingBytes) }
}

fn write_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn hex_decode_to(hex: &str, out: &mut [u8]) -> std::result::Result<(), ()> {
    if hex.len() != out.len() * 2 {
        return Err(());
    }
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = hex_digit(chunk[0]).ok_or(())?;
        let lo = hex_digit(chunk[1]).ok_or(())?;
        out[i] = (hi << 4) | lo;
    }
    Ok(())
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{
        Signer,
        SigningKey,
    };

    use super::*;

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn verifying_key(seed: u8) -> VerifyingKey {
        signing_key(seed).verifying_key()
    }

    fn sample_id() -> DidId {
        DidId::new("main".into(), "alice".into(), [1u8; 16])
    }

    fn sample_document() -> DidDocument {
        DidDocument::new(vec![verifying_key(1)], false).expect("valid doc")
    }

    fn sample_op() -> DidOp {
        let doc = sample_document();
        let id = sample_id();
        let payload = {
            let mut buf = id.encode();
            buf.extend_from_slice(&doc.encode());
            buf
        };
        let sig = signing_key(1).sign(&payload);
        DidOp {
            id,
            document: doc,
            signature: Signature::new(sig.to_bytes()),
            signed_by: 0,
            is_creation: true,
        }
    }

    // --- DidId round-trip ---

    #[test]
    fn did_id_round_trips_through_encode_decode() {
        let id = sample_id();
        let encoded = id.encode();
        let mut cursor = &encoded[..];
        let decoded = DidId::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, id);
        assert!(cursor.is_empty());
    }

    #[test]
    fn did_id_parse_and_display_round_trip() {
        let id = DidId::new("testnet".into(), "bob".into(), [0xab; 16]);
        let s = id.to_string();
        assert_eq!(s, "did:jkain:testnet:bob:abababababababababababababababab");
        let parsed = DidId::parse(&s).expect("parses");
        assert_eq!(parsed, id);
    }

    #[test]
    fn did_id_parse_rejects_missing_prefix() {
        assert_eq!(DidId::parse("not-a-did"), Err(DidParseError::MissingPrefix));
    }

    #[test]
    fn did_id_parse_rejects_missing_separator() {
        assert_eq!(DidId::parse("did:jkain:nosep"), Err(DidParseError::MissingSeparator));
    }

    #[test]
    fn did_id_parse_rejects_short_uuid() {
        assert_eq!(DidId::parse("did:jkain:main:alice:abcd"), Err(DidParseError::InvalidUuid));
    }

    #[test]
    fn did_id_parse_rejects_invalid_hex() {
        assert_eq!(
            DidId::parse("did:jkain:main:alice:zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"),
            Err(DidParseError::InvalidUuid)
        );
    }

    // --- DidDocument round-trip ---

    #[test]
    fn did_document_round_trips_through_encode_decode() {
        let doc = DidDocument::new(vec![verifying_key(1), verifying_key(2)], true).expect("valid");
        let encoded = doc.encode();
        let mut cursor = &encoded[..];
        let decoded = DidDocument::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, doc);
        assert!(cursor.is_empty());
    }

    #[test]
    fn did_document_rejects_zero_keys() {
        assert!(DidDocument::new(vec![], false).is_err());
    }

    #[test]
    fn did_document_rejects_six_keys() {
        let keys: Vec<VerifyingKey> = (0..6).map(verifying_key).collect();
        assert!(DidDocument::new(keys, false).is_err());
    }

    // --- DidOp round-trip ---

    #[test]
    fn did_op_round_trips_through_encode_decode() {
        let op = sample_op();
        let encoded = op.encode();
        let decoded = DidOp::decode(&encoded).expect("decodes");
        assert_eq!(decoded, op);
    }

    #[test]
    fn did_op_decode_rejects_empty_payload() {
        assert_eq!(DidOp::decode(&[]), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_op_decode_rejects_truncated_network() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&[0, 0, 0, 5]);
        payload.extend_from_slice(b"main");
        assert_eq!(DidOp::decode(&payload), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_op_decode_rejects_trailing_bytes() {
        let mut encoded = sample_op().encode();
        encoded.push(0xff);
        assert_eq!(DidOp::decode(&encoded), Err(ExecutorError::TrailingBytes));
    }

    // --- DidDocument decode-time rejects ---

    #[test]
    fn did_document_decode_rejects_zero_keys() {
        let buf = [0u8];
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_six_keys() {
        let mut buf = vec![6u8];
        buf.extend_from_slice(&[0u8; 6 * 32]);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_truncated_key() {
        let mut buf = vec![2u8];
        buf.extend_from_slice(&[0u8; 32]);
        buf.extend_from_slice(&[0u8; 10]);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_missing_deactivated_flag() {
        let mut buf = vec![1u8];
        buf.extend_from_slice(&[0u8; 32]);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_rejects_invalid_verifying_key_bytes() {
        let mut buf = vec![1u8];
        // A y-coordinate of 2 encodes no valid Edwards point.
        buf.extend_from_slice(&[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    // --- signed_payload consistency ---

    #[test]
    fn signed_payload_matches_id_and_document_encoding() {
        let op = sample_op();
        let mut expected = op.id().encode();
        expected.extend_from_slice(&op.document().encode());
        assert_eq!(op.signed_payload(), expected);
    }
}
