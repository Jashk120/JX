//! The DID operation wire format (`did:jkain`).
//!
//! DID operations become a `Transaction` payload so they inherit consensus's
//! existing ordering and agreement machinery. A `Transaction`'s payload bytes
//! decode into exactly one [`DidOp`]; the executor applies it to the state by
//! storing the [`DidDocument`] under the [`did_state_key`] state key
//! (`0xD1 || DidId::encode()`).
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
//! [version: u8 (0x02)]
//! [control_key: 32 bytes Ed25519]
//! [num_methods: u8]
//! [method_type: u8][method_key: 32 bytes] × num_methods
//! [deactivated: u8 (0 or 1)]
//! [signature: 64 bytes]
//! [signed_by: u8]
//! [is_creation: u8 (0 or 1)]
//! ```
//!
//! `num_methods` must be in 1..=5 (maximum TOTAL methods); at least one
//! method must be Ed25519 signing (`0x01`); `0x02` is X25519 agreement.
//! `signed_by` indexes the FILTERED, in-document order of Ed25519 signing
//! methods only — never `control_key`, never an X25519 method. `is_creation`
//! distinguishes a DID creation (must target an absent identifier) from an
//! update or deactivation (must target an existing identifier). The signed
//! payload is `b"jkain:did:v1" || DidId::encode() || DidDocument::encode()`.
//!
//! Decode-time deterministic rejects: wrong version, unknown method type,
//! zero Ed25519 signing methods, empty or over-five method list, truncated
//! fields, invalid Ed25519 point — same pattern as
//! [`ExecutorError::Truncated`](crate::error::ExecutorError::Truncated).

use ed25519_dalek::VerifyingKey;
use primitives::Signature;

use crate::error::{
    ExecutorError,
    Result,
};

/// Version byte of the v2 [`DidDocument`] binary encoding.
pub const DID_DOCUMENT_VERSION: u8 = 0x02;
/// Method type tag for Ed25519 signing (`ed25519_dalek::VerifyingKey`).
pub const METHOD_TYPE_ED25519: u8 = 0x01;
/// Method type tag for X25519 agreement (`x25519_dalek::PublicKey`).
pub const METHOD_TYPE_X25519: u8 = 0x02;
/// State-key prefix for DID records: `did_state_key(id) = 0xD1 || id.encode()`.
pub const DID_STATE_PREFIX: u8 = 0xD1;
/// Domain tag prefixing every [`DidOp`] signed payload.
pub const DID_SIGNED_DOMAIN: &[u8] = b"jkain:did:v1";

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
    pub fn new(
        network: String,
        alias: String,
        uuid: [u8; UUID_LEN],
    ) -> std::result::Result<Self, DidParseError> {
        if network.contains(':') || alias.contains(':') {
            return Err(DidParseError::InvalidDid);
        }
        Ok(Self { network, alias, uuid })
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
        if network.contains(':') || alias.contains(':') || uuid_hex.contains(':') {
            return Err(DidParseError::InvalidDid);
        }
        if uuid_hex.len() != UUID_LEN * 2 {
            return Err(DidParseError::InvalidUuid);
        }
        let mut uuid = [0u8; UUID_LEN];
        hex_decode_to(uuid_hex, &mut uuid).map_err(|()| DidParseError::InvalidUuid)?;
        Ok(Self { network: network.to_owned(), alias: alias.to_owned(), uuid })
    }

    /// Binary encoding of the identifier itself (unprefixed).
    ///
    /// The state key is [`did_state_key`] (`0xD1 || encode()`); the
    /// [`DidOp`] signed payload uses this raw encoding after the domain tag.
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
        let network = String::from_utf8(network_bytes).map_err(|_| ExecutorError::InvalidDid)?;
        let alias = String::from_utf8(alias_bytes).map_err(|_| ExecutorError::InvalidDid)?;
        if network.contains(':') || alias.contains(':') {
            return Err(ExecutorError::InvalidDid);
        }
        let uuid: [u8; UUID_LEN] = uuid_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        Ok(Self { network, alias, uuid })
    }
}

impl std::fmt::Display for DidId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "did:jkain:{}:{}:{}", self.network, self.alias, hex_encode(&self.uuid))
    }
}

/// The state key for a DID record: `0xD1 || id.encode()`.
///
/// `DidId::encode()` itself is unchanged and stays raw/unprefixed; only the
/// state key carries the reserved `0xD1` prefix (generic KV writes to this
/// prefix are rejected at decode time).
pub fn did_state_key(id: &DidId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + id.encode().len());
    key.push(DID_STATE_PREFIX);
    key.extend_from_slice(&id.encode());
    key
}

/// A single type-tagged verification method of a [`DidDocument`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationMethod {
    /// Ed25519 signing method, addressable by `signed_by`.
    Signing(VerifyingKey),
    /// X25519 agreement method, never addressable by `signed_by`.
    Agreement(x25519_dalek::PublicKey),
}

impl VerificationMethod {
    /// The wire type tag: `0x01` for signing, `0x02` for agreement.
    pub fn method_type(&self) -> u8 {
        match self {
            Self::Signing(_) => METHOD_TYPE_ED25519,
            Self::Agreement(_) => METHOD_TYPE_X25519,
        }
    }

    /// The raw 32 bytes of the method key.
    pub fn key_bytes(&self) -> [u8; 32] {
        match self {
            Self::Signing(key) => key.to_bytes(),
            Self::Agreement(key) => key.to_bytes(),
        }
    }
}

/// A versioned v2 DID document: explicit Ed25519 `control_key` plus
/// type-tagged verification methods and a deactivated flag.
///
/// Binary encoding:
/// `[version:u8 = 0x02][control_key: 32B][num_methods:u8][(type:u8,key:32B) × num_methods][deactivated:u8]`
///
/// `num_methods` must be in 1..=5 (maximum TOTAL methods) and at least one
/// method must be Ed25519 signing. The `control_key` is independent of the
/// method list: it participates in the canonical encoding (and thus every
/// `DidOp` signature) and is never addressable by `signed_by`. The
/// `deactivated` flag is a tombstone: when true the DID is considered retired
/// but the state key remains present.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DidDocument {
    control_key: VerifyingKey,
    methods: Vec<VerificationMethod>,
    deactivated: bool,
}

impl DidDocument {
    pub fn new(
        control_key: VerifyingKey,
        methods: Vec<VerificationMethod>,
        deactivated: bool,
    ) -> std::result::Result<Self, ExecutorError> {
        if methods.is_empty() || methods.len() > MAX_VERIFICATION_METHODS {
            return Err(ExecutorError::Truncated);
        }
        if !methods.iter().any(|m| matches!(m, VerificationMethod::Signing(_))) {
            return Err(ExecutorError::NoSigningMethod);
        }
        Ok(Self { control_key, methods, deactivated })
    }

    pub fn control_key(&self) -> &VerifyingKey {
        &self.control_key
    }

    pub fn methods(&self) -> &[VerificationMethod] {
        &self.methods
    }

    pub fn deactivated(&self) -> bool {
        self.deactivated
    }

    /// Returns the `index`-th Ed25519 signing method in filtered,
    /// in-document order — skipping X25519 agreement methods.
    ///
    /// This is the only key `signed_by` can address: the `control_key` and
    /// agreement methods are never reachable through this accessor.
    pub fn signing_key(&self, index: usize) -> Option<&VerifyingKey> {
        self.methods
            .iter()
            .filter_map(|m| match m {
                VerificationMethod::Signing(key) => Some(key),
                VerificationMethod::Agreement(_) => None,
            })
            .nth(index)
    }

    /// Binary encoding for use as a state value.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(DID_DOCUMENT_VERSION);
        buf.extend_from_slice(&self.control_key.to_bytes());
        buf.push(self.methods.len() as u8);
        for method in &self.methods {
            buf.push(method.method_type());
            buf.extend_from_slice(&method.key_bytes());
        }
        buf.push(u8::from(self.deactivated));
        buf
    }

    /// Decodes a `DidDocument` from its binary encoding.
    pub fn decode(cursor: &mut &[u8]) -> std::result::Result<Self, ExecutorError> {
        let version = take_exact(cursor, 1)?[0];
        if version != DID_DOCUMENT_VERSION {
            return Err(ExecutorError::UnsupportedDidDocumentVersion(version));
        }
        let control_bytes = take_exact(cursor, 32)?;
        let control_arr: [u8; 32] =
            control_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        let control_key =
            VerifyingKey::from_bytes(&control_arr).map_err(|_| ExecutorError::Truncated)?;
        let num_methods = take_exact(cursor, 1)?[0] as usize;
        if num_methods == 0 || num_methods > MAX_VERIFICATION_METHODS {
            return Err(ExecutorError::Truncated);
        }
        let mut methods = Vec::with_capacity(num_methods);
        for _ in 0..num_methods {
            let method_type = take_exact(cursor, 1)?[0];
            let key_bytes = take_exact(cursor, 32)?;
            let arr: [u8; 32] = key_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
            match method_type {
                METHOD_TYPE_ED25519 => {
                    let key =
                        VerifyingKey::from_bytes(&arr).map_err(|_| ExecutorError::Truncated)?;
                    methods.push(VerificationMethod::Signing(key));
                }
                METHOD_TYPE_X25519 => {
                    methods.push(VerificationMethod::Agreement(x25519_dalek::PublicKey::from(arr)));
                }
                other => return Err(ExecutorError::UnknownVerificationMethodType(other)),
            }
        }
        let deactivated_byte = take_exact(cursor, 1)?[0];
        let deactivated = deactivated_byte != 0;
        if !methods.iter().any(|m| matches!(m, VerificationMethod::Signing(_))) {
            return Err(ExecutorError::NoSigningMethod);
        }
        Ok(Self { control_key, methods, deactivated })
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

    /// The signed payload: `b"jkain:did:v1" || id.encode() || document.encode()`.
    ///
    /// The domain tag is new in v2; `id.encode()` stays raw/unprefixed.
    pub fn signed_payload(&self) -> Vec<u8> {
        let mut buf = Vec::from(DID_SIGNED_DOMAIN);
        buf.extend_from_slice(&self.id.encode());
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
    InvalidDid,
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
    buf.extend_from_slice(
        &u32::try_from(bytes.len()).expect("bytes length exceeds u32::MAX").to_be_bytes(),
    );
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
        match DidId::new("main".into(), "alice".into(), [1u8; 16]) {
            Ok(id) => id,
            Err(e) => panic!("sample_id: {e:?}"),
        }
    }

    fn sample_document() -> DidDocument {
        DidDocument::new(
            verifying_key(9),
            vec![VerificationMethod::Signing(verifying_key(1))],
            false,
        )
        .expect("valid doc")
    }

    fn sample_op() -> DidOp {
        let doc = sample_document();
        let id = sample_id();
        let mut unsigned = DidOp {
            id,
            document: doc,
            signature: Signature::new([0u8; 64]),
            signed_by: 0,
            is_creation: true,
        };
        let sig = signing_key(1).sign(&unsigned.signed_payload());
        unsigned.signature = Signature::new(sig.to_bytes());
        unsigned
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
        let id = match DidId::new("testnet".into(), "bob".into(), [0xab; 16]) {
            Ok(id) => id,
            Err(e) => panic!("did_id: {e:?}"),
        };
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

    #[test]
    fn did_id_new_rejects_colon_in_network() {
        assert_eq!(
            DidId::new("main:net".into(), "alice".into(), [1u8; 16]),
            Err(DidParseError::InvalidDid)
        );
    }

    #[test]
    fn did_id_new_rejects_colon_in_alias() {
        assert_eq!(
            DidId::new("main".into(), "al:ice".into(), [1u8; 16]),
            Err(DidParseError::InvalidDid)
        );
    }

    #[test]
    fn did_id_parse_rejects_colon_in_alias() {
        let uuid_hex = "abababababababababababababababab";
        assert_eq!(
            DidId::parse(&format!("did:jkain:main:al:ice:{uuid_hex}")),
            Err(DidParseError::InvalidDid)
        );
    }

    #[test]
    fn did_id_parse_rejects_colon_in_network() {
        let uuid_hex = "abababababababababababababababab";
        assert_eq!(
            DidId::parse(&format!("did:jkain:main:net:alice:{uuid_hex}")),
            Err(DidParseError::InvalidDid)
        );
    }

    #[test]
    fn did_id_decode_rejects_colon_in_alias() {
        let mut corrupted = Vec::new();
        corrupted.extend_from_slice(&(4u32.to_be_bytes()));
        corrupted.extend_from_slice(b"main");
        corrupted.extend_from_slice(&(5u32.to_be_bytes()));
        corrupted.extend_from_slice(b"al:ce");
        corrupted.extend_from_slice(&[1u8; 16]);
        let mut cursor = &corrupted[..];
        assert_eq!(DidId::decode(&mut cursor), Err(ExecutorError::InvalidDid));
    }

    #[test]
    fn did_id_decode_rejects_non_utf8() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(2u32.to_be_bytes()));
        buf.extend_from_slice(&[0xff, 0xff]);
        buf.extend_from_slice(&(5u32.to_be_bytes()));
        buf.extend_from_slice(b"alice");
        buf.extend_from_slice(&[1u8; 16]);
        let mut cursor = &buf[..];
        assert_eq!(DidId::decode(&mut cursor), Err(ExecutorError::InvalidDid));
    }

    // --- did_state_key ---

    #[test]
    fn did_state_key_is_d1_prefixed_id_encoding() {
        let id = sample_id();
        let key = did_state_key(&id);
        assert_eq!(key[0], 0xD1);
        assert_eq!(&key[1..], &id.encode()[..]);
    }

    // --- DidDocument v2 round-trip ---

    #[test]
    fn did_document_v2_round_trips_with_control_key_and_x25519() {
        let doc = DidDocument::new(
            verifying_key(9),
            vec![
                VerificationMethod::Signing(verifying_key(1)),
                VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32])),
                VerificationMethod::Signing(verifying_key(2)),
            ],
            true,
        )
        .expect("valid");
        let encoded = doc.encode();
        assert_eq!(encoded[0], 0x02);
        let mut cursor = &encoded[..];
        let decoded = DidDocument::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, doc);
        assert!(cursor.is_empty());
    }

    #[test]
    fn did_document_encode_layout_matches_spec() {
        let control = verifying_key(9);
        let sign = verifying_key(1);
        let agree = x25519_dalek::PublicKey::from([7u8; 32]);
        let doc = DidDocument::new(
            control,
            vec![VerificationMethod::Signing(sign), VerificationMethod::Agreement(agree)],
            false,
        )
        .expect("valid");
        let mut expected = vec![0x02];
        expected.extend_from_slice(&control.to_bytes());
        expected.push(2);
        expected.push(0x01);
        expected.extend_from_slice(&sign.to_bytes());
        expected.push(0x02);
        expected.extend_from_slice(&agree.to_bytes());
        expected.push(0);
        assert_eq!(doc.encode(), expected);
    }

    #[test]
    fn did_document_new_rejects_zero_methods() {
        assert_eq!(
            DidDocument::new(verifying_key(9), vec![], false),
            Err(ExecutorError::Truncated)
        );
    }

    #[test]
    fn did_document_new_rejects_six_methods() {
        let methods: Vec<VerificationMethod> =
            (0..6).map(|i| VerificationMethod::Signing(verifying_key(i))).collect();
        assert_eq!(
            DidDocument::new(verifying_key(9), methods, false),
            Err(ExecutorError::Truncated)
        );
    }

    #[test]
    fn did_document_new_rejects_zero_signing_methods() {
        let methods = vec![VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32]))];
        assert_eq!(
            DidDocument::new(verifying_key(9), methods, false),
            Err(ExecutorError::NoSigningMethod)
        );
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

    // --- DidDocument v2 decode-time rejects ---

    fn encode_doc_prefix(version: u8, control: &[u8; 32]) -> Vec<u8> {
        let mut buf = vec![version];
        buf.extend_from_slice(control);
        buf
    }

    #[test]
    fn did_document_decode_rejects_bad_version() {
        let mut buf = encode_doc_prefix(0x01, &verifying_key(9).to_bytes());
        buf.push(1);
        buf.push(0x01);
        buf.extend_from_slice(&verifying_key(1).to_bytes());
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(
            DidDocument::decode(&mut cursor),
            Err(ExecutorError::UnsupportedDidDocumentVersion(0x01))
        );
    }

    #[test]
    fn did_document_decode_rejects_unknown_method_type() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(2);
        buf.push(0x01);
        buf.extend_from_slice(&verifying_key(1).to_bytes());
        buf.push(0x7f);
        buf.extend_from_slice(&[0u8; 32]);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(
            DidDocument::decode(&mut cursor),
            Err(ExecutorError::UnknownVerificationMethodType(0x7f))
        );
    }

    #[test]
    fn did_document_decode_rejects_zero_signing_methods() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(1);
        buf.push(0x02);
        buf.extend_from_slice(&[7u8; 32]);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::NoSigningMethod));
    }

    #[test]
    fn did_document_decode_rejects_zero_methods() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(0);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_six_methods() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(6);
        for _ in 0..6 {
            buf.push(0x01);
            buf.extend_from_slice(&verifying_key(1).to_bytes());
        }
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_truncated_control_key() {
        let buf = [0x02, 1, 2, 3];
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_truncated_key() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(2);
        buf.push(0x01);
        buf.extend_from_slice(&verifying_key(1).to_bytes());
        buf.push(0x01);
        buf.extend_from_slice(&[0u8; 10]);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_decode_rejects_missing_deactivated_flag() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(1);
        buf.push(0x01);
        buf.extend_from_slice(&verifying_key(1).to_bytes());
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_rejects_invalid_ed25519_point() {
        let mut buf = encode_doc_prefix(0x02, &verifying_key(9).to_bytes());
        buf.push(1);
        buf.push(0x01);
        // A y-coordinate of 2 encodes no valid Edwards point.
        buf.extend_from_slice(&[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn did_document_rejects_invalid_control_key_point() {
        let mut buf = vec![0x02];
        buf.extend_from_slice(&[
            2u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ]);
        buf.push(1);
        buf.push(0x01);
        buf.extend_from_slice(&verifying_key(1).to_bytes());
        buf.push(0);
        let mut cursor = &buf[..];
        assert_eq!(DidDocument::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    // --- signing_key semantics ---

    #[test]
    fn signing_key_skips_x25519_and_never_covers_control_key() {
        let control = verifying_key(9);
        let first = verifying_key(1);
        let second = verifying_key(2);
        let doc = DidDocument::new(
            control,
            vec![
                VerificationMethod::Agreement(x25519_dalek::PublicKey::from([7u8; 32])),
                VerificationMethod::Signing(first),
                VerificationMethod::Agreement(x25519_dalek::PublicKey::from([8u8; 32])),
                VerificationMethod::Signing(second),
            ],
            false,
        )
        .expect("valid");
        assert_eq!(doc.signing_key(0), Some(&first));
        assert_eq!(doc.signing_key(1), Some(&second));
        assert_eq!(doc.signing_key(2), None);
        assert_ne!(doc.signing_key(0), Some(&control));
        assert_ne!(doc.signing_key(1), Some(&control));
    }

    // --- signed_payload consistency ---

    #[test]
    fn signed_payload_matches_domain_tag_and_encodings() {
        let op = sample_op();
        let mut expected = Vec::from(b"jkain:did:v1".as_slice());
        expected.extend_from_slice(&op.id().encode());
        expected.extend_from_slice(&op.document().encode());
        assert_eq!(op.signed_payload(), expected);
    }
}
