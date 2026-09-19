//! Canonical actor identity and root-actor records (PLAN-5 D-2/D-6/D-9).
//!
//! A DID functions as the person-level identity; creating one implicitly
//! creates a **root actor**: an index holding a Merkle commitment to its
//! sub-actor set, never the list itself. The root actor's `control_key` is
//! copied from the explicit [`DidDocument::control_key`](crate::did::DidDocument),
//! never derived from the `DidId` (which stays opaque).
//!
//! ```text
//! ActorId::Root(did)                    = 0x00 || DidId::encode()
//! ActorId::Sub { root_did, tag, index } = 0x01 || DidId::encode() || tag:u8 || index:u32BE
//! actor_state_key(id)                   = 0xA1 || ActorId::encode()
//! RootActor                             = did.encode() || merkle_root:32B || leaf_count:u64BE
//!                                         || control_key:32B
//! ```
//!
//! `tag` is informational (`0=defi, 1=messenger, 2=game, 3=generic`); decode
//! rejects `tag > 3` and `index >= 0x8000_0000` (u31), so an on-chain
//! `ActorId` can never name an index the HD derivation path cannot produce.
//! `DidId::encode` is self-delimiting, so the root record needs no length
//! prefixes. Decode-time deterministic rejects mirror `did.rs`: truncation
//! and invalid Ed25519 points surface as [`ExecutorError::Truncated`](crate::error::ExecutorError::Truncated).

use ed25519_dalek::VerifyingKey;

use crate::did::DidId;
use crate::error::{
    ExecutorError,
    Result,
};
use crate::merkle_log::Hash;

/// State-key prefix for actor records: `actor_state_key(id) = 0xA1 || id.encode()`.
pub const ACTOR_STATE_PREFIX: u8 = 0xA1;

/// Variant byte for [`ActorId::Root`].
const ACTOR_VARIANT_ROOT: u8 = 0x00;
/// Variant byte for [`ActorId::Sub`].
const ACTOR_VARIANT_SUB: u8 = 0x01;
/// Exclusive upper bound for sub-actor indices: only u31 values are valid.
const MAX_ACTOR_INDEX_PLUS_ONE: u32 = 0x8000_0000;

/// Descriptive tag of a sub-actor: which app scope it was derived for.
///
/// Informational only, never a permission gate. The codes double as the
/// D-5 HD path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tag {
    Defi = 0,
    Messenger = 1,
    Game = 2,
    Generic = 3,
}

impl Tag {
    /// The wire code of this tag (`0=defi, 1=messenger, 2=game, 3=generic`).
    pub fn code(self) -> u8 {
        self as u8
    }

    /// Resolves a wire code to a tag; `None` for `code > 3`.
    pub fn from_code(code: u8) -> Option<Tag> {
        match code {
            0 => Some(Tag::Defi),
            1 => Some(Tag::Messenger),
            2 => Some(Tag::Game),
            3 => Some(Tag::Generic),
            _ => None,
        }
    }
}

/// Canonical actor identity: either a DID's root actor or one tagged
/// sub-actor slot `(root_did, tag, index)`, unique per root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ActorId {
    Root(DidId),
    Sub { root_did: DidId, tag: Tag, index: u32 },
}

impl ActorId {
    /// Binary encoding: `0x00 || DidId::encode()` for roots, `0x01 ||
    /// DidId::encode() || tag:u8 || index:u32BE` for sub-actors.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        match self {
            Self::Root(did) => {
                buf.push(ACTOR_VARIANT_ROOT);
                buf.extend_from_slice(&did.encode());
            }
            Self::Sub { root_did, tag, index } => {
                buf.push(ACTOR_VARIANT_SUB);
                buf.extend_from_slice(&root_did.encode());
                buf.push(tag.code());
                buf.extend_from_slice(&index.to_be_bytes());
            }
        }
        buf
    }

    /// Decodes an `ActorId`, advancing `cursor` past it. Rejects an unknown
    /// variant byte, a `tag_code > 3`, and an `index >= 0x8000_0000`.
    pub fn decode(cursor: &mut &[u8]) -> Result<Self> {
        let variant = take_exact(cursor, 1)?[0];
        match variant {
            ACTOR_VARIANT_ROOT => {
                let did = DidId::decode(cursor)?;
                Ok(Self::Root(did))
            }
            ACTOR_VARIANT_SUB => {
                let root_did = DidId::decode(cursor)?;
                let tag_code = take_exact(cursor, 1)?[0];
                let Some(tag) = Tag::from_code(tag_code) else {
                    return Err(ExecutorError::UnknownActorTag(tag_code));
                };
                let index_bytes = take_exact(cursor, 4)?;
                let index = u32::from_be_bytes(
                    index_bytes.try_into().map_err(|_| ExecutorError::Truncated)?,
                );
                if index >= MAX_ACTOR_INDEX_PLUS_ONE {
                    return Err(ExecutorError::ActorIndexOutOfRange(index));
                }
                Ok(Self::Sub { root_did, tag, index })
            }
            other => Err(ExecutorError::UnknownActorIdVariant(other)),
        }
    }
}

/// The state key for an actor record: `0xA1 || id.encode()`.
///
/// Generic KV writes to the `0xA1` prefix are rejected at decode time, so
/// only the executor's validated actor transitions can populate these keys.
pub fn actor_state_key(id: &ActorId) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + id.encode().len());
    key.push(ACTOR_STATE_PREFIX);
    key.extend_from_slice(&id.encode());
    key
}

/// The root actor record: a DID's append-only sub-actor commitment.
///
/// `merkle_root` is an RFC-6962 root over domain-separated sub-actor leaf
/// hashes (see [`crate::merkle_log`]) with `leaf_count` leaves;
/// `control_key` mirrors the owning document's control key and is replaced
/// atomically on every DID rotation. Binary encoding: `did.encode() ||
/// merkle_root:32B || leaf_count:u64BE || control_key:32B`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootActor {
    did_id: DidId,
    merkle_root: Hash,
    leaf_count: u64,
    control_key: VerifyingKey,
}

impl RootActor {
    pub fn new(
        did_id: DidId,
        merkle_root: Hash,
        leaf_count: u64,
        control_key: VerifyingKey,
    ) -> Self {
        Self { did_id, merkle_root, leaf_count, control_key }
    }

    pub fn did_id(&self) -> &DidId {
        &self.did_id
    }

    pub fn merkle_root(&self) -> &Hash {
        &self.merkle_root
    }

    pub fn leaf_count(&self) -> u64 {
        self.leaf_count
    }

    pub fn control_key(&self) -> &VerifyingKey {
        &self.control_key
    }

    /// Binary encoding for use as a state value.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.did_id.encode());
        buf.extend_from_slice(&self.merkle_root);
        buf.extend_from_slice(&self.leaf_count.to_be_bytes());
        buf.extend_from_slice(&self.control_key.to_bytes());
        buf
    }

    /// Decodes a `RootActor`, advancing `cursor` past it.
    pub fn decode(cursor: &mut &[u8]) -> Result<Self> {
        let did_id = DidId::decode(cursor)?;
        let root_bytes = take_exact(cursor, 32)?;
        let merkle_root: Hash = root_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        let count_bytes = take_exact(cursor, 8)?;
        let leaf_count =
            u64::from_be_bytes(count_bytes.try_into().map_err(|_| ExecutorError::Truncated)?);
        let control_bytes = take_exact(cursor, 32)?;
        let control_arr: [u8; 32] =
            control_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        let control_key =
            VerifyingKey::from_bytes(&control_arr).map_err(|_| ExecutorError::Truncated)?;
        Ok(Self { did_id, merkle_root, leaf_count, control_key })
    }
}

fn take_exact<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let head = cursor.get(..len).ok_or(ExecutorError::Truncated)?;
    *cursor = &cursor[len..];
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle_log::EMPTY_ROOT;

    fn verifying_key(seed: u8) -> VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    fn sample_id() -> DidId {
        match DidId::new("main".into(), "alice".into(), [1u8; 16]) {
            Ok(id) => id,
            Err(e) => panic!("sample_id: {e:?}"),
        }
    }

    #[test]
    fn root_actor_id_round_trips_through_encode_decode() {
        let id = ActorId::Root(sample_id());
        let encoded = id.encode();
        assert_eq!(encoded[0], 0x00);
        let mut cursor = &encoded[..];
        let decoded = ActorId::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, id);
        assert!(cursor.is_empty());
    }

    #[test]
    fn sub_actor_id_round_trips_for_every_tag() {
        for (tag, code) in [(Tag::Defi, 0), (Tag::Messenger, 1), (Tag::Game, 2), (Tag::Generic, 3)]
        {
            let id = ActorId::Sub { root_did: sample_id(), tag, index: 42 };
            let encoded = id.encode();
            assert_eq!(encoded[0], 0x01);
            assert_eq!(encoded[encoded.len() - 5], code);
            assert_eq!(&encoded[encoded.len() - 4..], &42u32.to_be_bytes());
            let mut cursor = &encoded[..];
            let decoded = ActorId::decode(&mut cursor).expect("decodes");
            assert_eq!(decoded, id);
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn sub_actor_id_accepts_max_u31_index() {
        let id = ActorId::Sub { root_did: sample_id(), tag: Tag::Game, index: 0x7FFF_FFFF };
        let encoded = id.encode();
        let mut cursor = &encoded[..];
        assert_eq!(ActorId::decode(&mut cursor), Ok(id));
    }

    #[test]
    fn actor_id_decode_rejects_unknown_variant() {
        let mut bytes = vec![0x02];
        bytes.extend_from_slice(&sample_id().encode());
        let mut cursor = &bytes[..];
        assert_eq!(ActorId::decode(&mut cursor), Err(ExecutorError::UnknownActorIdVariant(0x02)));
    }

    #[test]
    fn actor_id_decode_rejects_unknown_tag() {
        let id = ActorId::Sub { root_did: sample_id(), tag: Tag::Defi, index: 0 };
        let mut encoded = id.encode();
        let tag_pos = encoded.len() - 5;
        encoded[tag_pos] = 0x04;
        let mut cursor = &encoded[..];
        assert_eq!(ActorId::decode(&mut cursor), Err(ExecutorError::UnknownActorTag(0x04)));
    }

    #[test]
    fn actor_id_decode_rejects_high_bit_index() {
        let id = ActorId::Sub { root_did: sample_id(), tag: Tag::Defi, index: 0 };
        let mut encoded = id.encode();
        let index_pos = encoded.len() - 4;
        encoded[index_pos..].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        let mut cursor = &encoded[..];
        assert_eq!(
            ActorId::decode(&mut cursor),
            Err(ExecutorError::ActorIndexOutOfRange(0x8000_0000))
        );
    }

    #[test]
    fn actor_id_decode_rejects_truncation() {
        let id = ActorId::Sub { root_did: sample_id(), tag: Tag::Messenger, index: 7 };
        let encoded = id.encode();
        assert_eq!(
            ActorId::decode(&mut &encoded[..encoded.len() - 1]),
            Err(ExecutorError::Truncated)
        );
        assert_eq!(ActorId::decode(&mut &[][..]), Err(ExecutorError::Truncated));
    }

    #[test]
    fn actor_state_key_is_a1_prefixed_id_encoding() {
        let id = ActorId::Root(sample_id());
        let key = actor_state_key(&id);
        assert_eq!(key[0], 0xA1);
        assert_eq!(&key[1..], &id.encode()[..]);
    }

    #[test]
    fn root_actor_round_trips_through_encode_decode() {
        let root = RootActor::new(sample_id(), EMPTY_ROOT, 0, verifying_key(9));
        let encoded = root.encode();
        let mut cursor = &encoded[..];
        let decoded = RootActor::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, root);
        assert!(cursor.is_empty());
        assert_eq!(decoded.did_id(), &sample_id());
        assert_eq!(decoded.merkle_root(), &EMPTY_ROOT);
        assert_eq!(decoded.leaf_count(), 0);
        assert_eq!(decoded.control_key(), &verifying_key(9));
    }

    #[test]
    fn root_actor_encode_layout_matches_spec() {
        let control = verifying_key(9);
        let root_hash = [0xabu8; 32];
        let root = RootActor::new(sample_id(), root_hash, 17, control);
        let mut expected = sample_id().encode();
        expected.extend_from_slice(&root_hash);
        expected.extend_from_slice(&17u64.to_be_bytes());
        expected.extend_from_slice(&control.to_bytes());
        assert_eq!(root.encode(), expected);
    }

    #[test]
    fn root_actor_decode_rejects_truncated_control_key() {
        let root = RootActor::new(sample_id(), EMPTY_ROOT, 0, verifying_key(9));
        let encoded = root.encode();
        let mut cursor = &encoded[..encoded.len() - 1];
        assert_eq!(RootActor::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn root_actor_decode_rejects_invalid_control_key_point() {
        let mut encoded = sample_id().encode();
        encoded.extend_from_slice(&EMPTY_ROOT);
        encoded.extend_from_slice(&0u64.to_be_bytes());
        encoded.extend_from_slice(&[2u8; 32]);
        let mut cursor = &encoded[..];
        assert_eq!(RootActor::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn tag_codes_round_trip() {
        for (tag, code) in [(Tag::Defi, 0), (Tag::Messenger, 1), (Tag::Game, 2), (Tag::Generic, 3)]
        {
            assert_eq!(tag.code(), code);
            assert_eq!(Tag::from_code(code), Some(tag));
        }
        assert_eq!(Tag::from_code(4), None);
    }
}
