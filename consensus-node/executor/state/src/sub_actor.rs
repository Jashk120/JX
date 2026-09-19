//! Sub-actor records and their log leaves (PLAN-5 D-9).
//!
//! A sub-actor is an app-scoped identity HD-derived from the wallet's master
//! seed; on chain it materializes a record carrying its immutable
//! `control_key` and its mutable `operating_key` (day-to-day signer,
//! rebindable). Only the `control_key` enters the root's append-only
//! membership commitment, as the domain-separated leaf
//! `b"jkain:subactor-leaf:v1" || actor_id_len:u32BE || actor_id_bytes ||
//! control_key:32B` hashed with [`leaf_hash`](crate::merkle_log::leaf_hash);
//! operating-key rebinds deliberately stay outside the commitment.
//!
//! Record encoding: `actor_id.encode() || control_key:32B ||
//! operating_key:32B` (`ActorId::encode` is self-delimiting). Decode-time
//! deterministic rejects mirror `did.rs`.

use ed25519_dalek::VerifyingKey;
use primitives::Signature;

use crate::did::DidId;
use crate::error::{
    ExecutorError,
    Result,
};
use crate::merkle_log::{
    ConsistencyProof,
    Hash,
    InclusionProof,
};
use crate::root_actor::{
    ActorId,
    Tag,
};

/// Domain tag prefixing every sub-actor leaf preimage.
///
/// Fixed-length, NOT length-prefixed; it differs from every signed-payload
/// tag so a leaf preimage is never replayable as a signature preimage.
pub const SUBACTOR_LEAF_DOMAIN: &[u8] = b"jkain:subactor-leaf:v1";

/// A sub-actor record: its canonical [`ActorId`] plus the immutable control
/// key (committed in the root log) and the mutable operating key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubActor {
    actor_id: ActorId,
    control_key: VerifyingKey,
    operating_key: VerifyingKey,
}

impl SubActor {
    /// Builds a sub-actor record; rejects an [`ActorId::Root`].
    pub fn new(
        actor_id: ActorId,
        control_key: VerifyingKey,
        operating_key: VerifyingKey,
    ) -> Result<Self> {
        if matches!(actor_id, ActorId::Root(_)) {
            return Err(ExecutorError::ExpectedSubActor);
        }
        Ok(Self { actor_id, control_key, operating_key })
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn control_key(&self) -> &VerifyingKey {
        &self.control_key
    }

    pub fn operating_key(&self) -> &VerifyingKey {
        &self.operating_key
    }

    /// Binary encoding for use as a state value.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.actor_id.encode());
        buf.extend_from_slice(&self.control_key.to_bytes());
        buf.extend_from_slice(&self.operating_key.to_bytes());
        buf
    }

    /// Decodes a `SubActor`, advancing `cursor` past it. Rejects a root
    /// actor ID, like [`SubActor::new`].
    pub fn decode(cursor: &mut &[u8]) -> Result<Self> {
        let actor_id = ActorId::decode(cursor)?;
        if matches!(actor_id, ActorId::Root(_)) {
            return Err(ExecutorError::ExpectedSubActor);
        }
        let control_key = decode_key(cursor)?;
        let operating_key = decode_key(cursor)?;
        Ok(Self { actor_id, control_key, operating_key })
    }
}

/// The leaf preimage committed in the root log for a sub-actor:
/// `b"jkain:subactor-leaf:v1" || actor_id_len:u32BE || actor_id_bytes ||
/// control_key:32B`. The operating key is deliberately absent: rebinds must
/// not change the append-only commitment.
pub fn subactor_leaf_data(actor_id: &ActorId, control_key: &VerifyingKey) -> Vec<u8> {
    let id_bytes = actor_id.encode();
    let mut buf = Vec::with_capacity(SUBACTOR_LEAF_DOMAIN.len() + 4 + id_bytes.len() + 32);
    buf.extend_from_slice(SUBACTOR_LEAF_DOMAIN);
    buf.extend_from_slice(
        &u32::try_from(id_bytes.len()).expect("actor ID exceeds u32::MAX").to_be_bytes(),
    );
    buf.extend_from_slice(&id_bytes);
    buf.extend_from_slice(&control_key.to_bytes());
    buf
}

/// The RFC-6962 leaf hash of [`subactor_leaf_data`]: the value appended to
/// the root's log when the sub-actor is minted.
pub fn subactor_leaf_hash(actor_id: &ActorId, control_key: &VerifyingKey) -> Hash {
    crate::merkle_log::leaf_hash(&subactor_leaf_data(actor_id, control_key))
}

fn decode_key(cursor: &mut &[u8]) -> Result<VerifyingKey> {
    let bytes = take_exact(cursor, 32)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| ExecutorError::Truncated)
}

fn take_exact<'a>(cursor: &mut &'a [u8], len: usize) -> Result<&'a [u8]> {
    let head = cursor.get(..len).ok_or(ExecutorError::Truncated)?;
    *cursor = &cursor[len..];
    Ok(head)
}

fn reject_trailing(cursor: &[u8]) -> Result<()> {
    if cursor.is_empty() { Ok(()) } else { Err(ExecutorError::TrailingBytes) }
}

/// Domain tag prefixing every [`SubActorOp`] signed payload.
///
/// Fixed-length, NOT length-prefixed; `new_root` and both proofs are
/// deliberately absent from the payload they prefix (unsigned op input).
pub const SUBACTOR_SIGNED_DOMAIN: &[u8] = b"jkain:subactor:v1";
/// Domain tag prefixing every [`RebindOp`] signed payload.
pub const REBIND_SIGNED_DOMAIN: &[u8] = b"jkain:rebind:v1";
/// Exclusive upper bound for on-chain sub-actor indices (u31 only).
const MAX_SUB_ACTOR_INDEX_PLUS_ONE: u32 = 0x8000_0000;

/// A sub-actor mint operation decoded from a `Transaction` payload.
///
/// The opcode `0x04` is consumed by [`DecodedOp`](crate::op::DecodedOp);
/// the body is decoded by [`SubActorOp::decode`]:
///
/// ```text
/// [root_did.encode()]
/// [tag:u8][index:u32BE]
/// [control_key: 32B][operating_key: 32B][new_root: 32B]
/// [consistency_proof.encode()][inclusion_proof.encode()]
/// [signature: 64B][signed_by:u8]
/// ```
///
/// Both proofs are self-delimiting (`node_count`-framed) and are read with
/// cursor decoding. Decode-time deterministic rejects: unknown tag,
/// `index >= 0x8000_0000`, invalid Ed25519 points, truncation, trailing
/// bytes — same pattern as
/// [`ExecutorError::Truncated`](crate::error::ExecutorError::Truncated).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubActorOp {
    root_did: DidId,
    tag: Tag,
    index: u32,
    control_key: VerifyingKey,
    operating_key: VerifyingKey,
    new_root: Hash,
    consistency_proof: ConsistencyProof,
    inclusion_proof: InclusionProof,
    signature: Signature,
    signed_by: u8,
}

/// Grouped constructor parameters for [`SubActorOp::new`].
///
/// Ten fields cannot pass as positional arguments (the workspace denies
/// `clippy::too_many_arguments`), so they travel as one value object with
/// the same field names and types as [`SubActorOp`] itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubActorOpParams {
    pub root_did: DidId,
    pub tag: Tag,
    pub index: u32,
    pub control_key: VerifyingKey,
    pub operating_key: VerifyingKey,
    pub new_root: Hash,
    pub consistency_proof: ConsistencyProof,
    pub inclusion_proof: InclusionProof,
    pub signature: Signature,
    pub signed_by: u8,
}

impl SubActorOp {
    pub fn new(params: SubActorOpParams) -> Self {
        let SubActorOpParams {
            root_did,
            tag,
            index,
            control_key,
            operating_key,
            new_root,
            consistency_proof,
            inclusion_proof,
            signature,
            signed_by,
        } = params;
        Self {
            root_did,
            tag,
            index,
            control_key,
            operating_key,
            new_root,
            consistency_proof,
            inclusion_proof,
            signature,
            signed_by,
        }
    }

    pub fn root_did(&self) -> &DidId {
        &self.root_did
    }

    pub fn tag(&self) -> Tag {
        self.tag
    }

    pub fn index(&self) -> u32 {
        self.index
    }

    pub fn control_key(&self) -> &VerifyingKey {
        &self.control_key
    }

    pub fn operating_key(&self) -> &VerifyingKey {
        &self.operating_key
    }

    pub fn new_root(&self) -> &Hash {
        &self.new_root
    }

    pub fn consistency_proof(&self) -> &ConsistencyProof {
        &self.consistency_proof
    }

    pub fn inclusion_proof(&self) -> &InclusionProof {
        &self.inclusion_proof
    }

    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn signed_by(&self) -> u8 {
        self.signed_by
    }

    /// The canonical sub-actor identity this operation mints:
    /// `ActorId::Sub { root_did, tag, index }`.
    pub fn actor_id(&self) -> ActorId {
        ActorId::Sub { root_did: self.root_did.clone(), tag: self.tag, index: self.index }
    }

    /// Decodes `payload` (the body after the `0x04` opcode) into a `SubActorOp`.
    pub fn decode(payload: &[u8]) -> Result<SubActorOp> {
        let mut cursor = payload;
        let root_did = DidId::decode(&mut cursor)?;
        let tag_code = take_exact(&mut cursor, 1)?[0];
        let Some(tag) = Tag::from_code(tag_code) else {
            return Err(ExecutorError::UnknownActorTag(tag_code));
        };
        let index_bytes = take_exact(&mut cursor, 4)?;
        let index =
            u32::from_be_bytes(index_bytes.try_into().map_err(|_| ExecutorError::Truncated)?);
        if index >= MAX_SUB_ACTOR_INDEX_PLUS_ONE {
            return Err(ExecutorError::ActorIndexOutOfRange(index));
        }
        let control_key = decode_key(&mut cursor)?;
        let operating_key = decode_key(&mut cursor)?;
        let root_bytes = take_exact(&mut cursor, 32)?;
        let new_root: Hash = root_bytes.try_into().map_err(|_| ExecutorError::Truncated)?;
        let Some(consistency_proof) = ConsistencyProof::decode_from(&mut cursor) else {
            return Err(ExecutorError::Truncated);
        };
        let Some(inclusion_proof) = InclusionProof::decode_from(&mut cursor) else {
            return Err(ExecutorError::Truncated);
        };
        let sig_bytes = take_exact(&mut cursor, 64)?;
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes);
        let signature = Signature::new(sig_arr);
        let signed_by = take_exact(&mut cursor, 1)?[0];
        reject_trailing(cursor)?;
        Ok(Self {
            root_did,
            tag,
            index,
            control_key,
            operating_key,
            new_root,
            consistency_proof,
            inclusion_proof,
            signature,
            signed_by,
        })
    }

    /// The canonical encoding of this operation — the inverse of
    /// [`SubActorOp::decode`]. `decode(&op.encode())` returns `Ok(op)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.root_did.encode());
        buf.push(self.tag.code());
        buf.extend_from_slice(&self.index.to_be_bytes());
        buf.extend_from_slice(&self.control_key.to_bytes());
        buf.extend_from_slice(&self.operating_key.to_bytes());
        buf.extend_from_slice(&self.new_root);
        buf.extend_from_slice(&self.consistency_proof.encode());
        buf.extend_from_slice(&self.inclusion_proof.encode());
        buf.extend_from_slice(self.signature.as_bytes());
        buf.push(self.signed_by);
        buf
    }

    /// The signed payload: `b"jkain:subactor:v1" || actor_id_len:u32BE ||
    /// actor_id_bytes || control_key:32B || operating_key:32B`.
    ///
    /// `new_root` and both proofs are deliberately NOT signed: they are
    /// unsigned op input verified independently against state at apply time.
    pub fn signed_payload(&self) -> Vec<u8> {
        let id_bytes = self.actor_id().encode();
        let mut buf = Vec::from(SUBACTOR_SIGNED_DOMAIN);
        buf.extend_from_slice(
            &u32::try_from(id_bytes.len()).expect("actor ID exceeds u32::MAX").to_be_bytes(),
        );
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&self.control_key.to_bytes());
        buf.extend_from_slice(&self.operating_key.to_bytes());
        buf
    }
}

/// An operating-key rebind operation decoded from a `Transaction` payload.
///
/// The opcode `0x05` is consumed by [`DecodedOp`](crate::op::DecodedOp);
/// the body is decoded by [`RebindOp::decode`]:
///
/// ```text
/// [actor_id.encode()]
/// [new_operating_key: 32B]
/// [proof_of_possession: 64B][authorizing_signature: 64B]
/// ```
///
/// Phase A rebinds sub-actors only and is root-control-only: there is no
/// `signed_by` field, and a root actor ID is rejected at apply time (not
/// here). Decode-time deterministic rejects: truncation and trailing bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebindOp {
    actor_id: ActorId,
    new_operating_key: VerifyingKey,
    proof_of_possession: Signature,
    authorizing_signature: Signature,
}

impl RebindOp {
    pub fn new(
        actor_id: ActorId,
        new_operating_key: VerifyingKey,
        proof_of_possession: Signature,
        authorizing_signature: Signature,
    ) -> Self {
        Self { actor_id, new_operating_key, proof_of_possession, authorizing_signature }
    }

    pub fn actor_id(&self) -> &ActorId {
        &self.actor_id
    }

    pub fn new_operating_key(&self) -> &VerifyingKey {
        &self.new_operating_key
    }

    pub fn proof_of_possession(&self) -> &Signature {
        &self.proof_of_possession
    }

    pub fn authorizing_signature(&self) -> &Signature {
        &self.authorizing_signature
    }

    /// Decodes `payload` (the body after the `0x05` opcode) into a `RebindOp`.
    pub fn decode(payload: &[u8]) -> Result<RebindOp> {
        let mut cursor = payload;
        let actor_id = ActorId::decode(&mut cursor)?;
        let new_operating_key = decode_key(&mut cursor)?;
        let pop_bytes = take_exact(&mut cursor, 64)?;
        let mut pop_arr = [0u8; 64];
        pop_arr.copy_from_slice(pop_bytes);
        let auth_bytes = take_exact(&mut cursor, 64)?;
        let mut auth_arr = [0u8; 64];
        auth_arr.copy_from_slice(auth_bytes);
        reject_trailing(cursor)?;
        Ok(Self {
            actor_id,
            new_operating_key,
            proof_of_possession: Signature::new(pop_arr),
            authorizing_signature: Signature::new(auth_arr),
        })
    }

    /// The canonical encoding of this operation — the inverse of
    /// [`RebindOp::decode`]. `decode(&op.encode())` returns `Ok(op)`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&self.actor_id.encode());
        buf.extend_from_slice(&self.new_operating_key.to_bytes());
        buf.extend_from_slice(self.proof_of_possession.as_bytes());
        buf.extend_from_slice(self.authorizing_signature.as_bytes());
        buf
    }

    /// The signed payload: `b"jkain:rebind:v1" || actor_id_len:u32BE ||
    /// actor_id_bytes || old_operating_key:32B || new_operating_key:32B`.
    ///
    /// The old operating key comes from state at apply time, not from the
    /// op; both signatures cover exactly this payload.
    pub fn signed_payload(&self, old_operating_key: &VerifyingKey) -> Vec<u8> {
        let id_bytes = self.actor_id.encode();
        let mut buf = Vec::from(REBIND_SIGNED_DOMAIN);
        buf.extend_from_slice(
            &u32::try_from(id_bytes.len()).expect("actor ID exceeds u32::MAX").to_be_bytes(),
        );
        buf.extend_from_slice(&id_bytes);
        buf.extend_from_slice(&old_operating_key.to_bytes());
        buf.extend_from_slice(&self.new_operating_key.to_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::DidId;
    use crate::merkle_log::{
        mth,
        prove_consistency,
        prove_inclusion,
    };
    use crate::root_actor::Tag;

    fn verifying_key(seed: u8) -> VerifyingKey {
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32]).verifying_key()
    }

    fn sample_id() -> DidId {
        match DidId::new("main".into(), "alice".into(), [1u8; 16]) {
            Ok(id) => id,
            Err(e) => panic!("sample_id: {e:?}"),
        }
    }

    fn sample_sub_id() -> ActorId {
        ActorId::Sub { root_did: sample_id(), tag: Tag::Messenger, index: 3 }
    }

    #[test]
    fn sub_actor_round_trips_through_encode_decode() {
        let actor =
            SubActor::new(sample_sub_id(), verifying_key(4), verifying_key(5)).expect("valid");
        let encoded = actor.encode();
        let mut cursor = &encoded[..];
        let decoded = SubActor::decode(&mut cursor).expect("decodes");
        assert_eq!(decoded, actor);
        assert!(cursor.is_empty());
        assert_eq!(decoded.actor_id(), &sample_sub_id());
        assert_eq!(decoded.control_key(), &verifying_key(4));
        assert_eq!(decoded.operating_key(), &verifying_key(5));
    }

    #[test]
    fn sub_actor_new_rejects_root_id() {
        assert_eq!(
            SubActor::new(ActorId::Root(sample_id()), verifying_key(4), verifying_key(5)),
            Err(ExecutorError::ExpectedSubActor)
        );
    }

    #[test]
    fn sub_actor_decode_rejects_root_id() {
        let mut encoded = ActorId::Root(sample_id()).encode();
        encoded.extend_from_slice(&verifying_key(4).to_bytes());
        encoded.extend_from_slice(&verifying_key(5).to_bytes());
        let mut cursor = &encoded[..];
        assert_eq!(SubActor::decode(&mut cursor), Err(ExecutorError::ExpectedSubActor));
    }

    #[test]
    fn sub_actor_decode_rejects_truncated_key() {
        let actor =
            SubActor::new(sample_sub_id(), verifying_key(4), verifying_key(5)).expect("valid");
        let encoded = actor.encode();
        let mut cursor = &encoded[..encoded.len() - 1];
        assert_eq!(SubActor::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn sub_actor_decode_rejects_invalid_point() {
        let mut encoded = sample_sub_id().encode();
        encoded.extend_from_slice(&[2u8; 32]);
        encoded.extend_from_slice(&verifying_key(5).to_bytes());
        let mut cursor = &encoded[..];
        assert_eq!(SubActor::decode(&mut cursor), Err(ExecutorError::Truncated));
    }

    #[test]
    fn leaf_data_layout_matches_spec() {
        let control = verifying_key(4);
        let id_bytes = sample_sub_id().encode();
        let mut expected = Vec::from(SUBACTOR_LEAF_DOMAIN);
        expected.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&id_bytes);
        expected.extend_from_slice(&control.to_bytes());
        assert_eq!(subactor_leaf_data(&sample_sub_id(), &control), expected);
    }

    #[test]
    fn leaf_hash_is_rfc6962_leaf_of_leaf_data() {
        let control = verifying_key(4);
        assert_eq!(
            subactor_leaf_hash(&sample_sub_id(), &control),
            crate::merkle_log::leaf_hash(&subactor_leaf_data(&sample_sub_id(), &control))
        );
    }

    #[test]
    fn leaf_hash_ignores_operating_key() {
        // The commitment covers the immutable control key only.
        let control = verifying_key(4);
        let leaf = subactor_leaf_hash(&sample_sub_id(), &control);
        assert_eq!(leaf, subactor_leaf_hash(&sample_sub_id(), &control));
        assert_ne!(leaf, subactor_leaf_hash(&sample_sub_id(), &verifying_key(6)));
    }

    fn sample_sub_actor_op() -> SubActorOp {
        let actor_id = sample_sub_id();
        let control = verifying_key(4);
        let operating = verifying_key(5);
        let leaf = subactor_leaf_hash(&actor_id, &control);
        let leaves = [leaf];
        let new_root = mth(&leaves);
        let consistency_proof = prove_consistency(&leaves, 0).expect("bootstrap proves");
        let inclusion_proof = prove_inclusion(&leaves, 0).expect("in range");
        SubActorOp::new(SubActorOpParams {
            root_did: sample_id(),
            tag: Tag::Messenger,
            index: 3,
            control_key: control,
            operating_key: operating,
            new_root,
            consistency_proof,
            inclusion_proof,
            signature: primitives::Signature::new([7u8; 64]),
            signed_by: 0,
        })
    }

    fn sample_rebind_op() -> RebindOp {
        RebindOp::new(
            sample_sub_id(),
            verifying_key(6),
            primitives::Signature::new([7u8; 64]),
            primitives::Signature::new([8u8; 64]),
        )
    }

    #[test]
    fn sub_actor_op_round_trips_through_encode_decode() {
        let op = sample_sub_actor_op();
        let decoded = SubActorOp::decode(&op.encode()).expect("decodes");
        assert_eq!(decoded, op);
        assert_eq!(decoded.actor_id(), sample_sub_id());
        assert_eq!(decoded.root_did(), &sample_id());
        assert_eq!(decoded.tag(), Tag::Messenger);
        assert_eq!(decoded.index(), 3);
        assert_eq!(decoded.control_key(), &verifying_key(4));
        assert_eq!(decoded.operating_key(), &verifying_key(5));
        assert_eq!(decoded.signed_by(), 0);
    }

    #[test]
    fn sub_actor_op_decode_rejects_truncation() {
        let encoded = sample_sub_actor_op().encode();
        assert_eq!(
            SubActorOp::decode(&encoded[..encoded.len() - 1]),
            Err(ExecutorError::Truncated)
        );
        assert_eq!(SubActorOp::decode(&[]), Err(ExecutorError::Truncated));
    }

    #[test]
    fn sub_actor_op_decode_rejects_trailing_bytes() {
        let mut encoded = sample_sub_actor_op().encode();
        encoded.push(0xff);
        assert_eq!(SubActorOp::decode(&encoded), Err(ExecutorError::TrailingBytes));
    }

    #[test]
    fn sub_actor_op_decode_rejects_unknown_tag() {
        let mut encoded = sample_sub_actor_op().encode();
        let tag_pos = sample_id().encode().len();
        encoded[tag_pos] = 0x04;
        assert_eq!(SubActorOp::decode(&encoded), Err(ExecutorError::UnknownActorTag(0x04)));
    }

    #[test]
    fn sub_actor_op_decode_rejects_high_bit_index() {
        let mut encoded = sample_sub_actor_op().encode();
        let index_pos = sample_id().encode().len() + 1;
        encoded[index_pos..index_pos + 4].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        assert_eq!(
            SubActorOp::decode(&encoded),
            Err(ExecutorError::ActorIndexOutOfRange(0x8000_0000))
        );
    }

    #[test]
    fn sub_actor_op_decode_rejects_invalid_point() {
        let mut encoded = sample_sub_actor_op().encode();
        let key_pos = sample_id().encode().len() + 1 + 4;
        encoded[key_pos..key_pos + 32].copy_from_slice(&[2u8; 32]);
        assert_eq!(SubActorOp::decode(&encoded), Err(ExecutorError::Truncated));
    }

    #[test]
    fn sub_actor_op_signed_payload_layout_matches_spec() {
        let op = sample_sub_actor_op();
        let id_bytes = sample_sub_id().encode();
        let mut expected = Vec::from(SUBACTOR_SIGNED_DOMAIN);
        expected.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&id_bytes);
        expected.extend_from_slice(&verifying_key(4).to_bytes());
        expected.extend_from_slice(&verifying_key(5).to_bytes());
        assert_eq!(op.signed_payload(), expected);
    }

    #[test]
    fn rebind_op_round_trips_through_encode_decode() {
        let op = sample_rebind_op();
        let decoded = RebindOp::decode(&op.encode()).expect("decodes");
        assert_eq!(decoded, op);
        assert_eq!(decoded.actor_id(), &sample_sub_id());
        assert_eq!(decoded.new_operating_key(), &verifying_key(6));
    }

    #[test]
    fn rebind_op_decode_rejects_truncation_and_trailing() {
        let encoded = sample_rebind_op().encode();
        assert_eq!(RebindOp::decode(&encoded[..encoded.len() - 1]), Err(ExecutorError::Truncated));
        assert_eq!(RebindOp::decode(&[]), Err(ExecutorError::Truncated));
        let mut extended = encoded.clone();
        extended.push(0xff);
        assert_eq!(RebindOp::decode(&extended), Err(ExecutorError::TrailingBytes));
    }

    #[test]
    fn rebind_op_signed_payload_layout_matches_spec() {
        let op = sample_rebind_op();
        let old = verifying_key(5);
        let id_bytes = sample_sub_id().encode();
        let mut expected = Vec::from(REBIND_SIGNED_DOMAIN);
        expected.extend_from_slice(&(id_bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(&id_bytes);
        expected.extend_from_slice(&old.to_bytes());
        expected.extend_from_slice(&verifying_key(6).to_bytes());
        assert_eq!(op.signed_payload(&old), expected);
    }
}
