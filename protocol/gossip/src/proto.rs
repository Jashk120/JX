use crypto::canonical::CanonicalEncode;
use primitives::{
    Event,
    EventHash,
    NodeId,
};

use crate::error::{
    GossipError,
    Result,
};

/// One byte that tells a reader how to parse the payload of a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    SyncRequest = 0x00,
    SyncResponse = 0x01,
    Event = 0x02,
    CheckpointSig = 0x03,
    Reconnect = 0x04,
    ReconnectResponse = 0x05,
    /// The responder's delta-computation failed because the requester is
    /// behind the history this node has pruned (Phase 4). The requester
    /// must reconnect from a checkpoint.
    Behind = 0x06,
}

impl MessageType {
    fn from_tag(tag: u8) -> Result<Self> {
        match tag {
            0x00 => Ok(Self::SyncRequest),
            0x01 => Ok(Self::SyncResponse),
            0x02 => Ok(Self::Event),
            0x03 => Ok(Self::CheckpointSig),
            0x04 => Ok(Self::Reconnect),
            0x05 => Ok(Self::ReconnectResponse),
            0x06 => Ok(Self::Behind),
            other => Err(GossipError::framing(format!("unknown message tag {other:#04x}"))),
        }
    }
}

/// A sync-round request (Consensus Spec §5): this node's `NodeId` plus a
/// compact per-creator summary of the events it already has, expressed as
/// the highest sequence number it holds from each creator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncRequest {
    pub from: NodeId,
    pub known: Vec<(NodeId, u64)>,
}

/// A sync-round response: the events the responder has that the requester
/// lacks, sent in topological order (parents before children) so the
/// requester can insert them without ever hitting a `MissingParent`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SyncResponse {
    pub events: Vec<Event>,
}

/// Phase 4 — the reconnect learner's request: "I need to reconnect from a
/// checkpoint." Carries nothing but the requester's identity; the teacher
/// answers with a [`ReconnectResponse`] on its dedicated reconnect port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectRequest {
    pub from: NodeId,
}

/// Phase 4 — the teacher's response: everything the learner needs to
/// bootstrap from a checkpoint and participate from that round onward.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReconnectResponse {
    /// The accepted checkpoint (self-describing: embeds the roster snapshot
    /// active at its round, plus the signatures over its signing bytes).
    pub signed_checkpoint: consensus::SignedCheckpoint,
    /// Raw `State::to_bytes()` exactly as it stood at the checkpoint round, so
    /// rebuilding the Merkle tree from it yields a root equal to
    /// `signed_checkpoint.payload.state_hash` and the learner's replay of the
    /// retained events newer than the checkpoint is exactly-once.
    pub state_bytes: Vec<u8>,
    /// Encoded [`consensus::RosterHistory`] (see `consensus::reconnect`).
    pub roster_history_bytes: Vec<u8>,
    /// The teacher's highest fully-decided round, so the learner can seed its
    /// decided-round set and continue producing checkpoints without
    /// re-deciding the history it already holds.
    pub decided_round: u64,
    /// The teacher's entire retained graph, with full record metadata. The
    /// learner inserts these as accepted history, so its known-summary
    /// frontier is honest (it holds full chains, not just per-creator heads)
    /// and subsequent delta syncs never reference a parent it lacks.
    pub retained: Vec<consensus::RetainedEvent>,
}

/// One unit of wire traffic on a gossip connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Frame {
    SyncRequest(SyncRequest),
    SyncResponse(SyncResponse),
    Event(Event),
    CheckpointSig(consensus::CheckpointSig),
    Reconnect(ReconnectRequest),
    ReconnectResponse(ReconnectResponse),
    /// The responder could not build a delta for the requester because the
    /// requester is behind the history the responder has pruned.
    Behind,
}

impl Frame {
    pub fn message_type(&self) -> MessageType {
        match self {
            Self::SyncRequest(_) => MessageType::SyncRequest,
            Self::SyncResponse(_) => MessageType::SyncResponse,
            Self::Event(_) => MessageType::Event,
            Self::CheckpointSig(_) => MessageType::CheckpointSig,
            Self::Reconnect(_) => MessageType::Reconnect,
            Self::ReconnectResponse(_) => MessageType::ReconnectResponse,
            Self::Behind => MessageType::Behind,
        }
    }

    /// Serializes to the on-wire form: `[tag: u8][len: u32 BE][payload]`,
    /// where `len` is the payload length in bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut payload = Vec::new();
        match self {
            Self::SyncRequest(req) => req.encode_canonical(&mut payload),
            Self::SyncResponse(resp) => resp.encode_canonical(&mut payload),
            Self::Event(event) => event.encode_canonical(&mut payload),
            Self::CheckpointSig(sig) => sig.encode_canonical(&mut payload),
            Self::Reconnect(req) => {
                req.from.encode_canonical(&mut payload);
            }
            Self::ReconnectResponse(resp) => {
                let cp_bytes =
                    consensus::reconnect::encode_signed_checkpoint(&resp.signed_checkpoint);
                payload.extend_from_slice(&(cp_bytes.len() as u32).to_be_bytes());
                payload.extend_from_slice(&cp_bytes);
                payload.extend_from_slice(&(resp.state_bytes.len() as u32).to_be_bytes());
                payload.extend_from_slice(&resp.state_bytes);
                payload.extend_from_slice(&(resp.roster_history_bytes.len() as u32).to_be_bytes());
                payload.extend_from_slice(&resp.roster_history_bytes);
                payload.extend_from_slice(&resp.decided_round.to_be_bytes());
                payload.extend_from_slice(&(resp.retained.len() as u32).to_be_bytes());
                for retained in &resp.retained {
                    payload.extend_from_slice(&retained.seq.to_be_bytes());
                    payload.extend_from_slice(&retained.round.to_be_bytes());
                    match retained.round_received {
                        Some(rr) => {
                            payload.push(0x01);
                            payload.extend_from_slice(&rr.to_be_bytes());
                        }
                        None => payload.push(0x00),
                    }
                    payload.extend_from_slice(&(retained.ancestor_seqs.len() as u32).to_be_bytes());
                    for seq in &retained.ancestor_seqs {
                        payload.extend_from_slice(&seq.to_be_bytes());
                    }
                    let event_bytes = retained.event.canonical_bytes();
                    payload.extend_from_slice(&(event_bytes.len() as u32).to_be_bytes());
                    payload.extend_from_slice(&event_bytes);
                }
            }
            Self::Behind => {}
        }

        let mut out = Vec::with_capacity(5 + payload.len());
        out.push(self.message_type() as u8);
        out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Parses a complete frame (including the tag and length prefix) that
    /// was produced by [`Self::to_bytes`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 5 {
            return Err(GossipError::framing(format!("frame too short: {} bytes", bytes.len())));
        }
        let tag = bytes[0];
        let len = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
        if bytes.len() != 5 + len {
            return Err(GossipError::framing(format!(
                "frame length mismatch: prefix says {len}, buffer has {}",
                bytes.len() - 5
            )));
        }
        let payload = &bytes[5..];
        match MessageType::from_tag(tag)? {
            MessageType::SyncRequest => Ok(Self::SyncRequest(SyncRequest::decode(payload)?)),
            MessageType::SyncResponse => Ok(Self::SyncResponse(SyncResponse::decode(payload)?)),
            MessageType::Event => {
                let mut cursor = Cursor::new(payload);
                let event = decode_event(&mut cursor)?;
                cursor.finish()?;
                Ok(Self::Event(event))
            }
            MessageType::CheckpointSig => {
                let sig = consensus::CheckpointSig::decode(payload)
                    .ok_or_else(|| GossipError::framing("invalid checkpoint signature frame"))?;
                Ok(Self::CheckpointSig(sig))
            }
            MessageType::Reconnect => {
                let mut cursor = Cursor::new(payload);
                let from = decode_node_id(&mut cursor)?;
                cursor.finish()?;
                Ok(Self::Reconnect(ReconnectRequest { from }))
            }
            MessageType::ReconnectResponse => {
                let mut cursor = Cursor::new(payload);
                let cp_len = cursor.read_u32()? as usize;
                let cp_bytes = cursor.read(cp_len)?;
                let signed_checkpoint = consensus::reconnect::decode_signed_checkpoint(cp_bytes)
                    .ok_or_else(|| {
                        GossipError::framing("invalid signed checkpoint in reconnect response")
                    })?;
                let state_len = cursor.read_u32()? as usize;
                let state_bytes = cursor.read(state_len)?.to_vec();
                let rh_len = cursor.read_u32()? as usize;
                let roster_history_bytes = cursor.read(rh_len)?.to_vec();
                let decided_round = cursor.read_u64()?;
                let retained_count = cursor.read_u32()? as usize;
                const MIN_RETAINED: usize = 8 + 8 + 1 + 4 + 4 + 86; // seq + round + rr_tag + ancestor_count + event_len + event
                if retained_count > cursor.remaining() / MIN_RETAINED {
                    return Err(GossipError::framing("declared count exceeds remaining buffer"));
                }
                let mut retained = Vec::with_capacity(retained_count);
                for _ in 0..retained_count {
                    let seq = cursor.read_u64()?;
                    let round = cursor.read_u64()?;
                    let round_received = match cursor.read(1)?[0] {
                        0x00 => None,
                        0x01 => Some(cursor.read_u64()?),
                        other => {
                            return Err(GossipError::framing(format!(
                                "invalid round-received tag {other:#04x}"
                            )));
                        }
                    };
                    let ancestor_count = cursor.read_u32()? as usize;
                    const MIN_ANCESTOR_SEQ: usize = 8; // u64
                    if ancestor_count > cursor.remaining() / MIN_ANCESTOR_SEQ {
                        return Err(GossipError::framing(
                            "declared count exceeds remaining buffer",
                        ));
                    }
                    let mut ancestor_seqs = Vec::with_capacity(ancestor_count);
                    for _ in 0..ancestor_count {
                        ancestor_seqs.push(cursor.read_u64()?);
                    }
                    let event_len = cursor.read_u32()? as usize;
                    let event_bytes = cursor.read(event_len)?;
                    let mut event_cursor = Cursor::new(event_bytes);
                    let event = decode_event(&mut event_cursor)?;
                    event_cursor.finish()?;
                    retained.push(consensus::RetainedEvent {
                        event,
                        seq,
                        round,
                        ancestor_seqs,
                        round_received,
                    });
                }
                cursor.finish()?;
                Ok(Self::ReconnectResponse(ReconnectResponse {
                    signed_checkpoint,
                    state_bytes,
                    roster_history_bytes,
                    decided_round,
                    retained,
                }))
            }
            MessageType::Behind => {
                let cursor = Cursor::new(payload);
                cursor.finish()?;
                Ok(Self::Behind)
            }
        }
    }
}

impl CanonicalEncode for SyncRequest {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        self.from.encode_canonical(buf);
        buf.extend_from_slice(&(self.known.len() as u32).to_be_bytes());
        for &(node, seq) in &self.known {
            node.encode_canonical(buf);
            buf.extend_from_slice(&seq.to_be_bytes());
        }
    }
}

impl SyncRequest {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let from = decode_node_id(&mut cursor)?;
        let count = cursor.read_u32()? as usize;
        const MIN_KNOWN_ENTRY: usize = 8 + 8; // NodeId + u64 seq
        if count > cursor.remaining() / MIN_KNOWN_ENTRY {
            return Err(GossipError::framing("declared count exceeds remaining buffer"));
        }
        let mut known = Vec::with_capacity(count);
        for _ in 0..count {
            let node = decode_node_id(&mut cursor)?;
            let seq = cursor.read_u64()?;
            known.push((node, seq));
        }
        cursor.finish()?;
        Ok(Self { from, known })
    }
}

impl CanonicalEncode for SyncResponse {
    fn encode_canonical(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&(self.events.len() as u32).to_be_bytes());
        for event in &self.events {
            event.encode_canonical(buf);
        }
    }
}

impl SyncResponse {
    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cursor = Cursor::new(bytes);
        let count = cursor.read_u32()? as usize;
        const MIN_EVENT: usize = 8 + 1 + 1 + 8 + 4 + 64; // creator + 2 opt hashes + timestamp + payload_len + sig
        if count > cursor.remaining() / MIN_EVENT {
            return Err(GossipError::framing("declared count exceeds remaining buffer"));
        }
        let mut events = Vec::with_capacity(count);
        for _ in 0..count {
            events.push(decode_event(&mut cursor)?);
        }
        cursor.finish()?;
        Ok(Self { events })
    }
}

/// A byte-cursor over a frame payload with bounds-checked reads.
struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn read(&mut self, len: usize) -> Result<&'a [u8]> {
        let end =
            self.pos.checked_add(len).ok_or_else(|| GossipError::framing("cursor overflow"))?;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| GossipError::framing("truncated frame payload"))?;
        self.pos = end;
        Ok(slice)
    }

    fn read_u32(&mut self) -> Result<u32> {
        let bytes = self.read(4)?;
        let arr: [u8; 4] = bytes
            .try_into()
            .map_err(|_| GossipError::framing("internal cursor read length mismatch"))?;
        Ok(u32::from_be_bytes(arr))
    }

    fn read_u64(&mut self) -> Result<u64> {
        let bytes = self.read(8)?;
        let arr: [u8; 8] = bytes
            .try_into()
            .map_err(|_| GossipError::framing("internal cursor read length mismatch"))?;
        Ok(u64::from_be_bytes(arr))
    }

    fn finish(&self) -> Result<()> {
        if self.pos == self.bytes.len() {
            Ok(())
        } else {
            Err(GossipError::framing(format!(
                "{} trailing bytes after payload",
                self.bytes.len() - self.pos
            )))
        }
    }
}

fn decode_node_id(cursor: &mut Cursor<'_>) -> Result<NodeId> {
    let id = cursor.read_u64()?;
    Ok(NodeId::new(id))
}

fn decode_event(cursor: &mut Cursor<'_>) -> Result<Event> {
    // Mirror the field order of `CanonicalEncode for Event`:
    // creator, self_parent, other_parent, timestamp, payload, signature.
    let creator = decode_node_id(cursor)?;
    let self_parent = decode_optional_hash(cursor)?;
    let other_parent = decode_optional_hash(cursor)?;
    let timestamp = cursor.read_u64()?;
    let payload_count = cursor.read_u32()? as usize;
    const MIN_TX: usize = 4; // tx_len prefix
    if payload_count > cursor.remaining() / MIN_TX {
        return Err(GossipError::framing("declared count exceeds remaining buffer"));
    }
    let mut payload = Vec::with_capacity(payload_count);
    for _ in 0..payload_count {
        let tx_len = cursor.read_u32()? as usize;
        let tx_bytes = cursor.read(tx_len)?;
        payload.push(primitives::Transaction::from_bytes(tx_bytes.to_vec()));
    }
    let signature = cursor.read(64)?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let signature = primitives::Signature::new(sig_bytes);

    let unsigned = primitives::UnsignedEvent::new(
        creator,
        self_parent,
        other_parent,
        primitives::Timestamp::new(timestamp),
        payload,
    );
    Ok(unsigned.finalize(signature))
}

fn decode_optional_hash(cursor: &mut Cursor<'_>) -> Result<Option<EventHash>> {
    let tag = cursor.read(1)?[0];
    match tag {
        0x00 => Ok(None),
        0x01 => {
            let bytes = cursor.read(32)?;
            let mut hash_bytes = [0u8; 32];
            hash_bytes.copy_from_slice(bytes);
            Ok(Some(EventHash::new(hash_bytes)))
        }
        other => Err(GossipError::framing(format!("invalid optional-hash tag {other:#04x}"))),
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use primitives::{
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };

    use super::*;

    fn sample_event(payload_len: usize) -> Event {
        let unsigned = UnsignedEvent::new(
            NodeId::new(7),
            Some(EventHash::new([1; 32])),
            None,
            Timestamp::new(1234),
            vec![Transaction::from_bytes(vec![7u8; payload_len])],
        );
        unsigned.finalize(Signature::new([2; 64]))
    }

    #[test]
    fn sync_request_round_trips() {
        let request = SyncRequest {
            from: NodeId::new(3),
            known: vec![(NodeId::new(1), 5), (NodeId::new(2), 0)],
        };
        let frame = Frame::SyncRequest(request.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::SyncRequest(request));
    }

    #[test]
    fn sync_response_round_trips() {
        let response = SyncResponse { events: vec![sample_event(4), sample_event(64)] };
        let frame = Frame::SyncResponse(response.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::SyncResponse(response));
    }

    #[test]
    fn event_frame_round_trips() {
        let event = sample_event(100);
        let frame = Frame::Event(event.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::Event(event));
    }

    #[test]
    fn event_with_both_parents_and_no_payload_round_trips() {
        let event = UnsignedEvent::new(
            NodeId::new(1),
            Some(EventHash::new([3; 32])),
            Some(EventHash::new([4; 32])),
            Timestamp::new(9),
            Vec::new(),
        )
        .finalize(Signature::new([5; 64]));
        let decoded = Frame::from_bytes(&Frame::Event(event.clone()).to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::Event(event));
    }

    #[test]
    fn checkpoint_sig_frame_round_trips() {
        let sig = consensus::CheckpointSig {
            round: 42,
            signer: NodeId::new(7),
            sig: Signature::new([9; 64]),
        };
        let frame = Frame::CheckpointSig(sig.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::CheckpointSig(sig));
        assert_eq!(frame.message_type(), MessageType::CheckpointSig);
    }

    #[test]
    fn frame_carries_correct_message_type_tag() {
        assert_eq!(
            Frame::SyncRequest(SyncRequest { from: NodeId::new(1), known: Vec::new() })
                .message_type(),
            MessageType::SyncRequest
        );
        assert_eq!(
            Frame::SyncResponse(SyncResponse { events: Vec::new() }).message_type(),
            MessageType::SyncResponse
        );
        assert_eq!(Frame::Event(sample_event(1)).message_type(), MessageType::Event);
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let bytes = Frame::Event(sample_event(1)).to_bytes();
        assert!(Frame::from_bytes(&bytes[..bytes.len() - 3]).is_err());
    }

    #[test]
    fn corrupt_length_is_rejected() {
        let bytes = Frame::Event(sample_event(1)).to_bytes();
        assert!(Frame::from_bytes(&bytes[..8]).is_err());
    }

    #[test]
    fn unknown_tag_is_rejected() {
        let mut bytes =
            Frame::SyncRequest(SyncRequest { from: NodeId::new(1), known: Vec::new() }).to_bytes();
        bytes[0] = 0xFF;
        assert!(Frame::from_bytes(&bytes).is_err());
    }

    #[test]
    fn reconnect_request_round_trips() {
        let request = ReconnectRequest { from: NodeId::new(3) };
        let frame = Frame::Reconnect(request.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::Reconnect(request));
        assert_eq!(frame.message_type(), MessageType::Reconnect);
    }

    #[test]
    fn behind_frame_round_trips() {
        let frame = Frame::Behind;
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(decoded, Frame::Behind);
        assert_eq!(frame.message_type(), MessageType::Behind);
    }

    /// A real `SignedCheckpoint`-bearing response with a live roster, one
    /// retained event, and an encoded roster history — the full wire shape
    /// the reconnect protocol uses.
    fn sample_reconnect_response() -> ReconnectResponse {
        let mut registry = crypto::MembershipRegistry::new();
        for id in [1u64, 2, 3] {
            let key = SigningKey::from_bytes(&[id as u8; 32]);
            registry.register(NodeId::new(id), key.verifying_key());
        }
        let payload = consensus::CheckpointPayload::new(4, [7u8; 32], registry.clone());
        let sigs = vec![consensus::CheckpointSig {
            round: 4,
            signer: NodeId::new(1),
            sig: Signature::new([9; 64]),
        }];
        let roster_history = crypto::RosterHistory::new(registry);
        ReconnectResponse {
            signed_checkpoint: consensus::SignedCheckpoint { payload, sigs },
            state_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
            roster_history_bytes: consensus::reconnect::encode_roster_history(&roster_history),
            decided_round: 6,
            retained: vec![consensus::RetainedEvent {
                event: sample_event(3),
                seq: 2,
                round: 1,
                ancestor_seqs: vec![2, 0, 0],
                round_received: Some(1),
            }],
        }
    }

    #[test]
    fn reconnect_response_round_trips() {
        let response = sample_reconnect_response();
        let frame = Frame::ReconnectResponse(response.clone());
        let decoded = Frame::from_bytes(&frame.to_bytes()).expect("parses");
        assert_eq!(frame.message_type(), MessageType::ReconnectResponse);

        let Frame::ReconnectResponse(decoded) = decoded else {
            panic!("decoded to the wrong frame type");
        };
        assert_eq!(decoded, response);
    }

    #[test]
    fn reconnect_response_rejects_truncated_payload() {
        let bytes = Frame::ReconnectResponse(sample_reconnect_response()).to_bytes();
        // Cutting inside the checkpoint/state/roster/frontier regions.
        for cut in [5, 40, 80, bytes.len() - 10] {
            assert!(Frame::from_bytes(&bytes[..cut]).is_err(), "cut at {cut}");
        }
    }

    #[test]
    fn sync_request_oversized_count_rejected() {
        // A SyncRequest whose declared `count` of known entries vastly exceeds
        // the remaining buffer. The capacity guard from commit b6a53a5 must
        // reject this before any allocation or loop iteration.
        let mut payload = Vec::new();
        // NodeId (8 bytes)
        payload.extend_from_slice(&1u64.to_be_bytes());
        // count = u32::MAX — only 4 bytes of payload remain after the NodeId.
        payload.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut frame = vec![MessageType::SyncRequest as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg == "declared count exceeds remaining buffer"),
            "SyncRequest with bogus count must be rejected"
        );
    }

    #[test]
    fn sync_response_oversized_count_rejected() {
        // A SyncResponse whose declared `count` of events exceeds what the
        // buffer could possibly contain. Must trigger the capacity guard
        // from commit b6a53a5.
        let mut frame = vec![MessageType::SyncResponse as u8];
        frame.extend_from_slice(&(4u32).to_be_bytes()); // len = 4
        frame.extend_from_slice(&u32::MAX.to_be_bytes()); // count = u32::MAX
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg == "declared count exceeds remaining buffer"),
            "SyncResponse with bogus count must be rejected"
        );
    }

    #[test]
    fn reconnect_response_oversized_retained_count_rejected() {
        // A ReconnectResponse whose declared `retained_count` exceeds what
        // the buffer can hold. The capacity guard (commit b6a53a5) must
        // reject before allocation.
        let response = sample_reconnect_response();
        let mut payload = Vec::new();
        // Checkpoint encoded bytes.
        let cp_bytes = consensus::reconnect::encode_signed_checkpoint(&response.signed_checkpoint);
        payload.extend_from_slice(&(cp_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&cp_bytes);
        // State bytes.
        payload.extend_from_slice(&(response.state_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.state_bytes);
        // Roster history bytes.
        payload.extend_from_slice(&(response.roster_history_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.roster_history_bytes);
        // Decided round.
        payload.extend_from_slice(&response.decided_round.to_be_bytes());
        // Retained count — absurdly large, no real entries follow.
        payload.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut frame = vec![MessageType::ReconnectResponse as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg == "declared count exceeds remaining buffer"),
            "ReconnectResponse with bogus retained_count must be rejected"
        );
    }

    #[test]
    fn reconnect_response_oversized_ancestor_count_rejected() {
        // A ReconnectResponse with a valid retained_count of 1, but the
        // single entry declares an ancestor_count that exceeds the buffer.
        // The inner capacity guard (commit b6a53a5) must catch this.
        let response = sample_reconnect_response();
        let mut payload = Vec::new();
        let cp_bytes = consensus::reconnect::encode_signed_checkpoint(&response.signed_checkpoint);
        payload.extend_from_slice(&(cp_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&cp_bytes);
        payload.extend_from_slice(&(response.state_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.state_bytes);
        payload.extend_from_slice(&(response.roster_history_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.roster_history_bytes);
        payload.extend_from_slice(&response.decided_round.to_be_bytes());
        // retained_count = 1
        payload.extend_from_slice(&1u32.to_be_bytes());
        // seq (u64)
        payload.extend_from_slice(&0u64.to_be_bytes());
        // round (u64)
        payload.extend_from_slice(&1u64.to_be_bytes());
        // round_received tag = 0x00 (None)
        payload.push(0x00);
        // ancestor_count = u32::MAX — far more than the buffer can hold.
        payload.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut frame = vec![MessageType::ReconnectResponse as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg == "declared count exceeds remaining buffer"),
            "ReconnectResponse with oversized ancestor_count must be rejected"
        );
    }

    #[test]
    fn event_oversized_payload_count_rejected() {
        // An Event frame whose payload_count exceeds the remaining buffer.
        // The capacity guard in decode_event (commit b6a53a5) must reject.
        let mut event_payload = Vec::new();
        // creator (NodeId, u64)
        event_payload.extend_from_slice(&1u64.to_be_bytes());
        // self_parent tag = 0x00 (None)
        event_payload.push(0x00);
        // other_parent tag = 0x00 (None)
        event_payload.push(0x00);
        // timestamp (u64)
        event_payload.extend_from_slice(&100u64.to_be_bytes());
        // payload_count = u32::MAX — the buffer is only ~21 bytes.
        event_payload.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut frame = vec![MessageType::Event as u8];
        frame.extend_from_slice(&(event_payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&event_payload);
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg == "declared count exceeds remaining buffer"),
            "Event with oversized payload_count must be rejected"
        );
    }

    #[test]
    fn event_invalid_optional_hash_tag_rejected() {
        // An Event frame whose self_parent tag is neither 0x00 nor 0x01.
        // decode_optional_hash must return a framing error.
        let mut event_payload = Vec::new();
        event_payload.extend_from_slice(&1u64.to_be_bytes()); // creator
        event_payload.push(0xFF); // invalid self_parent tag
        event_payload.push(0x00); // other_parent tag
        event_payload.extend_from_slice(&100u64.to_be_bytes()); // timestamp
        event_payload.extend_from_slice(&0u32.to_be_bytes()); // payload_count
        event_payload.extend_from_slice(&[0u8; 64]); // signature

        let mut frame = vec![MessageType::Event as u8];
        frame.extend_from_slice(&(event_payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&event_payload);
        assert!(
            matches!(Frame::from_bytes(&frame), Err(GossipError::Framing(msg)) if msg.contains("invalid optional-hash tag")),
            "Event with invalid optional-hash tag must be rejected"
        );
    }

    #[test]
    fn reconnect_response_invalid_round_received_tag_rejected() {
        // A ReconnectResponse with a retained entry whose round_received
        // tag is neither 0x00 nor 0x01.
        let response = sample_reconnect_response();
        let mut payload = Vec::new();
        let cp_bytes = consensus::reconnect::encode_signed_checkpoint(&response.signed_checkpoint);
        payload.extend_from_slice(&(cp_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&cp_bytes);
        payload.extend_from_slice(&(response.state_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.state_bytes);
        payload.extend_from_slice(&(response.roster_history_bytes.len() as u32).to_be_bytes());
        payload.extend_from_slice(&response.roster_history_bytes);
        payload.extend_from_slice(&response.decided_round.to_be_bytes());
        // retained_count = 1
        payload.extend_from_slice(&1u32.to_be_bytes());
        // seq (u64)
        payload.extend_from_slice(&0u64.to_be_bytes());
        // round (u64)
        payload.extend_from_slice(&1u64.to_be_bytes());
        // round_received tag = 0xFF (invalid)
        payload.push(0xFF);
        // Pad so the retained_count guard (MIN_RETAINED = 111) passes.
        payload.extend_from_slice(&[0u8; 200]);

        let mut frame = vec![MessageType::ReconnectResponse as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let result = Frame::from_bytes(&frame);
        assert!(result.is_err(), "must reject invalid round_received tag");
        let msg = match result.unwrap_err() {
            GossipError::Framing(m) => m,
            other => panic!("expected Framing error, got: {other:?}"),
        };
        assert!(
            msg.contains("round-received"),
            "error must mention round-received tag, got: {msg}"
        );
    }

    #[test]
    fn sync_response_truncated_mid_event_rejected() {
        // A SyncResponse whose event payload is cut short — the cursor hits
        // EOF before the event is fully decoded. The "truncated frame
        // payload" error from Cursor::read must surface.
        let event = sample_event(32);
        let mut event_bytes = Vec::new();
        event.encode_canonical(&mut event_bytes);
        // SyncResponse: count=1, then only the first 10 bytes of the event.
        let mut payload = Vec::new();
        payload.extend_from_slice(&1u32.to_be_bytes());
        payload.extend_from_slice(&event_bytes[..10]);

        let mut frame = vec![MessageType::SyncResponse as u8];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let result = Frame::from_bytes(&frame);
        assert!(result.is_err(), "SyncResponse truncated mid-event must be rejected");
        let msg = match result.unwrap_err() {
            GossipError::Framing(m) => m,
            other => panic!("expected Framing error, got: {other:?}"),
        };
        assert!(
            msg.contains("truncated")
                || msg.contains("cursor overflow")
                || msg.contains("remaining"),
            "error must indicate truncated/overflow, got: {msg}"
        );
    }
}
