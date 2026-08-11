use std::sync::Arc;

use crypto::{
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use primitives::{
    Event,
    NodeId,
    Timestamp,
    UnsignedEvent,
};
use tokio::sync::Mutex;

use crate::error::{
    GossipError,
    Result,
};
use crate::frontier::known_summary;
use crate::proto::{
    Frame,
    SyncRequest,
};
use crate::transport::SyncTransport;

/// Runs one gossip sync round as the initiator (Consensus Spec §5):
///
/// 1. Send a `SyncRequest` carrying our per-creator known summary.
/// 2. Receive the peer's delta, verify and insert each event (skipping
///    ones we already have).
/// 3. Create our own event — `self_parent` our last, `other_parent` the
///    peer's last — insert it, and push it back on the same stream.
pub async fn run_sync(
    transport: &mut (impl SyncTransport + Send),
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
    signing_key: &SigningKey,
    peer_id: NodeId,
) -> Result<()> {
    let known = {
        let hashgraph = hashgraph.lock().await;
        known_summary(&hashgraph, registry)
    };
    transport
        .send_frame(&Frame::SyncRequest(SyncRequest { from: node_id, known: known.clone() }))
        .await?;

    let response = match transport.recv_frame().await? {
        Frame::SyncResponse(response) => response,
        other => {
            return Err(GossipError::UnexpectedFrame {
                expected: "SyncResponse",
                got: frame_name(&other),
            });
        }
    };

    for event in response.events {
        insert_verified(hashgraph, registry, event).await?;
    }

    let (self_parent, other_parent) = {
        let hashgraph = hashgraph.lock().await;
        let self_parent = hashgraph.latest_event_by(&node_id).copied();
        let other_parent = hashgraph.latest_event_by(&peer_id).copied();
        (self_parent, other_parent)
    };

    let unsigned =
        UnsignedEvent::new(node_id, self_parent, other_parent, now_timestamp(), Vec::new());
    let event = unsigned.sign(signing_key);
    insert_verified(hashgraph, registry, event.clone()).await?;
    transport.send_frame(&Frame::Event(event)).await?;

    Ok(())
}

/// Verifies an inbound event against the registry and inserts it, treating
/// `AlreadyPresent` as a benign no-op (events can arrive via concurrent
/// syncs).
pub(crate) async fn insert_verified(
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    event: Event,
) -> Result<()> {
    let verified = event.verify(registry)?;
    let mut hashgraph = hashgraph.lock().await;
    match hashgraph.insert(verified) {
        Ok(_) => Ok(()),
        Err(consensus::ConsensusError::AlreadyPresent(_)) => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn frame_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::SyncRequest(_) => "SyncRequest",
        Frame::SyncResponse(_) => "SyncResponse",
        Frame::Event(_) => "Event",
        Frame::CheckpointSig(_) => "CheckpointSig",
    }
}

fn now_timestamp() -> Timestamp {
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Timestamp::new(millis)
}
