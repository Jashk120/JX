use std::sync::Arc;
use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

use crypto::{
    MembershipRegistry,
    Signable,
    Verifiable,
};
use ed25519_dalek::SigningKey;
use primitives::{
    Event,
    EventHash,
    NodeId,
    Timestamp,
    Transaction,
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
///    peer's last, payload from `payload` — insert it, and push it back on
///    the same stream.
///
/// Returns the hashes of every event that was freshly inserted this round,
/// so the caller can append them to the durable event log (Phase 8).
#[allow(clippy::too_many_arguments)]
pub async fn run_sync(
    transport: &mut (impl SyncTransport + Send),
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
    signing_key: &SigningKey,
    peer_id: NodeId,
    payload: Vec<Transaction>,
    timestamp: Timestamp,
) -> Result<Vec<EventHash>> {
    let known = {
        let hashgraph = hashgraph.lock().await;
        known_summary(&hashgraph, registry)
    };
    transport
        .send_frame(&Frame::SyncRequest(SyncRequest { from: node_id, known: known.clone() }))
        .await?;

    let response = match transport.recv_frame().await? {
        Frame::SyncResponse(response) => response,
        Frame::Behind => {
            // Phase 4: the peer cannot build a delta because it has pruned
            // the history this node needs — the "too far behind" signal.
            return Err(GossipError::Reconnect(
                "peer reports this node is behind its retained history".into(),
            ));
        }
        other => {
            return Err(GossipError::UnexpectedFrame {
                expected: "SyncResponse",
                got: frame_name(&other),
            });
        }
    };

    let mut fresh = Vec::new();
    for event in response.events {
        if let Some(hash) = insert_verified(hashgraph, registry, event).await? {
            fresh.push(hash);
        }
    }

    let (self_parent, other_parent) = {
        let hashgraph = hashgraph.lock().await;
        let self_parent = hashgraph.latest_event_by(&node_id).copied();
        let other_parent = hashgraph.latest_event_by(&peer_id).copied();
        (self_parent, other_parent)
    };

    let unsigned = UnsignedEvent::new(node_id, self_parent, other_parent, timestamp, payload);
    let event = unsigned.sign(signing_key);
    if let Some(hash) = insert_verified(hashgraph, registry, event.clone()).await? {
        fresh.push(hash);
    }
    transport.send_frame(&Frame::Event(event)).await?;

    Ok(fresh)
}

/// Verifies an inbound event against the registry and inserts it, treating
/// `AlreadyPresent` as a benign no-op (events can arrive via concurrent
/// syncs). Returns the hash of a freshly inserted event, or `None` for a
/// duplicate.
pub(crate) async fn insert_verified(
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    event: Event,
) -> Result<Option<EventHash>> {
    let verified = event.verify(registry)?;
    let mut hashgraph = hashgraph.lock().await;
    match hashgraph.insert(verified) {
        Ok(hash) => Ok(Some(hash)),
        Err(consensus::ConsensusError::AlreadyPresent(_)) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn frame_name(frame: &Frame) -> &'static str {
    match frame {
        Frame::SyncRequest(_) => "SyncRequest",
        Frame::SyncResponse(_) => "SyncResponse",
        Frame::Event(_) => "Event",
        Frame::CheckpointSig(_) => "CheckpointSig",
        Frame::Reconnect(_) => "Reconnect",
        Frame::ReconnectResponse(_) => "ReconnectResponse",
        Frame::Behind => "Behind",
    }
}

/// Returns the next timestamp for `last`'s node, monotonically clamped
/// against `last`'s previous value. `SystemTime` is still the physical
/// source, but `max(clock, last+1)` guarantees successive calls from the
/// same creator never return equal or decreasing values, even if the wall
/// clock stalls, has 15.6 ms Windows granularity, or steps backwards.
/// A clock error (before `UNIX_EPOCH`) is logged and treated as `0`, which
/// then clamps to `last+1` so `0` never silently enters the event stream —
/// a `0` would otherwise corrupt every future median that includes its
/// witness (convergent but wrong, worse than divergent).
pub fn next_timestamp(last: &AtomicU64) -> Timestamp {
    let clock_millis = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_millis() as u64,
        Err(e) => {
            tracing::error!(error = %e, "system clock before UNIX_EPOCH, using monotonic fallback");
            0
        }
    };
    next_timestamp_with_clock(clock_millis, last)
}

/// Deterministic core of [`next_timestamp`]: `max(clock_millis, last+1)`.
/// Exposed for unit testing with a mocked clock value.
pub(crate) fn next_timestamp_with_clock(clock_millis: u64, last: &AtomicU64) -> Timestamp {
    // `fetch_max` would be racy with two concurrent callers (both read same
    // `last`, both compute same `next`, one write lost). Use CAS loop.
    loop {
        let prev = last.load(Ordering::Relaxed);
        // `wrapping_add` is safe: `u64::MAX` would wrap to 0, but we never
        // emit that many events in one process lifetime; still, clamp to MAX
        // rather than wrap.
        let candidate = clock_millis.max(prev.saturating_add(1));
        // Never emit 0: if clock is 0 and prev is 0, candidate is 1.
        debug_assert!(candidate != 0, "monotonic clamp must never emit 0");
        match last.compare_exchange_weak(prev, candidate, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Timestamp::new(candidate),
            Err(_) => continue,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicU64;

    use super::*;

    #[test]
    fn monotonic_clamp_never_equal_or_decreasing_with_stalled_clock() {
        let last = AtomicU64::new(0);
        let t1 = next_timestamp_with_clock(100, &last);
        let t2 = next_timestamp_with_clock(100, &last);
        assert!(t2.get() > t1.get(), "same clock must still advance: {t1:?} vs {t2:?}");
        let t3 = next_timestamp_with_clock(100, &last);
        assert!(t3.get() > t2.get());
        // Clock goes backwards.
        let t4 = next_timestamp_with_clock(50, &last);
        assert!(t4.get() > t3.get(), "backward clock must still advance");
        // Clock returns 0 (simulated SystemTime error).
        let t5 = next_timestamp_with_clock(0, &last);
        assert!(t5.get() > t4.get());
        assert_ne!(t5.get(), 0, "must never emit 0");
    }

    #[test]
    fn monotonic_clamp_initial_zero_clock_emits_one() {
        let last = AtomicU64::new(0);
        let t = next_timestamp_with_clock(0, &last);
        assert_eq!(t.get(), 1);
        assert_ne!(t.get(), 0);
    }
}
