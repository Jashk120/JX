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
///
/// The outcome reports two delivery signals the caller must honor:
///
/// * `pushback_delivered` — `false` means the own event was inserted locally
///   but its `Event` push-back frame failed to send. The initiator and the
///   responder would otherwise diverge (initiator keeps the event, responder
///   never sees it). The event stays in the local graph, so the next delta to
///   any peer redelivers it automatically; the caller should log and rely on
///   that next-delta hint rather than treating the round as failed (the
///   payload is already in the graph and must NOT be requeued).
/// * `blocked` — the number of delta events that could not be inserted
///   because the first `MissingParent` blocked the topologically-sorted
///   remainder. The insertable prefix is still applied but NO own event is
///   created: building on a gapped graph would emit a parentless (or forked)
///   event — e.g. a wiped node resuming with a bogus genesis event before its
///   reconnect — so the caller must reconnect first and retry the payload.
///   The caller must requeue its drained payload when this is non-zero.
#[derive(Debug, Clone, Default)]
pub struct SyncOutcome {
    /// Hashes freshly inserted this round, including the own event's hash
    /// when one was created (even if its push-back was not delivered).
    pub fresh: Vec<EventHash>,
    /// Whether the own-event `Event` frame reached the peer. Always `true`
    /// when no own event was created (nothing to deliver).
    pub pushback_delivered: bool,
    /// Delta events left uninserted after the first `MissingParent`
    /// (the blocking event plus the topologically-blocked remainder).
    pub blocked: usize,
}

impl SyncOutcome {
    /// Whether this round observed a gap the delta protocol cannot fill and
    /// the caller should reconnect from a checkpoint.
    pub fn needs_reconnect(&self) -> bool {
        self.blocked > 0
    }
}

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
) -> Result<SyncOutcome> {
    let (fresh, blocked) = exchange_delta(transport, hashgraph, registry, node_id).await?;

    if blocked > 0 {
        tracing::warn!(
            blocked,
            "delta partially applied: MissingParent blocked the remainder, skipping own event until reconnect"
        );
        return Ok(SyncOutcome { fresh, pushback_delivered: true, blocked });
    }

    let created =
        create_own_event(hashgraph, registry, node_id, signing_key, peer_id, payload, timestamp)
            .await?;
    let mut pushback_delivered = true;
    let mut fresh = fresh;
    if let Some((event, hash)) = created {
        fresh.push(hash);
        if let Err(e) = transport.send_frame(&Frame::Event(event)).await {
            // The own event is already in the local graph (`fresh` carries
            // its hash for the event log), so the next delta to any peer
            // redelivers it via the normal known-summary hint. Report the
            // round as successful with an undelivered push-back rather than
            // failing: failing would make the caller requeue a payload that
            // is already in the graph (duplicating it) while the responder
            // still never saw the event.
            tracing::warn!(error = %e, "own event push-back failed, will redeliver via next delta");
            pushback_delivered = false;
        }
    }

    Ok(SyncOutcome { fresh, pushback_delivered, blocked })
}

/// Runs one gossip sync round as the initiator without creating an own
/// event: exchanges the delta (steps 1–2 of [`run_sync`]) and then pushes
/// one of the tick's already-inserted `precreated` events — created as `k`
/// chained events by the fanout driver — on the same stream so the peer
/// learns it immediately.
///
/// `precreated` is `None` only when that slot's per-tick creation produced
/// no new event (practically impossible with a fresh monotonic timestamp);
/// the round then degrades to a delta-only sync.
///
/// The precreated event was inserted (and logged) once by the driver, so its
/// hash is deliberately not included in `fresh`; only the delta's freshly
/// inserted hashes are returned. A failed push-back is reported via
/// `pushback_delivered` (the event stays in the graph for next-delta
/// redelivery) rather than failing the round.
pub async fn run_sync_with_precreated_event(
    transport: &mut (impl SyncTransport + Send),
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
    peer_id: NodeId,
    precreated: Option<Event>,
) -> Result<SyncOutcome> {
    let _ = peer_id;
    let (fresh, blocked) = exchange_delta(transport, hashgraph, registry, node_id).await?;
    let mut pushback_delivered = true;
    if let Some(event) = precreated
        && let Err(e) = transport.send_frame(&Frame::Event(event)).await
    {
        tracing::warn!(error = %e, "precreated event push-back failed, will redeliver via next delta");
        pushback_delivered = false;
    }
    if blocked > 0 {
        tracing::warn!(
            blocked,
            "delta partially applied: MissingParent blocked the remainder, reconnect needed"
        );
    }
    Ok(SyncOutcome { fresh, pushback_delivered, blocked })
}

/// Steps 1–2 of [`run_sync`]: send our known summary, receive the peer's
/// delta, verify and insert each event. Returns the freshly inserted hashes
/// plus the count of events left uninserted after the first `MissingParent`.
///
/// `pub(crate)` so the fanout driver can exchange deltas concurrently and
/// then serialize only own-event creation (post-delta parents) under its
/// own lock — keeping `k` chained events per tick with per-slot
/// `other_parent`s that reflect the just-synced peer head.
///
/// The delta arrives topologically sorted (parents first), so on the first
/// `MissingParent` the insertable prefix is kept and the blocking event plus
/// every event after it is counted as blocked — later events cannot be
/// admitted without their parents. Non-parent errors (bad signatures,
/// unknown creators) still abort the round: they signal a faulty peer, not a
/// history gap.
pub(crate) async fn exchange_delta(
    transport: &mut (impl SyncTransport + Send),
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
) -> Result<(Vec<EventHash>, usize)> {
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
    let mut blocked = 0usize;
    let mut events = response.events.into_iter();
    while let Some(event) = events.next() {
        match insert_verified(hashgraph, registry, event).await {
            Ok(Some(hash)) => fresh.push(hash),
            Ok(None) => {}
            Err(GossipError::Consensus(consensus::ConsensusError::MissingParent(_))) => {
                blocked = 1 + events.len();
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok((fresh, blocked))
}

/// Step 3 of [`run_sync`]: reads `self_parent` (our last) and `other_parent`
/// (the peer's last) under one hashgraph lock, then signs and inserts the
/// own event via [`insert_own_event`].
///
/// The read and the insert are deliberately split across two short lock
/// holdings with only synchronous signing in between, so concurrent callers
/// would still race on the same `self_parent` (an honest self-fork). The
/// fanout driver therefore serializes its `k` per-tick creations under its
/// own-event lock after each task's delta exchange (see `node.rs`); concurrent
/// use without that lock is not supported.
pub async fn create_own_event(
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
    signing_key: &SigningKey,
    peer_id: NodeId,
    payload: Vec<Transaction>,
    timestamp: Timestamp,
) -> Result<Option<(Event, EventHash)>> {
    let (self_parent, other_parent) = {
        let hashgraph = hashgraph.lock().await;
        let self_parent = hashgraph.latest_event_by(&node_id).copied();
        let other_parent = hashgraph.latest_event_by(&peer_id).copied();
        (self_parent, other_parent)
    };
    insert_own_event(
        hashgraph,
        registry,
        node_id,
        signing_key,
        self_parent,
        other_parent,
        payload,
        timestamp,
    )
    .await
}

/// Signs an own event over the given explicit parents and inserts it.
/// Pure signing happens before the insert lock is taken, so the caller must
/// ensure the parents are fresh — i.e. sequential chained creation per tick —
/// or concurrent callers will fork on the same `self_parent`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_own_event(
    hashgraph: &Arc<Mutex<consensus::Hashgraph>>,
    registry: &MembershipRegistry,
    node_id: NodeId,
    signing_key: &SigningKey,
    self_parent: Option<EventHash>,
    other_parent: Option<EventHash>,
    payload: Vec<Transaction>,
    timestamp: Timestamp,
) -> Result<Option<(Event, EventHash)>> {
    let unsigned = UnsignedEvent::new(node_id, self_parent, other_parent, timestamp, payload);
    let event = unsigned.sign(signing_key)?;
    if let Some(hash) = insert_verified(hashgraph, registry, event.clone()).await? {
        Ok(Some((event, hash)))
    } else {
        Ok(None)
    }
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
