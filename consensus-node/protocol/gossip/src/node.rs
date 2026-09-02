use std::collections::{
    BTreeMap,
    HashMap,
    VecDeque,
};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    AtomicU64,
    Ordering,
};
use std::time::Duration;

use consensus::{
    CheckpointAccumulator,
    CheckpointSig,
    RETENTION_ROUNDS,
    RecordsRootItem,
    SignedCheckpoint,
};
use crypto::{
    BlsIdentity,
    Hashable,
    MembershipOp,
    MembershipRegistry,
    Verifiable,
};
use ed25519_dalek::{
    SigningKey,
    VerifyingKey,
};
use lru::LruCache;
use primitives::{
    Event,
    EventHash,
    NodeId,
    Transaction,
};
use storage::EventSink;
use tokio::net::{
    TcpListener,
    TcpStream,
};
use tokio::sync::{
    Mutex,
    Notify,
    Semaphore,
};
use tokio::task::JoinSet;

use crate::error::{
    GossipError,
    Result,
};
use crate::frontier::{
    DedupState,
    SyncConfig,
    delta_events_filtered,
};
use crate::peer::PeerInfo;
use crate::peer_manager::{
    FanoutMode,
    PeerManager,
};
use crate::proto::{
    Frame,
    ReconnectResponse,
    SyncResponse,
};
use crate::reconnect::fetch_checkpoint;
use crate::sync::{
    insert_verified,
    run_sync,
};
use crate::tls::TlsIdentity;
use crate::transport::{
    SyncTransport,
    TcpTransport,
};

#[derive(Clone, Debug, Default)]
pub struct GossipMetrics {
    pub sync_attempts: u64,
    pub sync_success: u64,
    pub sync_failures: u64,
    pub p50_rtt_ms: f64,
    pub p95_rtt_ms: f64,
    pub delta_bytes_per_sync: f64,
    pub cache_hit_rate: f64,
    pub pending_dropped: u64,
}

impl GossipMetrics {
    pub fn success_rate(&self) -> f64 {
        if self.sync_attempts == 0 {
            0.0
        } else {
            self.sync_success as f64 / self.sync_attempts as f64
        }
    }

    /// Record a successful sync's latency and payload size into the EWMA
    /// metrics. `p50` uses a fast alpha (0.1) for a responsive median while
    /// `p95` uses a slower alpha (0.05) so tail spikes are retained longer
    /// and the two series diverge. `fresh_len` drives two additional EWMAs:
    /// `delta_bytes_per_sync` is a rough estimate (1 KiB per event) and
    /// `cache_hit_rate` tracks the empty-delta ratio.
    pub fn record_sync_success(&mut self, rtt: Duration, fresh_len: usize) {
        self.sync_attempts += 1;
        self.sync_success += 1;
        let rtt_ms = rtt.as_millis() as f64;
        // p50: alpha 0.1 (decay 0.9) — responsive; p95: alpha 0.05 (decay 0.95) — retains tails.
        self.p50_rtt_ms = self.p50_rtt_ms * 0.9 + rtt_ms * 0.1;
        self.p95_rtt_ms = self.p95_rtt_ms * 0.95 + rtt_ms * 0.05;
        // Rough estimate: ~1 KiB per event; keep EWMA for observability.
        let delta_bytes = fresh_len as f64 * 1024.0;
        self.delta_bytes_per_sync = self.delta_bytes_per_sync * 0.9 + delta_bytes * 0.1;
        let hit = if fresh_len == 0 { 1.0 } else { 0.0 };
        self.cache_hit_rate = self.cache_hit_rate * 0.9 + hit * 0.1;
    }
}

/// The sync driver's timing parameters.
#[derive(Clone, Copy, Debug)]
pub struct SyncTiming {
    /// How often the driver picks a uniform-random peer and runs a sync round.
    pub sync_interval: Duration,
    /// How long a single sync round may block waiting for a silent peer.
    pub sync_timeout: Duration,
}

impl SyncTiming {
    pub const fn new(sync_interval: Duration, sync_timeout: Duration) -> Self {
        Self { sync_interval, sync_timeout }
    }
}

/// The membership-op activation queue plus the processed-event and
/// checkpoint watermarks.
///
/// All live under one `Mutex` so the watermarks and the pending queue advance
/// together atomically: a concurrent `process_finalized_rounds` can never
/// skip events whose ops have not been bucketed yet, or emit a checkpoint for
/// a round that a later pass is still ordering.
#[derive(Default)]
struct ActivationState {
    pending: BTreeMap<u64, Vec<MembershipOp>>,
    processed_through_round: u64,
    /// Highest decided round for which this node has produced a checkpoint.
    checkpoint_watermark: u64,
}

/// How many pending transaction payloads the sync driver drains into one
/// own event per sync round. Bounded so a burst cannot produce unbounded
/// events; ordering across payloads is consensus's job, not the driver's.
const TX_PER_SYNC: usize = 64;

/// Bounded LRU capacity for the outbound transport pool (PLAN-2 D4/D5).
/// `N=6 → 10`, `N=100 → 30`, linear interpolation in between.
pub fn outbound_capacity(n: usize) -> NonZeroUsize {
    let cap = if n <= 6 {
        10
    } else if n >= 100 {
        30
    } else {
        10 + (n - 6) * 20 / (100 - 6)
    };
    NonZeroUsize::new(cap).expect("outbound capacity must be non-zero")
}

const MAX_PENDING_SIGS_PER_ROUND: usize = 64;

const MAX_PENDING_TRANSACTIONS: usize = 1_024;

/// A JKain node: owns a hashgraph, a TLS identity, the known-peer table,
/// and the async machinery that runs gossip syncs on a fixed interval.
pub struct GossipNode {
    pub node_id: NodeId,
    pub hashgraph: Arc<Mutex<consensus::Hashgraph>>,
    signing_key: SigningKey,
    bls_identity: BlsIdentity,
    registry: Mutex<MembershipRegistry>,
    identity: TlsIdentity,
    peers: Mutex<PeerManager>,
    sync_timing: SyncTiming,
    fanout: FanoutMode,
    sync_config: SyncConfig,
    dedup_state: Mutex<HashMap<NodeId, DedupState>>,
    gossip_metrics: Arc<Mutex<GossipMetrics>>,
    executor: Mutex<state::Executor>,
    /// The durable Fjall state database backing the executor's `State` (the
    /// live LSM partition) plus the per-accepted-round snapshots a restart or
    /// reconnect learner restores state from (replacing the `.snap` files).
    state_db: Arc<state::StateDb>,
    activation: Mutex<ActivationState>,
    /// One in-flight [`CheckpointAccumulator`] per round whose checkpoint
    /// this node has produced but not yet accepted. Removed on acceptance.
    checkpoint_accumulators: Mutex<HashMap<u64, CheckpointAccumulator>>,
    /// Accepted checkpoints, ascending by round.
    signed_checkpoints: Mutex<Vec<SignedCheckpoint>>,
    /// Per-round serialized state (`State::to_bytes()`), keyed by round,
    /// recorded when that round's checkpoint is accepted
    /// (`accept_checkpoint`, from the accumulator-carried bytes) or restored
    /// via reconnect apply, keyed by exact round. A reconnect learner is
    /// served the snapshot for the checkpoint round — not the live state,
    /// which has advanced past it — so the served bytes rebuild to the
    /// committed `state_hash` and the learner's replay of the retained window
    /// is exactly-once. Evicted in `accept_checkpoint` alongside pruning,
    /// keeping every snapshot still servable by
    /// `select_checkpoint_for_learner`.
    state_snapshots: Mutex<BTreeMap<u64, Vec<u8>>>,
    /// This node's own signatures, gossiped after every successful sync round.
    outbound_checkpoint_sigs: Mutex<Vec<CheckpointSig>>,
    /// Inbound signatures for rounds this node has not produced a checkpoint
    /// for yet (they arrive ahead of the events that decide the round).
    pending_checkpoint_sigs: Mutex<BTreeMap<u64, Vec<CheckpointSig>>>,
    /// Set when a sync round encounters `MissingParent`, signalling that this
    /// node is too far behind for delta-sync and must reconnect from a
    /// checkpoint. Only ever set by the sync driver and read on the next loop
    /// iteration, so an `AtomicBool` (no mutex) suffices.
    needs_reconnect: AtomicBool,
    /// Monotonic last-emitted timestamp (millis since epoch) for this node's
    /// own events. Used by [`Self::next_timestamp`] to clamp `SystemTime` so
    /// two successive calls never return equal or decreasing values, even if
    /// the wall clock stalls or steps backwards. Stored as `AtomicU64` because
    /// the sync driver mutates it without holding any other lock.
    last_timestamp: AtomicU64,
    /// Notified whenever `accept_checkpoint` or `process_finalized_rounds`
    /// completes, so test helpers waiting for a persisted checkpoint or
    /// finalized state can wake without polling. Production code does not
    /// wait on this; it is purely a test synchronization aid.
    checkpoint_notify: Arc<Notify>,
    /// Raw transaction payloads submitted via [`Self::submit_transaction`],
    /// drained by the sync driver into the next own events.
    pending_transactions: Mutex<VecDeque<Vec<u8>>>,
    /// Durable sink for accepted checkpoints, set by the embedding
    /// application (e.g. the `jkaind` daemon). `None` means no persistence.
    checkpoint_sink: Mutex<Option<Arc<dyn CheckpointSink + Send + Sync>>>,
    /// Durable event-log sink (Phase 8): every freshly inserted event is
    /// appended, ordering updates and roster-history changes are recorded,
    /// and prunes are mirrored. `None` means no event persistence.
    event_sink: Mutex<Option<Arc<dyn storage::EventSink + Send + Sync>>>,
    /// Second event sink (Phase 8, mirror streams): the event stream file
    /// writer, receiving every freshly inserted event in topological order.
    /// Unlike the event log, ordering updates, roster-history changes, and
    /// prunes are deliberately not forwarded — event files are append-only
    /// and carry ordering only when the appended record already knows it.
    event_stream_sink: Mutex<Option<Arc<stream::EventStreamWriter>>>,
    /// Sink for the record stream file writer (Phase 8, mirror streams):
    /// notified with every newly accepted checkpoint, so each decided round's
    /// record file is emitted. `None` means no record stream.
    record_sink: Mutex<Option<Arc<stream::RecordStreamWriter>>>,
    /// Sidecar sink for the record proof files (`.rsf_proofs`): notified
    /// alongside `record_sink` with the same checkpoint/diffs so each decided
    /// round's Merkle inclusion proofs are emitted. `None` means no proof
    /// stream. The record writer itself already emits the sidecar
    /// atomically, so this sink is optional and typically points at the same
    /// writer as `record_sink`; keeping it separate allows a dedicated proof
    /// writer if desired without blocking consensus.
    record_proof_sink: Mutex<Option<Arc<stream::RecordStreamWriter>>>,
    /// Cumulative per-round state hashes for every finalized round.
    /// Unlike the per-pass `state_hashes` built in `process_finalized_rounds`,
    /// this map is never truncated on the hot path: `canonical_checkpoint_payload`
    /// and `prev_checkpoint_hash_for` read from it, so a node always derives
    /// the true per-round state hash regardless of which rounds finalized
    /// together in a given pass (PLAN-2 Rule 1).
    cumulative_state_hashes: Mutex<BTreeMap<u64, [u8; 32]>>,
}

impl GossipNode {
    /// `peers` must not include this node itself; any self-entry is
    /// dropped. All members (including this node) must be registered in
    /// `registry` so their events can be verified and inserted.
    ///
    /// `sync_timeout` bounds how long a single sync round may block waiting
    /// for a peer that has gone silent, so a dead persistent connection is
    /// dropped and retried instead of stalling the driver forever.
    pub fn new(
        node_id: NodeId,
        signing_key: SigningKey,
        registry: MembershipRegistry,
        identity: TlsIdentity,
        peers: Vec<PeerInfo>,
        sync_timing: SyncTiming,
        state_db: Arc<state::StateDb>,
    ) -> Self {
        let bls_identity =
            BlsIdentity::from_ikm(&signing_key.to_bytes()).expect("BLS identity from signing key");
        Self::new_with_bls(
            node_id,
            signing_key,
            bls_identity,
            registry,
            identity,
            peers,
            sync_timing,
            state_db,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_bls(
        node_id: NodeId,
        signing_key: SigningKey,
        bls_identity: BlsIdentity,
        registry: MembershipRegistry,
        identity: TlsIdentity,
        peers: Vec<PeerInfo>,
        sync_timing: SyncTiming,
        state_db: Arc<state::StateDb>,
    ) -> Self {
        let peers: Vec<PeerInfo> =
            peers.into_iter().filter(|peer| peer.node_id != node_id).collect();
        let hashgraph = consensus::Hashgraph::new(&registry);
        Self {
            node_id,
            hashgraph: Arc::new(Mutex::new(hashgraph)),
            signing_key,
            bls_identity,
            registry: Mutex::new(registry),
            identity,
            peers: Mutex::new(PeerManager::new(peers)),
            sync_timing,
            fanout: FanoutMode::Auto,
            sync_config: SyncConfig::default(),
            dedup_state: Mutex::new(HashMap::new()),
            gossip_metrics: Arc::new(Mutex::new(GossipMetrics::default())),
            executor: Mutex::new(state::Executor::new(state_db.state_keyspace())),
            state_db,
            activation: Mutex::new(ActivationState::default()),
            checkpoint_accumulators: Mutex::new(HashMap::new()),
            signed_checkpoints: Mutex::new(Vec::new()),
            state_snapshots: Mutex::new(BTreeMap::new()),
            outbound_checkpoint_sigs: Mutex::new(Vec::new()),
            pending_checkpoint_sigs: Mutex::new(BTreeMap::new()),
            needs_reconnect: AtomicBool::new(false),
            last_timestamp: AtomicU64::new(0),
            checkpoint_notify: Arc::new(Notify::new()),
            pending_transactions: Mutex::new(VecDeque::new()),
            checkpoint_sink: Mutex::new(None),
            event_sink: Mutex::new(None),
            event_stream_sink: Mutex::new(None),
            record_sink: Mutex::new(None),
            record_proof_sink: Mutex::new(None),
            cumulative_state_hashes: Mutex::new({
                let mut m = BTreeMap::new();
                m.insert(0, state::SparseMerkleTree::new().root());
                m
            }),
        }
    }

    pub fn set_fanout(&mut self, fanout: FanoutMode) {
        self.fanout = fanout;
    }

    pub fn fanout(&self) -> FanoutMode {
        self.fanout
    }

    pub async fn gossip_metrics_snapshot(&self) -> GossipMetrics {
        self.gossip_metrics.lock().await.clone()
    }

    pub async fn backoff_peer_count(&self) -> usize {
        self.peers.lock().await.backoff_count()
    }

    /// Whether `node` is a registered member of this node's hashgraph.
    pub async fn is_consensus_member(&self, node: NodeId) -> bool {
        let hg = self.hashgraph.lock().await;
        hg.is_member(&node)
    }

    /// A handle to the executor's current deterministic state (observability
    /// helper; the daemon and tests read the committed state through this).
    /// The returned `State` shares the node's backing partition, so reads see
    /// the live state.
    pub async fn executor_state(&self) -> state::State {
        self.executor.lock().await.state().clone()
    }

    /// The number of known peers (observability helper).
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
    }

    /// A snapshot of the known peer set (observability helper; feeds the
    /// daemon's `status`/`peers` control output).
    pub async fn peers(&self) -> Vec<PeerInfo> {
        self.peers.lock().await.all()
    }

    /// The live (structurally-registered) member set as `(NodeId, key)`
    /// pairs. A member appears here as soon as its `MembershipOp::Add`
    /// activates, exactly matching [`Self::is_consensus_member`] — unlike a
    /// round-indexed roster lookup, which can still lag by the one round the
    /// new roster is scheduled to activate.
    pub async fn members(&self) -> Vec<(NodeId, VerifyingKey)> {
        let registry = self.registry.lock().await;
        registry
            .member_ids()
            .into_iter()
            .map(|id| {
                let key = registry.key_for(&id).expect("registered member has a key");
                (id, *key)
            })
            .collect()
    }

    /// Queues a raw transaction payload to be included in this node's next
    /// own event. Payloads are drained by the sync driver, up to
    /// [`TX_PER_SYNC`] per round, and passed into the initiator's own event.
    /// If that sync round fails the drained payloads are dropped — ordering
    /// is consensus's job, so a dropped payload is simply not included.
    /// Returns `true` if the payload was queued, `false` if the pending queue
    /// is full.
    pub async fn submit_transaction(&self, payload: Vec<u8>) -> bool {
        let mut pending = self.pending_transactions.lock().await;
        if pending.len() >= MAX_PENDING_TRANSACTIONS {
            tracing::warn!(
                pending = pending.len(),
                limit = MAX_PENDING_TRANSACTIONS,
                "pending queue full, dropping transaction"
            );
            drop(pending);
            self.gossip_metrics.lock().await.pending_dropped += 1;
            return false;
        }
        pending.push_back(payload);
        true
    }

    /// Requests a reconnect from a live peer on the next sync interval, even
    /// when no sync round has signalled `MissingParent`/`Behind`. Used by the
    /// daemon restart path: a node rebuilt from a persisted checkpoint holds
    /// only the checkpointed state and must fetch the live event window from
    /// a peer before resuming normal delta-sync.
    pub fn request_reconnect(&self) {
        self.needs_reconnect.store(true, Ordering::Release);
    }

    /// Returns the next timestamp for this node's own event, monotonically
    /// clamped against this node's last emitted value so wall-clock
    /// regression or low resolution (e.g. 15.6 ms on Windows) can never
    /// produce equal or decreasing timestamps from this creator. This is
    /// scoped narrowly to *this node's* emissions, not a Lamport merge of
    /// peer timestamps.
    pub fn next_timestamp(&self) -> primitives::Timestamp {
        crate::sync::next_timestamp(&self.last_timestamp)
    }

    /// Returns a clone of the checkpoint `Notify`, which is signaled
    /// whenever `accept_checkpoint` completes or `process_finalized_rounds`
    /// finishes a batch. Test helpers use this to avoid `sleep`-polling.
    pub fn checkpoint_notify(&self) -> Arc<Notify> {
        Arc::clone(&self.checkpoint_notify)
    }

    /// Drains up to [`TX_PER_SYNC`] pending payloads into transactions for
    /// the next own event. Removes them from the queue; if the sync round
    /// they were destined for fails, they are dropped (inclusion-only).
    async fn drain_pending_transactions(&self) -> Vec<Transaction> {
        let mut pending = self.pending_transactions.lock().await;
        (0..TX_PER_SYNC).filter_map(|_| pending.pop_front().map(Transaction::from_bytes)).collect()
    }

    /// Registers `sink` as the durable checkpoint destination. It is invoked
    /// with every newly accepted [`SignedCheckpoint`] and the serialized state
    /// snapshot for that checkpoint round (`State::to_bytes()`), so the
    /// embedding application can persist both. Replacing the sink at runtime
    /// is allowed but unusual.
    pub async fn set_checkpoint_sink(&self, sink: Arc<dyn CheckpointSink + Send + Sync>) {
        *self.checkpoint_sink.lock().await = Some(sink);
    }

    /// Registers `sink` as the durable event-log destination. It is invoked
    /// on every fresh event insert, on ordering/roster-history changes, and
    /// on graph prunes, so a restarting node can rebuild its retained graph
    /// from the log. Replacing the sink at runtime is allowed but unusual.
    pub async fn set_event_sink(&self, sink: Arc<dyn storage::EventSink + Send + Sync>) {
        *self.event_sink.lock().await = Some(sink);
    }

    /// Registers `sink` as the event stream file writer (Phase 8, mirror
    /// streams). It is invoked with every freshly inserted event in
    /// topological order; ordering/roster-history changes and prunes are not
    /// forwarded (event files are append-only and mirror the append hook
    /// only). Replacing the sink at runtime is allowed but unusual.
    pub async fn set_event_stream_sink(&self, sink: Arc<stream::EventStreamWriter>) {
        *self.event_stream_sink.lock().await = Some(sink);
    }

    /// Registers `sink` as the record stream file writer (Phase 8, mirror
    /// streams). It is invoked with every newly accepted checkpoint, so each
    /// decided round's `.rsf` is emitted from the threshold-signed anchor.
    pub async fn set_record_sink(&self, sink: Arc<stream::RecordStreamWriter>) {
        *self.record_sink.lock().await = Some(sink);
    }

    pub async fn set_record_proof_sink(&self, sink: Arc<stream::RecordStreamWriter>) {
        *self.record_proof_sink.lock().await = Some(sink);
    }

    /// Flushes the event stream's buffered window to disk alongside the
    /// event-log flush, so a checkpoint and its events are durably co-located.
    async fn flush_event_stream_sink(&self) {
        if let Some(sink) = self.event_stream_sink.lock().await.clone() {
            storage::EventSink::flush(&*sink);
        }
    }

    /// Flushes the event and record streams and awaits their writer barriers
    /// with a bounded timeout. Returns `true` if both barriers were observed
    /// within `timeout`, `false` on timeout or if no writers are configured.
    pub async fn flush_streams(&self, timeout: Duration) -> bool {
        if let Some(sink) = self.event_stream_sink.lock().await.clone() {
            sink.flush();
        }
        let event_writer = self.event_stream_sink.lock().await.clone();
        let record_writer = self.record_sink.lock().await.clone();
        let proof_writer = self.record_proof_sink.lock().await.clone();
        let flush_fut = async move {
            if let Some(writer) = event_writer {
                writer.barrier().await;
            }
            if let Some(writer) = record_writer.as_ref() {
                writer.barrier().await;
            }
            if let Some(writer) = proof_writer.as_ref() {
                let is_duplicate =
                    record_writer.as_ref().is_some_and(|record| Arc::ptr_eq(writer, record));
                if !is_duplicate {
                    writer.barrier().await;
                }
            }
        };
        tokio::time::timeout(timeout, flush_fut).await.is_ok()
    }

    /// Appends every freshly inserted event in `fresh` to the durable event
    /// log (Phase 8), reading each event's record metadata from the graph.
    /// Called right after insertion, before any pruning can remove the
    /// events, so the log and the live graph stay in lockstep. The same
    /// records feed the event stream file writer, so the mirror-facing event
    /// stream sees exactly the inserted events in topological order.
    async fn log_fresh_inserts(&self, fresh: &[EventHash]) {
        let sink = self.event_sink.lock().await.clone();
        let stream_sink = self.event_stream_sink.lock().await.clone();
        const MAX_SYNC_EVENT_COUNT: usize = 4096;
        if fresh.len() > MAX_SYNC_EVENT_COUNT {
            tracing::warn!(
                fresh_len = fresh.len(),
                limit = MAX_SYNC_EVENT_COUNT,
                "fresh delta exceeds per-sync event cap, truncating"
            );
        }
        let retained_vec: Vec<consensus::RetainedEvent> = {
            let hg = self.hashgraph.lock().await;
            fresh
                .iter()
                .take(MAX_SYNC_EVENT_COUNT)
                .filter_map(|hash| {
                    hg.get(hash).map(|record| consensus::RetainedEvent {
                        event: record.event().clone(),
                        seq: record.seq(),
                        round: record.round(),
                        ancestor_seqs: record.ancestor_seqs().to_vec(),
                        round_received: None,
                        consensus_timestamp: None,
                    })
                })
                .collect()
        };
        for retained in &retained_vec {
            if let Some(sink) = &sink {
                sink.append(retained);
            }
            if let Some(stream_sink) = &stream_sink {
                storage::EventSink::append(&**stream_sink, retained);
            }
        }
    }

    /// Runs the node: accepts inbound gossip connections and, every
    /// `sync_interval`, syncs with a uniform-random peer. Runs until the
    /// surrounding task is aborted.
    pub async fn run(self: Arc<Self>, listener: TcpListener) -> Result<()> {
        self.run_until_stopped(listener, Arc::new(AtomicBool::new(false))).await
    }

    /// Like [`Self::run`], but the sync driver stops once `stop` is set.
    /// The flag is polled at each loop boundary (never racing a
    /// notification), and an in-flight sync round is allowed to complete
    /// first — so after a short settle the node's hashgraph is quiescent,
    /// which lets tests compare exact state across nodes.
    pub async fn run_until_stopped(
        self: Arc<Self>,
        listener: TcpListener,
        stop: Arc<AtomicBool>,
    ) -> Result<()> {
        let _accept_task = tokio::spawn(self.clone().accept_loop(listener));

        let outbound: Arc<Mutex<LruCache<NodeId, Arc<Mutex<TcpTransport>>>>> =
            Arc::new(Mutex::new(LruCache::new(outbound_capacity(self.peers.lock().await.len()))));
        let mut consecutive_failures: u64 = 0;
        let mut decided_watermark: u64 = 0;
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(self.sync_timing.sync_interval).await;
            if stop.load(Ordering::Acquire) {
                break;
            }

            if self.needs_reconnect.load(Ordering::Acquire) {
                let mut attempted = false;
                if let Some(peer) = self.peers.lock().await.random_peer()
                    && let Some(reconnect_addr) = peer.reconnect_addr
                {
                    attempted = true;
                    let trusted_roster_hash = {
                        let registry = self.registry.lock().await;
                        if registry.is_empty() {
                            tracing::error!("reconnect refused: no trusted roster hash available");
                            continue;
                        }
                        registry.hash().expect("hash bounded")
                    };
                    tracing::info!(peer = ?peer.node_id, "reconnect attempt starting");
                    let attempt = tokio::time::timeout(
                        self.sync_timing.sync_timeout * 2,
                        fetch_checkpoint(
                            &self.identity,
                            &peer,
                            reconnect_addr,
                            self.node_id,
                            trusted_roster_hash,
                        ),
                    )
                    .await;
                    match attempt {
                        Ok(Ok(response)) => {
                            if self.apply_checkpoint(response).await {
                                self.needs_reconnect.store(false, Ordering::Release);
                                tracing::info!(peer = ?peer.node_id, "reconnect succeeded");
                            }
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(error = %e, "reconnect attempt failed");
                        }
                        Err(_) => {
                            tracing::warn!(peer = ?peer.node_id, "reconnect attempt timed out");
                        }
                    }
                }
                if attempted {
                    continue;
                }
            }

            {
                let mut cache = outbound.lock().await;
                let cap = outbound_capacity(self.peers.lock().await.len());
                if cache.cap() != cap {
                    cache.resize(cap);
                }
            }

            let k = self.fanout.effective_k(self.peers.lock().await.len());
            if k <= 1 {
                let peer = self.peers.lock().await.random_peer();
                let Some(peer) = peer else { continue };

                let transport_arc = {
                    let mut cache = outbound.lock().await;
                    if let Some(existing) = cache.get(&peer.node_id) {
                        existing.clone()
                    } else {
                        let arc = Arc::new(Mutex::new(TcpTransport::new(self.identity.clone())));
                        cache.put(peer.node_id, arc.clone());
                        arc
                    }
                };

                let connect_result = {
                    let mut guard = transport_arc.lock().await;
                    if guard.is_connected() {
                        Ok(())
                    } else {
                        let res = guard.connect(&peer).await;
                        if res.is_err() {
                            *guard = TcpTransport::new(self.identity.clone());
                        }
                        res.map(|_| ())
                    }
                };
                if let Err(e) = connect_result {
                    consecutive_failures += 1;
                    self.peers.lock().await.record_failure(peer.node_id);
                    {
                        let mut m = self.gossip_metrics.lock().await;
                        m.sync_attempts += 1;
                        m.sync_failures += 1;
                    }
                    if consecutive_failures == 1 || consecutive_failures.is_multiple_of(10) {
                        tracing::warn!(
                            peer = ?peer.node_id,
                            consecutive_failures,
                            error = %e,
                            "sync connect failed"
                        );
                    }
                    continue;
                }

                let registry = self.registry.lock().await.clone();
                let payload = self.drain_pending_transactions().await;
                let timestamp = self.next_timestamp();
                let start = std::time::Instant::now();
                let round = {
                    let mut guard = transport_arc.lock().await;
                    let res = tokio::time::timeout(
                        self.sync_timing.sync_timeout,
                        run_sync(
                            &mut *guard,
                            &self.hashgraph,
                            &registry,
                            self.node_id,
                            &self.signing_key,
                            peer.node_id,
                            payload,
                            timestamp,
                        ),
                    )
                    .await;
                    match res {
                        Ok(r) => r,
                        Err(_) => Err(GossipError::Sync(format!(
                            "sync round with peer {peer:?} timed out after {:?}",
                            self.sync_timing.sync_timeout
                        ))),
                    }
                };

                match &round {
                    Err(e) => {
                        consecutive_failures += 1;
                        self.peers.lock().await.record_failure(peer.node_id);
                        {
                            let mut m = self.gossip_metrics.lock().await;
                            m.sync_attempts += 1;
                            m.sync_failures += 1;
                        }
                        {
                            let mut guard = transport_arc.lock().await;
                            *guard = TcpTransport::new(self.identity.clone());
                        }
                        if consecutive_failures == 1 || consecutive_failures.is_multiple_of(10) {
                            tracing::warn!(
                                peer = ?peer.node_id,
                                consecutive_failures,
                                error = %e,
                                "sync round failed"
                            );
                        }
                    }
                    Ok(fresh) => {
                        consecutive_failures = 0;
                        let rtt = start.elapsed();
                        self.peers.lock().await.record_success(peer.node_id, rtt);
                        {
                            let mut m = self.gossip_metrics.lock().await;
                            m.record_sync_success(rtt, fresh.len());
                            if m.sync_attempts.is_multiple_of(10) {
                                tracing::info!(
                                    sync_attempts = m.sync_attempts,
                                    sync_success = m.sync_success,
                                    success_rate = m.success_rate(),
                                    p50_rtt_ms = m.p50_rtt_ms,
                                    p95_rtt_ms = m.p95_rtt_ms,
                                    delta_bytes_per_sync = m.delta_bytes_per_sync,
                                    cache_hit_rate = m.cache_hit_rate,
                                    consecutive_failures = consecutive_failures,
                                    "gossip metrics periodic"
                                );
                            }
                        }
                        tracing::debug!(
                            peer = ?peer.node_id,
                            fresh_events = fresh.len(),
                            "sync round succeeded"
                        );
                        self.log_fresh_inserts(fresh).await;
                        {
                            let mut guard = transport_arc.lock().await;
                            self.gossip_checkpoint_sigs(&mut *guard).await;
                        }
                    }
                }

                if matches!(
                    &round,
                    Err(GossipError::Consensus(consensus::ConsensusError::MissingParent(_)))
                        | Err(GossipError::Reconnect(_))
                ) {
                    self.needs_reconnect.store(true, Ordering::Release);
                }

                self.process_finalized_rounds().await;

                let decided = {
                    let hg = self.hashgraph.lock().await;
                    hg.highest_decided_round()
                };
                if decided > decided_watermark {
                    decided_watermark = decided;
                    tracing::info!(decided_round = decided, "round decided");
                    let m = self.gossip_metrics.lock().await.clone();
                    tracing::info!(
                        sync_attempts = m.sync_attempts,
                        sync_success = m.sync_success,
                        success_rate = m.success_rate(),
                        p50_rtt_ms = m.p50_rtt_ms,
                        p95_rtt_ms = m.p95_rtt_ms,
                        delta_bytes_per_sync = m.delta_bytes_per_sync,
                        cache_hit_rate = m.cache_hit_rate,
                        consecutive_failures = consecutive_failures,
                        "gossip metrics"
                    );
                    let mut cache = outbound.lock().await;
                    let cap = outbound_capacity(self.peers.lock().await.len());
                    if cache.cap() != cap {
                        cache.resize(cap);
                    }
                }
                continue;
            }

            {
                let peers_snapshot = self.peers.lock().await.all();
                let hg = self.hashgraph.lock().await;
                let my_seq = hg
                    .latest_event_by(&self.node_id)
                    .and_then(|h| hg.get(h))
                    .map_or(0, |r| r.seq()) as i64;
                let mut gaps: Vec<(NodeId, i64)> = Vec::with_capacity(peers_snapshot.len());
                for peer in &peers_snapshot {
                    let peer_seq = hg
                        .latest_event_by(&peer.node_id)
                        .and_then(|h| hg.get(h))
                        .map_or(0, |r| r.seq()) as i64;
                    gaps.push((peer.node_id, my_seq - peer_seq));
                }
                drop(hg);
                let mut pm = self.peers.lock().await;
                for (id, gap) in gaps {
                    pm.set_frontier_gap(id, gap);
                }
            }
            let peers = self.peers.lock().await.pick_k(k);
            if peers.is_empty() {
                self.process_finalized_rounds().await;
                continue;
            }
            let semaphore = Arc::new(Semaphore::new(k));
            let mut join_set: JoinSet<()> = JoinSet::new();
            let payload = self.drain_pending_transactions().await;
            for peer in peers {
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        tracing::debug!("fanout backpressure: skip spawn, k in-flight");
                        break;
                    }
                };
                let outbound = outbound.clone();
                let self_clone = self.clone();
                let peer_clone = peer.clone();
                let payload_clone = payload.clone();
                let registry_clone = self_clone.registry.lock().await.clone();
                let metrics = self_clone.gossip_metrics.clone();
                join_set.spawn(async move {
                    let _permit = permit;
                    let start = std::time::Instant::now();
                    let transport_arc = {
                        let mut cache = outbound.lock().await;
                        if let Some(existing) = cache.get(&peer_clone.node_id) {
                            existing.clone()
                        } else {
                            let arc = Arc::new(Mutex::new(TcpTransport::new(
                                self_clone.identity.clone(),
                            )));
                            cache.put(peer_clone.node_id, arc.clone());
                            arc
                        }
                    };
                    let mut guard = transport_arc.lock().await;
                    if !guard.is_connected()
                        && let Err(e) = guard.connect(&peer_clone).await
                    {
                        self_clone.peers.lock().await.record_failure(peer_clone.node_id);
                        {
                            let mut m = metrics.lock().await;
                            m.sync_attempts += 1;
                            m.sync_failures += 1;
                        }
                        *guard = TcpTransport::new(self_clone.identity.clone());
                        tracing::warn!(peer=?peer_clone.node_id, error=%e, "sync connect failed");
                        return;
                    }
                    let timestamp = self_clone.next_timestamp();
                    let result = tokio::time::timeout(
                        self_clone.sync_timing.sync_timeout,
                        run_sync(
                            &mut *guard,
                            &self_clone.hashgraph,
                            &registry_clone,
                            self_clone.node_id,
                            &self_clone.signing_key,
                            peer_clone.node_id,
                            payload_clone,
                            timestamp,
                        ),
                    )
                    .await;
                    let result = match result {
                        Ok(r) => r,
                        Err(_) => Err(GossipError::Sync(format!(
                            "sync round with peer {:?} timed out after {:?}",
                            peer_clone.node_id, self_clone.sync_timing.sync_timeout
                        ))),
                    };
                    match result {
                        Err(e) => {
                            self_clone.peers.lock().await.record_failure(peer_clone.node_id);
                            {
                                let mut m = metrics.lock().await;
                                m.sync_attempts += 1;
                                m.sync_failures += 1;
                            }
                            *guard = TcpTransport::new(self_clone.identity.clone());
                            if matches!(
                                &e,
                                GossipError::Consensus(consensus::ConsensusError::MissingParent(_))
                                    | GossipError::Reconnect(_)
                            ) {
                                self_clone.needs_reconnect.store(true, Ordering::Release);
                            }
                            tracing::warn!(peer=?peer_clone.node_id, error=%e, "sync round failed");
                        }
                        Ok(fresh) => {
                            let rtt = start.elapsed();
                            self_clone.peers.lock().await.record_success(peer_clone.node_id, rtt);
                            {
                                let mut m = metrics.lock().await;
                                m.record_sync_success(rtt, fresh.len());
                                if m.sync_attempts.is_multiple_of(10) {
                                    tracing::info!(
                                        sync_attempts = m.sync_attempts,
                                        sync_success = m.sync_success,
                                        success_rate = m.success_rate(),
                                        p50_rtt_ms = m.p50_rtt_ms,
                                        p95_rtt_ms = m.p95_rtt_ms,
                                        delta_bytes_per_sync = m.delta_bytes_per_sync,
                                        cache_hit_rate = m.cache_hit_rate,
                                        "gossip metrics periodic fanout"
                                    );
                                }
                            }
                            self_clone.log_fresh_inserts(&fresh).await;
                            self_clone.gossip_checkpoint_sigs(&mut *guard).await;
                        }
                    }
                });
            }
            while let Some(res) = join_set.join_next().await {
                if let Err(e) = res {
                    tracing::warn!(error=%e, "fanout task panicked");
                }
            }

            self.process_finalized_rounds().await;

            let decided = {
                let hg = self.hashgraph.lock().await;
                hg.highest_decided_round()
            };
            if decided > decided_watermark {
                decided_watermark = decided;
                tracing::info!(decided_round = decided, "round decided");
                let m = self.gossip_metrics.lock().await.clone();
                tracing::info!(
                    sync_attempts = m.sync_attempts,
                    sync_success = m.sync_success,
                    success_rate = m.success_rate(),
                    p50_rtt_ms = m.p50_rtt_ms,
                    p95_rtt_ms = m.p95_rtt_ms,
                    delta_bytes_per_sync = m.delta_bytes_per_sync,
                    cache_hit_rate = m.cache_hit_rate,
                    "gossip metrics fanout"
                );
                let mut cache = outbound.lock().await;
                let cap = outbound_capacity(self.peers.lock().await.len());
                if cache.cap() != cap {
                    cache.resize(cap);
                }
            }
        }
        if !self.flush_streams(Duration::from_secs(5)).await {
            tracing::warn!("stream flush barrier timed out or failed");
            self.gossip_metrics.lock().await.sync_failures += 1;
        }
        Ok(())
    }

    /// Decodes every newly finalized event's payload, buckets membership ops
    /// by `roundReceived`, and activates any whose activation round is now
    /// fully decided. Called after each sync round, regardless of whether the
    /// sync itself succeeded.
    ///
    /// Activation round = `roundReceived + 1`, and activation fires only once
    /// that round is fully decided — the same finality notion `order.rs` uses
    /// to produce finalized order — so node 4 is never admitted into a
    /// round whose fame elections are still running under the old roster.
    /// The new roster first applies to `activation_round + 1`.
    ///
    /// Lock discipline: Phase A collects all needed data under the hashgraph
    /// lock alone; Phase B holds only the executor + activation locks; Phase C
    /// touches each store with its own short lock and never holds two at
    /// once. This eliminates the deadlock hazard of acquiring `hg`,
    /// `registry`, and `peers` in nested order.
    pub async fn process_finalized_rounds(&self) {
        // Phase A: collect (event, round_received) pairs under the hg lock only.
        let finalized: Vec<(Event, u64)> = {
            let hg = self.hashgraph.lock().await;
            state::finalized_events(&hg)
                .into_iter()
                .filter_map(|event| {
                    let hash = event.hash().expect("hash bounded");
                    hg.round_received(&hash).map(|rr| (event, rr))
                })
                .collect()
        };

        // Phase A.5: record each newly finalized event's ordering in the
        // durable log (Phase 8) so a later replay reproduces `roundReceived`
        // exactly instead of re-deriving it. Called for every finalized event;
        // `EventLog::set_round_received` is idempotent, so late events with
        // `rr <= watermark` (H-2) still get persisted for crash recovery.
        let sink = self.event_sink.lock().await.clone();
        if let Some(sink) = &sink {
            for (event, rr) in &finalized {
                sink.set_round_received(&event.hash().expect("hash bounded"), *rr);
            }
        }

        if !finalized.is_empty() {
            // Phase B: execute finalized events one round at a time,
            // capturing the deterministic Merkle root after each round's
            // events. Rooting per round — rather than rooting the state once
            // at the end of the batch — is what makes every node compute the
            // *identical* root for a given round's checkpoint regardless of
            // how many later rounds landed in the same batch; without it, two
            // nodes producing a checkpoint for the same round at different
            // finalization points would sign different bytes and their
            // signatures would never verify against each other. The
            // serialized state is captured at the same point, so a reconnect
            // learner can be served the state exactly as it stood at the
            // checkpoint round.
            let (state_hashes, snapshots, diffs) = {
                let (pre_batch_hash, pre_batch_bytes) = {
                    let executor = self.executor.lock().await;
                    (executor.state().root(), executor.state().to_bytes())
                };
                let mut activation = self.activation.lock().await;
                let mut executor = self.executor.lock().await;
                let mut by_round: BTreeMap<u64, Vec<(Event, u64)>> = BTreeMap::new();
                for pair in &finalized {
                    by_round.entry(pair.1).or_default().push(pair.clone());
                }
                let mut hashes: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
                let mut snapshots: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
                let mut diffs: BTreeMap<u64, Vec<stream::pb::StateDiff>> = BTreeMap::new();
                hashes.insert(0, pre_batch_hash);
                snapshots.insert(0, pre_batch_bytes);
                let ActivationState { pending, processed_through_round, .. } = &mut *activation;
                let original_watermark = *processed_through_round;
                for (round, events) in by_round {
                    let before_root = executor.state().root();
                    let round_diffs_map = match executor.bucket_finalized_with_diffs(
                        pending,
                        processed_through_round,
                        &events,
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::error!(round, error = %e, "bucket_finalized failed");
                            continue;
                        }
                    };
                    let pb_diffs: Vec<stream::pb::StateDiff> = round_diffs_map
                        .get(&round)
                        .map(|vec| {
                            vec.iter()
                                .map(|d| stream::pb::StateDiff {
                                    key: d.key.clone(),
                                    value: d.value.clone(),
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    let after_root = executor.state().root();
                    if round > original_watermark {
                        hashes.insert(round, after_root);
                        snapshots.insert(round, executor.state().to_bytes());
                        diffs.insert(round, pb_diffs);
                    } else {
                        if after_root != before_root {
                            hashes.insert(*processed_through_round, after_root);
                            snapshots.insert(*processed_through_round, executor.state().to_bytes());
                        }
                        if !pb_diffs.is_empty() {
                            let target = *processed_through_round;
                            let mut merged: BTreeMap<Vec<u8>, Option<Vec<u8>>> = BTreeMap::new();
                            if let Some(existing) = diffs.remove(&target) {
                                for d in existing {
                                    merged.insert(d.key, d.value);
                                }
                            }
                            for d in pb_diffs {
                                merged.insert(d.key, d.value);
                            }
                            let merged_vec = merged
                                .into_iter()
                                .map(|(k, v)| stream::pb::StateDiff { key: k, value: v })
                                .collect();
                            diffs.insert(target, merged_vec);
                        }
                    }
                }
                (hashes, snapshots, diffs)
            };

            // Phase C: activate ops whose activation round is now fully decided.
            let candidate_rrs: Vec<u64> = {
                let activation = self.activation.lock().await;
                activation.pending.keys().copied().collect()
            };

            for rr in candidate_rrs {
                let activation_round = rr + 1;
                let is_decided = {
                    let hg = self.hashgraph.lock().await;
                    hg.is_round_decided(activation_round)
                };
                if !is_decided {
                    continue;
                }

                let ops = {
                    let mut activation = self.activation.lock().await;
                    activation.pending.remove(&rr).unwrap_or_default()
                };

                for op in ops {
                    if let MembershipOp::Add { node, key, bls_key, pop, addr, reconnect_addr } = op
                    {
                        let already_member = {
                            let hg = self.hashgraph.lock().await;
                            hg.is_member(&node)
                        };
                        if already_member {
                            continue;
                        }

                        if !verify_pop_bytes(&bls_key, &pop) {
                            tracing::warn!(
                                node_id = node.get(),
                                "invalid BLS PoP for add-member; skipping activation"
                            );
                            continue;
                        }

                        let key: VerifyingKey = *key;
                        // Build the post-join registry from the roster active at
                        // the activation round (which still excludes the new node).
                        let mut new_registry = {
                            let hg = self.hashgraph.lock().await;
                            hg.registry_at_round(activation_round)
                        };
                        new_registry.register(node, key, bls_key);

                        // Atomic: structural growth + roster schedule in one call.
                        {
                            let mut hg = self.hashgraph.lock().await;
                            hg.add_member(node, activation_round, new_registry);
                        }

                        // Persist the extended roster history (Phase 8) so a
                        // future restart can replay the log and verify each
                        // event against the roster active at its birth round.
                        let roster_bytes = {
                            let hg = self.hashgraph.lock().await;
                            consensus::encode_roster_history(hg.roster_history())
                                .expect("roster_history bounded")
                        };
                        let sink = self.event_sink.lock().await.clone();
                        if let Some(sink) = &sink {
                            sink.set_roster_history(&roster_bytes);
                        }

                        // Keep the event-verification registry in sync so the new
                        // node's events can be verified and inserted.
                        {
                            let mut registry = self.registry.lock().await;
                            registry.register(node, key, bls_key);
                        }

                        // TLS-pin the new peer, deriving the fingerprint from its
                        // Ed25519 key (same derivation as boot-time peers), and
                        // carry its reconnect port so it can serve as a
                        // reconnect source for the existing cluster.
                        {
                            let mut pm = self.peers.lock().await;
                            pm.add_peer_from_key(node, &key, addr, reconnect_addr);
                        }
                    }
                }
            }

            // Phase D: produce checkpoints for every round decided since the
            // last pass. State hashes are cumulative so `prev_checkpoint_hash_for`
            // rebuilds read true per-round hashes (Rule 1), not the pass-local
            // pre-batch sentinel.
            let cumulative_state_hashes = {
                let mut cumulative = self.cumulative_state_hashes.lock().await;
                for (round, hash) in &state_hashes {
                    if *round != 0 {
                        cumulative.insert(*round, *hash);
                    }
                }
                cumulative.clone()
            };
            self.produce_pending_checkpoints(&cumulative_state_hashes, &snapshots, &diffs).await;
        } else {
            let (bytes, _root) = {
                let executor = self.executor.lock().await;
                (executor.state().to_bytes(), executor.state().root())
            };
            let cumulative_state_hashes = self.cumulative_state_hashes.lock().await.clone();
            let snapshots = BTreeMap::from([(0, bytes)]);
            let diffs: BTreeMap<u64, Vec<stream::pb::StateDiff>> = BTreeMap::new();
            self.produce_pending_checkpoints(&cumulative_state_hashes, &snapshots, &diffs).await;
        }
        self.checkpoint_notify.notify_waiters();
    }

    /// Emits a checkpoint for every round decided since the last pass, in
    /// ascending order. A round is decided when all its witnesses have a
    /// final fame decision *and* this node's view of the round is complete
    /// (`is_round_decided`), which is exactly the point at which its ordering
    /// can no longer change.
    async fn produce_pending_checkpoints(
        &self,
        state_hashes: &BTreeMap<u64, [u8; 32]>,
        snapshots: &BTreeMap<u64, Vec<u8>>,
        diffs: &BTreeMap<u64, Vec<stream::pb::StateDiff>>,
    ) {
        loop {
            let round = self.activation.lock().await.checkpoint_watermark + 1;
            let decided = {
                let hg = self.hashgraph.lock().await;
                hg.is_round_decided(round)
            };
            if !decided {
                break;
            }
            {
                let mut activation = self.activation.lock().await;
                activation.checkpoint_watermark = round;
            }
            self.produce_checkpoint(round, state_hashes, snapshots, diffs).await;
        }
    }

    /// Builds and signs the checkpoint payload for `round`, registers the
    /// self-signature, flushes any inbound signatures buffered for the round,
    /// and accepts the checkpoint if quorum is reached.
    ///
    /// The state hash is taken from `state_hashes`: the hash recorded after
    /// processing the latest finalized round at or before `round` — i.e. the
    /// deterministic state exactly at this checkpoint, identical on every
    /// node, so signatures produced here verify against any peer.
    async fn produce_checkpoint(
        &self,
        round: u64,
        state_hashes: &BTreeMap<u64, [u8; 32]>,
        snapshots: &BTreeMap<u64, Vec<u8>>,
        diffs: &BTreeMap<u64, Vec<stream::pb::StateDiff>>,
    ) {
        let snapshot_bytes = snapshots
            .range(..=round)
            .next_back()
            .map(|(_, bytes)| bytes.clone())
            .expect("the round-0 sentinel always present");
        let diffs_for_round = diffs.get(&round).cloned().unwrap_or_default();
        let signed_snapshot = self.signed_checkpoints.lock().await.clone();
        let payload = {
            let hg = self.hashgraph.lock().await;
            Self::canonical_checkpoint_payload_chained(&hg, round, state_hashes, &signed_snapshot)
        };
        let Some(payload) = payload else { return };

        let sig = self.bls_identity.sign(&payload.signing_bytes());
        let own_sig = CheckpointSig { round, signer: self.node_id, sig };
        self.outbound_checkpoint_sigs.lock().await.push(own_sig);

        let roster = {
            let hg = self.hashgraph.lock().await;
            hg.registry_at_round(round)
        };

        let pending = {
            let mut pending = self.pending_checkpoint_sigs.lock().await;
            pending.remove(&round).unwrap_or_default()
        };

        let (accepted, snapshot) = {
            let mut accumulators = self.checkpoint_accumulators.lock().await;
            let accumulator = accumulators
                .entry(round)
                .or_insert_with(|| CheckpointAccumulator::new(payload, snapshot_bytes));
            let mut accepted = accumulator.add_sig(own_sig, &roster);
            for sig in pending {
                if accepted.is_some() {
                    break;
                }
                if verify_checkpoint_sig(&sig, &accumulator.signing_bytes(), &roster) {
                    accepted = accumulator.add_sig(sig, &roster);
                }
            }
            let snapshot =
                if accepted.is_some() { Some(accumulator.snapshot().to_vec()) } else { None };
            if accepted.is_some() {
                accumulators.remove(&round);
            }
            (accepted, snapshot)
        };
        if let (Some(accepted), Some(snapshot)) = (accepted, snapshot) {
            self.accept_checkpoint(accepted, snapshot, diffs_for_round).await;
        }
    }

    /// Pure helper: the canonical checkpoint payload for `round` derived
    /// solely from decided history — the hashgraph's consensus order and
    /// the deterministic `state_hashes` map. Determinism is critical:
    /// every honest node must derive byte-identical payloads for the same
    /// round regardless of local acceptance progress (PLAN-2 Rule 1).
    ///
    /// Returns `None` while `round` is not yet decided or when no
    /// `state_hash` is available at or below `round`.
    fn canonical_checkpoint_payload(
        hg: &consensus::Hashgraph,
        round: u64,
        state_hashes: &BTreeMap<u64, [u8; 32]>,
    ) -> Option<consensus::CheckpointPayload> {
        let state_hash = *state_hashes.range(..=round).next_back()?.1;
        // Determinism: records_root is over consensus-order items for the round
        // (final/deterministic once the round is decided).
        let order = hg.consensus_order(round);
        let mut items = Vec::with_capacity(order.len());
        for hash in &order {
            if let Some(record) = hg.get(hash) {
                for (idx, tx) in record.event().payload().iter().enumerate() {
                    let tx_index = u32::try_from(idx)
                        .expect("tx_index must fit u32 - payload length bounded by u32::MAX");
                    items.push(RecordsRootItem {
                        event_hash: *hash.as_bytes(),
                        tx_index,
                        tx_payload: tx.payload().to_vec(),
                    });
                }
            }
        }
        let records_root = consensus::compute_records_root(&items);
        hg.checkpoint_payload(round, records_root, state_hash)
    }

    /// PLAN-2 Rule 1: the chained payload for `round`, where `prev_checkpoint_hash`
    /// is a pure function of decided history (plus a stored-checkpoint fallback
    /// for the restart-from-K pruned-graph case). Every honest node derives the
    /// identical bytes for the same `round` regardless of local acceptance lag.
    fn canonical_checkpoint_payload_chained(
        hg: &consensus::Hashgraph,
        round: u64,
        state_hashes: &BTreeMap<u64, [u8; 32]>,
        signed: &[SignedCheckpoint],
    ) -> Option<consensus::CheckpointPayload> {
        let base = Self::canonical_checkpoint_payload(hg, round, state_hashes)?;
        let prev = Self::prev_checkpoint_hash_for(hg, round, state_hashes, signed);
        Some(base.with_prev_checkpoint_hash(prev))
    }

    /// `prev_checkpoint_hash(R)` — the hash honest nodes sign for round `R`.
    /// Priority: stored checkpoint for `R-1` (covers restart-from-K where the
    /// hashgraph is pruned and cannot rebuild `K`), else the rebuilt chained
    /// payload for `R-1` from decided history, else genesis zeros.
    fn prev_checkpoint_hash_for(
        hg: &consensus::Hashgraph,
        round: u64,
        state_hashes: &BTreeMap<u64, [u8; 32]>,
        signed: &[SignedCheckpoint],
    ) -> [u8; 32] {
        if round == 0 {
            return [0u8; 32];
        }
        let prev_round = round - 1;
        if let Some(sc) = signed.iter().find(|sc| sc.payload.round == prev_round) {
            return sc.payload.signing_bytes_hash();
        }
        if let Some(prev_payload) =
            Self::canonical_checkpoint_payload_chained(hg, prev_round, state_hashes, signed)
        {
            return prev_payload.signing_bytes_hash();
        }
        [0u8; 32]
    }

    /// Feeds an inbound `CheckpointSig` into the accumulator for its round.
    /// The signature is verified against the roster active at that round
    /// before it is counted. If this node has not yet produced its own
    /// checkpoint for the round (so it has no payload to verify against),
    /// the signature is buffered and flushed when `produce_checkpoint` runs.
    async fn feed_checkpoint_sig(&self, sig: CheckpointSig) {
        let watermark =
            self.signed_checkpoints.lock().await.last().map(|c| c.payload.round).unwrap_or(0);
        if sig.round <= watermark {
            return;
        }
        if !self.is_pending_sig_admissible(&sig).await {
            return;
        }
        let signing_bytes = {
            let accumulators = self.checkpoint_accumulators.lock().await;
            accumulators.get(&sig.round).map(CheckpointAccumulator::signing_bytes)
        };
        let Some(signing_bytes) = signing_bytes else {
            self.buffer_pending_sig(sig).await;
            return;
        };
        let roster = {
            let hg = self.hashgraph.lock().await;
            hg.registry_at_round(sig.round)
        };
        if !verify_checkpoint_sig(&sig, &signing_bytes, &roster) {
            return;
        }
        let accepted = {
            let mut accumulators = self.checkpoint_accumulators.lock().await;
            let round = sig.round;
            let accepted = accumulators.get_mut(&round).and_then(|acc| {
                let accepted = acc.add_sig(sig, &roster)?;
                Some((accepted, acc.snapshot().to_vec()))
            });
            if accepted.is_some() {
                accumulators.remove(&round);
            }
            accepted
        };
        if let Some((accepted, snapshot)) = accepted {
            self.accept_checkpoint(accepted, snapshot, Vec::new()).await;
        }
    }

    /// Records an accepted checkpoint and prunes history below it, keeping a
    /// `RETENTION_ROUNDS` margin so a peer that fell behind can still
    /// delta-sync.
    ///
    /// State snapshots older than the prune floor are dropped too: a learner
    /// is always served the highest accepted checkpoint (round ≥ `round -
    /// RETENTION_ROUNDS`), so anything below the floor can never be served
    /// again and keeping it would only grow memory.
    async fn accept_checkpoint(
        &self,
        accepted: SignedCheckpoint,
        snapshot: Vec<u8>,
        diffs: Vec<stream::pb::StateDiff>,
    ) {
        let round = accepted.payload.round;
        // Defensive: refuse to persist a snapshot that does not rebuild to the
        // committed root. The accumulator carries the bytes captured in the same
        // producing pass as the payload, so this holds by construction — but a
        // divergence here would brick restart recovery (`verify_persisted`),
        // mirroring the rejection applied on the reconnect path.
        if state::State::root_of_bytes(&snapshot) != Some(accepted.payload.state_hash) {
            tracing::error!(
                round,
                "refusing to accept checkpoint: snapshot does not rebuild to the committed state_hash"
            );
            self.gossip_metrics.lock().await.sync_failures += 1;
            return;
        }
        // Durable copy: the `.snap` file is gone; a restart restores the
        // exact checkpoint-round state from this `snap` keyspace entry.
        // Flush *before* the checkpoint is recorded as accepted so a crash
        // cannot leave a checkpoint file that references a missing snapshot
        // on restart. The monotonic `last_timestamp` watermark is stored
        // alongside the snapshot so a restart with a backward wall clock
        // cannot emit a timestamp lower than a pre-restart event from the
        // same creator.
        let watermark = self.last_timestamp.load(Ordering::Relaxed);
        if let Err(e) = self.state_db.set_watermark(watermark) {
            tracing::error!(round, error = %e, "failed to persist timestamp watermark");
            return;
        }
        if let Err(e) = self.state_db.snapshot_and_flush(round, &snapshot) {
            tracing::error!(round, error = %e, "failed to persist state snapshot");
            return;
        }
        self.notify_checkpoint_accepted(&accepted).await;
        // Mirror streams (Phase 8): emit the round's record stream file
        // from the threshold-signed anchor. The writer assembles the
        // items from `consensus_order(round)` — final and immutable by
        // now — and writes the `.rsf` on its background task, so the
        // hot path never blocks on disk. Runs before pruning below, and
        // pruning only removes rounds already ordered, so the assembly
        // is race-free even when it runs concurrently.
        let record_sink = self.record_sink.lock().await.clone();
        let proof_sink = self.record_proof_sink.lock().await.clone();
        let proof_is_duplicate = match (&record_sink, &proof_sink) {
            (Some(r), Some(p)) => Arc::ptr_eq(r, p),
            _ => false,
        };
        if let Some(record_sink) = record_sink {
            stream::RecordSink::persist(&*record_sink, &accepted, diffs.clone()).await;
        }
        if let Some(proof_sink) = proof_sink
            && !proof_is_duplicate
        {
            stream::RecordSink::persist(&*proof_sink, &accepted, diffs).await;
        }
        {
            let mut signed = self.signed_checkpoints.lock().await;
            signed.push(accepted);
            signed.sort_by_key(|c| c.payload.round);
        }
        // Record the accepted snapshot under its exact round so a reconnect
        // learner is served the state exactly as it stood at this checkpoint.
        self.state_snapshots.lock().await.insert(round, snapshot);
        {
            let mut outbound = self.outbound_checkpoint_sigs.lock().await;
            outbound.retain(|sig| sig.round > round);
        }
        {
            let mut pending = self.pending_checkpoint_sigs.lock().await;
            pending.retain(|r, _| *r > round);
        }
        let prune_before_round = round.saturating_sub(RETENTION_ROUNDS);
        {
            let mut snapshots = self.state_snapshots.lock().await;
            snapshots.retain(|&snap_round, _| snap_round >= prune_before_round);
        }
        {
            let mut cumulative = self.cumulative_state_hashes.lock().await;
            cumulative.retain(|&r, _| r == 0 || r >= prune_before_round);
        }
        if let Err(e) = self.state_db.prune_snapshots_before(prune_before_round) {
            tracing::warn!(prune_before_round, error = %e, "failed to prune state snapshots");
        }
        let pruned = {
            let mut hg = self.hashgraph.lock().await;
            hg.prune_before_round(prune_before_round)
        };
        // Mirror the in-memory prune in the durable log and state database
        // (Phase 8) and make everything up to this checkpoint durable.
        let sink = self.event_sink.lock().await.clone();
        if let Some(sink) = &sink {
            sink.prune(&pruned);
            sink.flush();
        }
        self.flush_event_stream_sink().await;
        if let Err(e) = self.state_db.flush() {
            tracing::error!(error = %e, "failed to flush the state database");
        }
        self.checkpoint_notify.notify_waiters();
    }

    /// Feeds an accepted checkpoint to the registered [`CheckpointSink`], if
    /// any.
    async fn notify_checkpoint_accepted(&self, checkpoint: &SignedCheckpoint) {
        let sink = self.checkpoint_sink.lock().await.clone();
        if let Some(sink) = sink {
            sink.persist(checkpoint);
        }
    }

    /// The public inbound entry for a checkpoint signature — mirrors the
    /// `Frame::CheckpointSig` handling in `handle_inbound` so tests can
    /// exercise the same path without a live connection.
    pub async fn submit_checkpoint_sig(&self, sig: CheckpointSig) {
        let watermark =
            self.signed_checkpoints.lock().await.last().map(|c| c.payload.round).unwrap_or(0);
        if sig.round <= watermark {
            return;
        }
        if !self.is_pending_sig_admissible(&sig).await {
            return;
        }
        let decided = {
            let hg = self.hashgraph.lock().await;
            hg.is_round_decided(sig.round)
        };
        if decided {
            self.feed_checkpoint_sig(sig).await;
        } else {
            self.buffer_pending_sig(sig).await;
        }
    }

    async fn is_pending_sig_admissible(&self, sig: &CheckpointSig) -> bool {
        let roster = {
            let hg = self.hashgraph.lock().await;
            hg.registry_at_round(sig.round)
        };
        roster.contains(&sig.signer)
    }

    async fn buffer_pending_sig(&self, sig: CheckpointSig) {
        let mut pending = self.pending_checkpoint_sigs.lock().await;
        let entry = pending.entry(sig.round).or_default();
        if entry.iter().any(|existing| existing.signer == sig.signer) {
            return;
        }
        if entry.len() >= MAX_PENDING_SIGS_PER_ROUND {
            return;
        }
        entry.push(sig);
    }

    /// The signing bytes the node's checkpoint for `round` is over, if one
    /// has been produced. Tests use this to craft valid signatures.
    pub async fn checkpoint_signing_bytes(&self, round: u64) -> Option<[u8; 136]> {
        self.checkpoint_accumulators
            .lock()
            .await
            .get(&round)
            .map(CheckpointAccumulator::signing_bytes)
    }

    /// The accepted checkpoint for `round`, if any.
    pub async fn signed_checkpoint_for(&self, round: u64) -> Option<SignedCheckpoint> {
        self.signed_checkpoints.lock().await.iter().find(|c| c.payload.round == round).cloned()
    }

    /// The round of the highest accepted checkpoint, if any. `signed_checkpoints`
    /// is kept sorted by round, so the last entry is the highest.
    pub async fn latest_accepted_checkpoint_round(&self) -> Option<u64> {
        self.signed_checkpoints.lock().await.last().map(|c| c.payload.round)
    }

    /// The highest accepted [`SignedCheckpoint`], if any. Exposes the
    /// embedded roster snapshot for observability — `jkaind status` uses it
    /// to flag a checkpoint roster that disagrees with the live registry.
    pub async fn latest_signed_checkpoint(&self) -> Option<SignedCheckpoint> {
        self.signed_checkpoints.lock().await.last().cloned()
    }

    /// Sends every pending checkpoint signature on the given transport. Own
    /// signatures are re-sent on each successful sync until the round's
    /// checkpoint is accepted, so a peer that missed one delivery still
    /// accumulates them.
    async fn gossip_checkpoint_sigs(&self, transport: &mut (impl SyncTransport + Send)) {
        let sigs = self.outbound_checkpoint_sigs.lock().await.clone();
        for sig in sigs {
            if let Err(e) = transport.send_frame(&Frame::CheckpointSig(sig)).await {
                tracing::warn!(error = %e, "failed to send CheckpointSig");
                self.gossip_metrics.lock().await.sync_failures += 1;
                return;
            }
        }
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(e) => {
                    tracing::warn!(error = %e, "gossip accept failed");
                    self.gossip_metrics.lock().await.sync_failures += 1;
                    continue;
                }
            };
            tokio::spawn(self.clone().handle_inbound(stream));
        }
    }

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream) {
        let transport = TcpTransport::new(self.identity.clone());
        let acceptor = match transport.acceptor() {
            Ok(acceptor) => acceptor,
            Err(e) => {
                tracing::warn!(error = %e, "inbound: failed to build TLS acceptor");
                self.gossip_metrics.lock().await.sync_failures += 1;
                return;
            }
        };
        let tls = match acceptor.accept(stream).await {
            Ok(tls) => tls,
            Err(e) => {
                tracing::warn!(error = %e, "inbound: TLS accept failed");
                self.gossip_metrics.lock().await.sync_failures += 1;
                return;
            }
        };
        let mut transport = TcpTransport::from_tls_stream(self.identity.clone(), tls);

        loop {
            let frame = match transport.recv_frame().await {
                Ok(frame) => frame,
                Err(e) => {
                    tracing::warn!(error = %e, "inbound: recv_frame failed");
                    self.gossip_metrics.lock().await.sync_failures += 1;
                    return;
                }
            };
            match frame {
                Frame::SyncRequest(request) => {
                    let delta_result = {
                        let hashgraph = self.hashgraph.lock().await;
                        let mut dedup_map = self.dedup_state.lock().await;
                        let dedup = dedup_map.entry(request.from).or_default();
                        let config = self.sync_config.clone();
                        let target_peer = request.from;
                        delta_events_filtered(
                            &hashgraph,
                            &request.known,
                            self.node_id,
                            target_peer,
                            dedup,
                            &config,
                        )
                    };
                    match delta_result {
                        Ok(events) => {
                            let response = Frame::SyncResponse(SyncResponse { events });
                            if transport.send_frame(&response).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => {
                            // Phase 4: the requester is behind the history
                            // this node has pruned, so no delta can be built.
                            // Signal it explicitly — an empty delta would be
                            // indistinguishable from "you already know
                            // everything", and the requester's own event
                            // creation succeeds against its own held events,
                            // so nothing else would trigger a reconnect.
                            if transport.send_frame(&Frame::Behind).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                Frame::Event(event) => {
                    let registry = self.registry.lock().await.clone();
                    match insert_verified(&self.hashgraph, &registry, event).await {
                        Ok(fresh) => {
                            if let Some(hash) = fresh {
                                self.log_fresh_inserts(&[hash]).await;
                            }
                        }
                        Err(_) => return,
                    }
                }
                Frame::CheckpointSig(sig) => {
                    self.submit_checkpoint_sig(sig).await;
                }
                Frame::SyncResponse(_) => return,
                // The reconnect protocol runs on a dedicated port and is
                // handled by `handle_reconnect_inbound`; a reconnect frame
                // arriving on the gossip port is a protocol violation.
                Frame::Reconnect(_) => return,
                Frame::ReconnectResponse(_) => return,
                Frame::Behind => return,
            }
        }
    }

    /// Phase 4 — constructs a node that starts from a checkpoint rather than
    /// from genesis. A shell node is built with an empty registry and an
    /// empty hashgraph; `apply_checkpoint` immediately overwrites them from
    /// `response`. The caller must supply a response obtained and validated
    /// via `reconnect::fetch_checkpoint`.
    pub async fn from_checkpoint(
        node_id: NodeId,
        signing_key: SigningKey,
        identity: TlsIdentity,
        peers: Vec<PeerInfo>,
        sync_timing: SyncTiming,
        response: ReconnectResponse,
        state_db: Arc<state::StateDb>,
    ) -> Result<Self> {
        let bls_identity =
            BlsIdentity::from_ikm(&signing_key.to_bytes()).expect("BLS identity from signing key");
        Self::from_checkpoint_with_bls(
            node_id,
            signing_key,
            bls_identity,
            identity,
            peers,
            sync_timing,
            response,
            state_db,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn from_checkpoint_with_bls(
        node_id: NodeId,
        signing_key: SigningKey,
        bls_identity: BlsIdentity,
        identity: TlsIdentity,
        peers: Vec<PeerInfo>,
        sync_timing: SyncTiming,
        response: ReconnectResponse,
        state_db: Arc<state::StateDb>,
    ) -> Result<Self> {
        let shell = Self::new_with_bls(
            node_id,
            signing_key,
            bls_identity,
            MembershipRegistry::new(),
            identity,
            peers,
            sync_timing,
            state_db,
        );
        if !shell.apply_checkpoint(response).await {
            return Err(GossipError::Reconnect("checkpoint could not be applied".into()));
        }
        Ok(shell)
    }

    /// Phase 4 — loads a validated reconnect response: restores the executor
    /// state, rebuilds the hashgraph scaffold and loads the teacher's retained
    /// graph into it, advances the activation watermarks past the checkpoint
    /// round, and records the accepted checkpoint.
    ///
    /// Returns `false` (without applying anything) if the response is
    /// inconsistent — a lying peer must never be able to crash this node via
    /// a panic. The caller keeps `needs_reconnect` set so a failed load is
    /// retried next interval.
    async fn apply_checkpoint(&self, response: ReconnectResponse) -> bool {
        let checkpoint = &response.signed_checkpoint;
        let cp_round = checkpoint.payload.round;
        let sink = self.event_sink.lock().await.clone();

        // 1. The served state bytes must rebuild to the committed Merkle
        //    root. The teacher serves the state exactly as it stood at the
        //    checkpoint round, so this holds; the learner replays only the
        //    retained events newer than the checkpoint (step 7's watermark).
        //    Validate before touching the live partition so invalid bytes
        //    never wipe the current state — mirrors the
        //    `root_of_bytes == state_hash` guard in `accept_checkpoint`.
        let Some(verified_root) = state::State::root_of_bytes(&response.state_bytes) else {
            tracing::error!("reconnect: invalid state bytes from peer");
            return false;
        };
        if verified_root != checkpoint.payload.state_hash {
            tracing::error!("reconnect: state hash mismatch; rejecting checkpoint");
            return false;
        }
        let state = {
            if let Err(e) = self.state_db.clear_state() {
                tracing::error!(error = %e, "reconnect: failed to reset state partition");
                return false;
            }
            let Some(state) =
                state::State::from_bytes(self.state_db.state_keyspace(), &response.state_bytes)
            else {
                tracing::error!("reconnect: invalid state bytes from peer");
                return false;
            };
            state
        };
        debug_assert_eq!(state.root(), checkpoint.payload.state_hash);

        // 2. Decode the roster history.
        let Some(roster_history) = consensus::decode_roster_history(&response.roster_history_bytes)
        else {
            tracing::error!("reconnect: invalid roster history from peer");
            return false;
        };

        // 3. The roster active at the checkpoint round must match the
        //    committed roster_hash.
        let roster_at_cp = roster_history.roster_for_round(cp_round);
        if roster_at_cp.hash().expect("hash bounded") != checkpoint.payload.roster_hash {
            tracing::error!("reconnect: roster hash mismatch; rejecting checkpoint");
            return false;
        }

        // 3b. The roster must carry this node's own key. If it is absent or
        //     holds a different key, this node could never produce an event
        //     that verifies against the restored registry — every sync round
        //     would fail silently and consensus would stall. This is the
        //     live-path guard for the same misconfiguration the restart path
        //     refuses in `node::restart` (a `jkaind init --force` rotation
        //     without wiping `data/`).
        let own_key = self.signing_key.verifying_key();
        match checkpoint.payload.roster_snapshot.key_for(&self.node_id) {
            Err(_) => {
                tracing::error!(
                    node_id = self.node_id.get(),
                    "node not in served checkpoint roster; rejecting checkpoint"
                );
                return false;
            }
            Ok(key) if key.as_bytes() != own_key.as_bytes() => {
                tracing::error!(
                    node_id = self.node_id.get(),
                    "served checkpoint roster key does not match this node's secret; rejecting checkpoint"
                );
                return false;
            }
            Ok(_) => {}
        }

        // 4. Restore the executor from the checkpoint state — the state
        //    exactly at the checkpoint round, so replaying the retained
        //    window in `process_finalized_rounds` is exactly-once. The served
        //    bytes are retained as this node's own snapshot for that round —
        //    in memory (for reconnect serving) and in the state database's
        //    `snap` keyspace (so a future restart restores and verifies the
        //    same round) — so it can serve the same checkpoint to a future
        //    learner.
        *self.executor.lock().await = state::Executor::from_state(state);
        if let Err(e) = self.state_db.snapshot(cp_round, &response.state_bytes) {
            tracing::error!(round = cp_round, error = %e, "reconnect: failed to persist state snapshot");
            return false;
        }
        self.state_snapshots.lock().await.insert(cp_round, response.state_bytes.clone());
        {
            let mut cumulative = self.cumulative_state_hashes.lock().await;
            cumulative.clear();
            cumulative.insert(0, state::SparseMerkleTree::new().root());
            cumulative.insert(cp_round, checkpoint.payload.state_hash);
        }

        // 5. Rebuild the hashgraph scaffold and load the teacher's retained
        //    graph into it. The retained events carry their full record
        //    metadata (seq, round, ancestor_seqs, ordering), so this node's
        //    known-summary frontier is honest — it holds complete chains,
        //    not just per-creator heads — and future delta syncs never
        //    reference a parent it lacks. Retained events are
        //    signature-verified against the checkpoint roster first: a
        //    malicious teacher must not be able to poison the learner's
        //    graph with forged events.
        let stream_sink = self.event_stream_sink.lock().await.clone();
        {
            let mut hg = self.hashgraph.lock().await;
            *hg = consensus::Hashgraph::from_checkpoint(&checkpoint.payload, roster_history);
            for retained in &response.retained {
                let verified = match retained
                    .event
                    .clone()
                    .verify(&checkpoint.payload.roster_snapshot)
                {
                    Ok(verified) => verified,
                    Err(e) => {
                        tracing::error!(error = %e, "reconnect: retained event failed verification");
                        return false;
                    }
                };
                if let Err(e) = hg.insert_accepted(
                    verified.into_inner(),
                    retained.seq,
                    retained.round,
                    retained.ancestor_seqs.clone(),
                    retained.round_received,
                    retained.consensus_timestamp,
                ) {
                    tracing::error!(error = %e, "reconnect: retained event rejected");
                    return false;
                }
                if let Some(sink) = &sink {
                    sink.append(retained);
                }
                if let Some(stream_sink) = &stream_sink {
                    stream_sink.append(retained);
                }
            }
            // Rounds the teacher already finalized stay finalized here, so
            // this node keeps producing matching checkpoints instead of
            // re-deciding history it holds.
            hg.mark_decided_through(response.decided_round);
        }

        // Persist the roster history (Phase 8) so a future restart can
        // replay the log and verify each event against the roster active at
        // its birth round — regardless of whether this node learned the
        // history from a peer or from its own log.
        if let Some(sink) = &sink {
            sink.set_roster_history(&response.roster_history_bytes);
        }

        // 6. The live verification registry mirrors the checkpoint roster.
        *self.registry.lock().await = checkpoint.payload.roster_snapshot.clone();

        // 7. Advance the activation watermarks so `process_finalized_rounds`
        //    does not re-process the rounds the checkpoint already covers.
        {
            let mut activation = self.activation.lock().await;
            activation.processed_through_round = activation.processed_through_round.max(cp_round);
            activation.checkpoint_watermark = activation.checkpoint_watermark.max(cp_round);
        }

        // 7b. Restore the monotonic timestamp watermark from durable checkpoint
        //     state. `response.last_timestamp` is the teacher's (or local
        //     restart's) watermark persisted with the checkpoint. Also consider
        //     the max timestamp among retained own events to cover events emitted
        //     after the checkpoint but before a crash. Do not rely solely on
        //     retained events because pruning can remove the newest own event.
        {
            let retained_max = response
                .retained
                .iter()
                .filter(|r| *r.event.creator() == self.node_id)
                .map(|r| r.event.timestamp().get())
                .max()
                .unwrap_or(0);
            let target = response.last_timestamp.max(retained_max);
            self.last_timestamp.fetch_max(target, Ordering::Relaxed);
            // Persist the restored watermark so a subsequent restart sees it.
            let current = self.last_timestamp.load(Ordering::Relaxed);
            if let Err(e) = self.state_db.set_watermark(current) {
                tracing::error!(error = %e, "reconnect: failed to persist timestamp watermark");
            }
        }

        // 8. Record the accepted checkpoint so it is visible to
        //    `signed_checkpoint_for` and future reconnects.
        self.signed_checkpoints.lock().await.push(checkpoint.clone());

        // 9. Persist to durable storage via the registered sink, if any. The
        //    checkpoint-round state snapshot was already written to the state
        //    database's `snap` keyspace in step 4.
        self.notify_checkpoint_accepted(checkpoint).await;
        true
    }

    /// Phase 4 — accepts inbound connections on the dedicated reconnect port.
    async fn accept_reconnect_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => continue,
            };
            tokio::spawn(self.clone().handle_reconnect_inbound(stream));
        }
    }

    /// Phase 4 — serves one reconnect learner: receives a [`ReconnectRequest`],
    /// selects a checkpoint, and replies with the checkpoint plus the raw
    /// state, roster history, and frontier events. The connection closes
    /// after the single response.
    async fn handle_reconnect_inbound(self: Arc<Self>, stream: TcpStream) {
        let transport = TcpTransport::new(self.identity.clone());
        let acceptor = match transport.acceptor() {
            Ok(acceptor) => acceptor,
            Err(_) => return,
        };
        let tls = match acceptor.accept(stream).await {
            Ok(tls) => tls,
            Err(_) => return,
        };
        let mut transport = TcpTransport::from_tls_stream(self.identity.clone(), tls);

        let frame = match transport.recv_frame().await {
            Ok(frame) => frame,
            Err(_) => return,
        };
        let Frame::Reconnect(_request) = frame else { return };

        // Serve the highest accepted checkpoint, which leaves the learner a
        // replay window (cp_round, decided_round] fully inside this node's
        // retained graph.
        let Some(checkpoint) = self.select_checkpoint_for_learner().await else {
            return;
        };

        // Serve the state exactly as it stood at the checkpoint round, not
        // the live state: the live state has already applied rounds past the
        // checkpoint, so it would not hash to the committed `state_hash` and
        // the learner would replay the retained window a second time. The
        // learner restores this snapshot and replays only the events newer
        // than the checkpoint round.
        let Some(snapshot) = self
            .state_snapshots
            .lock()
            .await
            .range(..=checkpoint.payload.round)
            .next_back()
            .map(|(_, bytes)| bytes.clone())
        else {
            return;
        };

        let (roster_history_bytes, decided_round, retained) = {
            let hg = self.hashgraph.lock().await;
            let roster_history_bytes = consensus::encode_roster_history(hg.roster_history())
                .expect("roster_history bounded");
            let decided_round = hg.highest_decided_round();
            let retained = hg.retained_events();
            (roster_history_bytes, decided_round, retained)
        };
        let last_timestamp = self
            .state_db
            .watermark()
            .ok()
            .flatten()
            .unwrap_or_else(|| self.last_timestamp.load(Ordering::Relaxed));

        let response = ReconnectResponse {
            signed_checkpoint: checkpoint,
            state_bytes: snapshot,
            roster_history_bytes,
            decided_round,
            retained,
            last_timestamp,
        };
        if let Err(e) = transport.send_frame(&Frame::ReconnectResponse(response)).await {
            tracing::warn!(error = %e, "failed to send ReconnectResponse");
            self.gossip_metrics.lock().await.sync_failures += 1;
        }
    }

    /// Phase 4 — the checkpoint a reconnect learner should be served.
    ///
    /// Always the highest accepted checkpoint. Serving anything older is
    /// unsound with snapshot-based state transfer: the learner's replay
    /// window `(cp_round, decided_round]` must be fully inside the teacher's
    /// retained graph, which is only guaranteed for checkpoints at or above
    /// the prune floor (`latest accepted - RETENTION_ROUNDS`). The transferred
    /// retained graph already anchors the learner's frontier completely, so
    /// the old "non-empty incremental sync window" heuristic is unnecessary.
    async fn select_checkpoint_for_learner(&self) -> Option<SignedCheckpoint> {
        self.signed_checkpoints.lock().await.last().cloned()
    }

    /// Runs the node with a dedicated reconnect port: accepts inbound
    /// gossip connections on `gossip_listener` and reconnect requests on
    /// `reconnect_listener`.
    pub async fn run_with_reconnect(
        self: Arc<Self>,
        gossip_listener: TcpListener,
        reconnect_listener: TcpListener,
    ) -> Result<()> {
        let _reconnect_accept =
            tokio::spawn(self.clone().accept_reconnect_loop(reconnect_listener));
        self.run(gossip_listener).await
    }

    /// [`Self::run_until_stopped`] with a dedicated reconnect port.
    pub async fn run_until_stopped_with_reconnect(
        self: Arc<Self>,
        gossip_listener: TcpListener,
        reconnect_listener: TcpListener,
        stop: Arc<AtomicBool>,
    ) -> Result<()> {
        let _reconnect_accept =
            tokio::spawn(self.clone().accept_reconnect_loop(reconnect_listener));
        self.run_until_stopped(gossip_listener, stop).await
    }
}

fn verify_pop_bytes(bls_key: &[u8; 48], pop: &[u8; 96]) -> bool {
    let Ok(pk) = blst::min_pk::PublicKey::from_bytes(bls_key) else {
        return false;
    };
    let Ok(sig) = blst::min_pk::Signature::from_bytes(pop) else {
        return false;
    };
    crypto::bls::verify_pop(&pk, &sig)
}

/// Verifies `sig` over `signing_bytes` against the BLS key registered for
/// `sig.signer` in the roster active at the signature's round. A signature
/// from a member not in that roster is rejected.
fn verify_checkpoint_sig(
    sig: &CheckpointSig,
    signing_bytes: &[u8; 136],
    roster: &MembershipRegistry,
) -> bool {
    let Some(bls_bytes) = roster.bls_key_for(&sig.signer) else {
        return false;
    };
    let Ok(pk) = blst::min_pk::PublicKey::from_bytes(bls_bytes) else {
        return false;
    };
    sig.sig.verify(true, signing_bytes, crypto::bls::CHECKPOINT_DST, &[], &pk, true)
        == blst::BLST_ERROR::BLST_SUCCESS
}

/// Persists an accepted [`SignedCheckpoint`]. Implemented by the embedding
/// application (e.g. the `jkaind` daemon's `storage` module); `GossipNode`
/// only invokes it. The checkpoint-round state snapshot is no longer handed
/// to the sink — it lives in the state database's `snap` keyspace, which the
/// node itself writes in `accept_checkpoint`.
pub trait CheckpointSink {
    /// Called synchronously on the node's async task; implementations must
    /// not block for long.
    fn persist(&self, checkpoint: &SignedCheckpoint);
}

#[cfg(test)]
mod pending_sig_tests {
    use std::sync::Arc;

    use consensus::CheckpointSig;
    use crypto::MembershipRegistry;
    use ed25519_dalek::SigningKey;
    use primitives::NodeId;
    use tempfile::tempdir;

    use super::*;

    fn registry_with(nodes: &[u64]) -> (MembershipRegistry, Vec<SigningKey>) {
        let mut registry = MembershipRegistry::new();
        let mut keys = Vec::new();
        for &id in nodes {
            let k = SigningKey::from_bytes(&[id as u8; 32]);
            let bls = crypto::BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls");
            registry.register(NodeId::new(id), k.verifying_key(), bls.public.to_bytes());
            keys.push(k);
        }
        (registry, keys)
    }

    async fn make_node(registry: MembershipRegistry) -> Arc<GossipNode> {
        let dir = tempdir().expect("tempdir");
        let db = Arc::new(state::StateDb::open(dir.path()).expect("StateDb"));
        let identity = TlsIdentity::from_seed([9u8; 32], 1).expect("tls");
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let node = GossipNode::new(
            NodeId::new(1),
            signing_key,
            registry,
            identity,
            Vec::new(),
            SyncTiming::new(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_secs(1),
            ),
            db,
        );
        Arc::new(node)
    }

    fn sig(round: u64, signer: u64) -> CheckpointSig {
        let bls = crypto::BlsIdentity::from_ikm(&[signer as u8; 32]).expect("bls");
        // Dummy payload for signing not validated in pending tests; sign a fixed message.
        let dummy = [0u8; 136];
        CheckpointSig { round, signer: NodeId::new(signer), sig: bls.sign(&dummy) }
    }

    #[tokio::test]
    async fn pending_dedups_per_round_signer() {
        let (registry, _) = registry_with(&[1, 2, 3]);
        let node = make_node(registry).await;
        node.submit_checkpoint_sig(sig(5, 2)).await;
        node.submit_checkpoint_sig(sig(5, 2)).await;
        let pending = node.pending_checkpoint_sigs.lock().await;
        assert_eq!(pending.get(&5).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn pending_caps_per_round_queue() {
        let (registry2, _) = registry_with(&(1..80).collect::<Vec<_>>());
        let node2 = make_node(registry2).await;
        for i in 1..=(MAX_PENDING_SIGS_PER_ROUND as u64) {
            node2.submit_checkpoint_sig(sig(9, i)).await;
        }
        let before =
            node2.pending_checkpoint_sigs.lock().await.get(&9).map(|v| v.len()).unwrap_or(0);
        assert_eq!(before, MAX_PENDING_SIGS_PER_ROUND);
        node2.submit_checkpoint_sig(sig(9, 70)).await;
        let after =
            node2.pending_checkpoint_sigs.lock().await.get(&9).map(|v| v.len()).unwrap_or(0);
        assert_eq!(after, MAX_PENDING_SIGS_PER_ROUND, "cap must hold");
    }

    #[tokio::test]
    async fn pending_drops_round_at_or_below_watermark() {
        let (registry, _) = registry_with(&[1, 2, 3]);
        let node = make_node(registry.clone()).await;
        let payload = consensus::CheckpointPayload::new(10, [0u8; 32], [0u8; 32], registry);
        let agg = {
            let bls = crypto::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls");
            bls.sign(&payload.signing_bytes())
        };
        node.signed_checkpoints.lock().await.push(consensus::SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1)],
        });
        node.submit_checkpoint_sig(sig(10, 2)).await;
        node.submit_checkpoint_sig(sig(9, 2)).await;
        node.submit_checkpoint_sig(sig(11, 2)).await;
        let pending = node.pending_checkpoint_sigs.lock().await;
        assert!(!pending.contains_key(&10), "round == watermark dropped");
        assert!(!pending.contains_key(&9), "round < watermark dropped");
        assert_eq!(pending.get(&11).map(|v| v.len()), Some(1));
    }

    #[tokio::test]
    async fn outbound_and_pending_purged_on_accept() {
        let (registry, _) = registry_with(&[1, 2, 3, 4]);
        let node = make_node(registry).await;
        node.outbound_checkpoint_sigs.lock().await.push(sig(3, 1));
        node.outbound_checkpoint_sigs.lock().await.push(sig(5, 1));
        node.pending_checkpoint_sigs.lock().await.insert(3, vec![sig(3, 2)]);
        node.pending_checkpoint_sigs.lock().await.insert(5, vec![sig(5, 2)]);
        node.hashgraph.lock().await.mark_decided_through(5);
        let snapshot = node.executor.lock().await.state().to_bytes();
        let state_hash = state::State::root_of_bytes(&snapshot).expect("empty state hashes");
        let payload = consensus::CheckpointPayload::new(
            5,
            [0u8; 32],
            state_hash,
            node.registry.lock().await.clone(),
        );
        let agg = {
            let bls = crypto::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls");
            bls.sign(&payload.signing_bytes())
        };
        let accepted = consensus::SignedCheckpoint {
            payload,
            aggregate_sig: agg,
            signers: vec![NodeId::new(1)],
        };
        node.accept_checkpoint(accepted, snapshot, Vec::new()).await;
        assert!(
            node.state_snapshots.lock().await.contains_key(&5),
            "accepted round must be recorded for reconnect serving"
        );
        let outbound = node.outbound_checkpoint_sigs.lock().await;
        assert!(outbound.iter().all(|s| s.round > 5), "outbound retained only > accepted round");
        let pending = node.pending_checkpoint_sigs.lock().await;
        assert!(!pending.contains_key(&3));
        assert!(!pending.contains_key(&5));
    }
}

#[cfg(test)]
mod rule1_chain_tests {
    use std::collections::BTreeMap;

    use crypto::MembershipRegistry;
    use ed25519_dalek::SigningKey;
    use primitives::NodeId;

    use super::*;

    fn registry_with(nodes: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in nodes {
            let k = SigningKey::from_bytes(&[id as u8; 32]);
            let bls = crypto::BlsIdentity::from_ikm(&[id as u8; 32]).expect("bls");
            registry.register(NodeId::new(id), k.verifying_key(), bls.public.to_bytes());
        }
        registry
    }

    #[tokio::test]
    async fn chained_payload_identical_despite_acceptance_lag() {
        let registry = registry_with(&[1, 2, 3, 4]);
        let hg = {
            let mut hg = consensus::Hashgraph::new(&registry);
            hg.mark_decided_through(2);
            hg
        };
        let mut state_hashes = BTreeMap::new();
        state_hashes.insert(0, [0xAA; 32]);
        state_hashes.insert(1, [0x11; 32]);
        state_hashes.insert(2, [0x22; 32]);

        let payload_via_rebuild =
            GossipNode::canonical_checkpoint_payload_chained(&hg, 2, &state_hashes, &[])
                .expect("round 2 decided");

        let payload_round1 =
            GossipNode::canonical_checkpoint_payload_chained(&hg, 1, &state_hashes, &[])
                .expect("round 1 decided");
        let sig = {
            let bls = crypto::BlsIdentity::from_ikm(&[1u8; 32]).expect("bls");
            bls.sign(&payload_round1.signing_bytes())
        };
        let stored = consensus::SignedCheckpoint {
            payload: payload_round1.clone(),
            aggregate_sig: sig,
            signers: vec![NodeId::new(1)],
        };
        let payload_via_stored = GossipNode::canonical_checkpoint_payload_chained(
            &hg,
            2,
            &state_hashes,
            std::slice::from_ref(&stored),
        )
        .expect("round 2 via stored");

        assert_eq!(
            payload_via_rebuild.signing_bytes(),
            payload_via_stored.signing_bytes(),
            "lagging node (rebuild) and accepted node (stored) must sign identical bytes"
        );
        assert_eq!(
            payload_via_rebuild.prev_checkpoint_hash,
            payload_round1.signing_bytes_hash(),
            "prev must be hash of round 1"
        );
    }

    #[tokio::test]
    async fn genesis_prev_is_zeros_and_chain_is_pure() {
        let registry = registry_with(&[1, 2, 3, 4]);
        let mut hg = consensus::Hashgraph::new(&registry);
        hg.mark_decided_through(1);
        let mut state_hashes = BTreeMap::new();
        state_hashes.insert(0, [0xAA; 32]);
        state_hashes.insert(1, [0x11; 32]);

        let p1 = GossipNode::canonical_checkpoint_payload_chained(&hg, 1, &state_hashes, &[])
            .expect("round 1");
        assert_eq!(p1.prev_checkpoint_hash, [0u8; 32]);

        hg.mark_decided_through(2);
        state_hashes.insert(2, [0x22; 32]);
        let p2 = GossipNode::canonical_checkpoint_payload_chained(&hg, 2, &state_hashes, &[])
            .expect("round 2");
        assert_eq!(p2.prev_checkpoint_hash, p1.signing_bytes_hash());
    }

    #[tokio::test]
    async fn chained_payload_deterministic_across_pass_groupings() {
        let registry = registry_with(&[1, 2, 3, 4]);
        let mut hg = consensus::Hashgraph::new(&registry);
        hg.mark_decided_through(3);
        let mut cumulative = BTreeMap::new();
        cumulative.insert(0, [0xAA; 32]);
        cumulative.insert(1, [0x11; 32]);
        cumulative.insert(2, [0x22; 32]);
        cumulative.insert(3, [0x33; 32]);

        let payload3_cumulative =
            GossipNode::canonical_checkpoint_payload_chained(&hg, 3, &cumulative, &[])
                .expect("round 3 via cumulative");

        let mut map_a = BTreeMap::new();
        map_a.insert(0, [0x22; 32]);
        map_a.insert(3, [0x33; 32]);
        let payload3_a = GossipNode::canonical_checkpoint_payload_chained(&hg, 3, &map_a, &[])
            .expect("round 3 via map_a");

        let mut map_b = BTreeMap::new();
        map_b.insert(0, [0x11; 32]);
        map_b.insert(2, [0x22; 32]);
        map_b.insert(3, [0x33; 32]);
        let payload3_b = GossipNode::canonical_checkpoint_payload_chained(&hg, 3, &map_b, &[])
            .expect("round 3 via map_b");

        assert_ne!(
            payload3_a.signing_bytes(),
            payload3_b.signing_bytes(),
            "per-pass maps with different floors must diverge (the bug)"
        );

        let payload2 = GossipNode::canonical_checkpoint_payload_chained(&hg, 2, &cumulative, &[])
            .expect("round 2");
        let payload1 = GossipNode::canonical_checkpoint_payload_chained(&hg, 1, &cumulative, &[])
            .expect("round 1");
        assert_eq!(payload2.prev_checkpoint_hash, payload1.signing_bytes_hash());
        assert_eq!(payload3_cumulative.prev_checkpoint_hash, payload2.signing_bytes_hash());
        assert_ne!(payload3_a.prev_checkpoint_hash, payload2.signing_bytes_hash());
    }
}
