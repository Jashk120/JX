use std::collections::hash_map::Entry;
use std::collections::{
    BTreeMap,
    HashMap,
};
use std::sync::Arc;
use std::sync::atomic::{
    AtomicBool,
    Ordering,
};
use std::time::Duration;

use consensus::{
    CheckpointAccumulator,
    CheckpointSig,
    RETENTION_ROUNDS,
    SignedCheckpoint,
};
use crypto::{
    Hashable,
    MembershipOp,
    MembershipRegistry,
};
use ed25519_dalek::{
    Signer,
    SigningKey,
    VerifyingKey,
};
use primitives::{
    Event,
    NodeId,
};
use sha2::{
    Digest,
    Sha256,
};
use tokio::net::{
    TcpListener,
    TcpStream,
};
use tokio::sync::Mutex;

use crate::error::{
    GossipError,
    Result,
};
use crate::frontier::delta_events;
use crate::peer::PeerInfo;
use crate::peer_manager::PeerManager;
use crate::proto::{
    Frame,
    SyncResponse,
};
use crate::sync::{
    insert_verified,
    run_sync,
};
use crate::tls::TlsIdentity;
use crate::transport::{
    SyncTransport,
    TcpTransport,
};

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

/// A JKain node: owns a hashgraph, a TLS identity, the known-peer table,
/// and the async machinery that runs gossip syncs on a fixed interval.
pub struct GossipNode {
    pub node_id: NodeId,
    pub hashgraph: Arc<Mutex<consensus::Hashgraph>>,
    signing_key: SigningKey,
    registry: Mutex<MembershipRegistry>,
    identity: TlsIdentity,
    peers: Mutex<PeerManager>,
    sync_interval: Duration,
    sync_timeout: Duration,
    executor: Mutex<state::Executor>,
    activation: Mutex<ActivationState>,
    /// One in-flight [`CheckpointAccumulator`] per round whose checkpoint
    /// this node has produced but not yet accepted. Removed on acceptance.
    checkpoint_accumulators: Mutex<HashMap<u64, CheckpointAccumulator>>,
    /// Accepted checkpoints, ascending by round.
    signed_checkpoints: Mutex<Vec<SignedCheckpoint>>,
    /// This node's own signatures, gossiped after every successful sync round.
    outbound_checkpoint_sigs: Mutex<Vec<CheckpointSig>>,
    /// Inbound signatures for rounds this node has not produced a checkpoint
    /// for yet (they arrive ahead of the events that decide the round).
    pending_checkpoint_sigs: Mutex<BTreeMap<u64, Vec<CheckpointSig>>>,
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
        sync_interval: Duration,
        sync_timeout: Duration,
    ) -> Self {
        let peers: Vec<PeerInfo> =
            peers.into_iter().filter(|peer| peer.node_id != node_id).collect();
        let hashgraph = consensus::Hashgraph::new(&registry);
        Self {
            node_id,
            hashgraph: Arc::new(Mutex::new(hashgraph)),
            signing_key,
            registry: Mutex::new(registry),
            identity,
            peers: Mutex::new(PeerManager::new(peers)),
            sync_interval,
            sync_timeout,
            executor: Mutex::new(state::Executor::new()),
            activation: Mutex::new(ActivationState::default()),
            checkpoint_accumulators: Mutex::new(HashMap::new()),
            signed_checkpoints: Mutex::new(Vec::new()),
            outbound_checkpoint_sigs: Mutex::new(Vec::new()),
            pending_checkpoint_sigs: Mutex::new(BTreeMap::new()),
        }
    }

    /// Whether `node` is a registered member of this node's hashgraph.
    pub async fn is_consensus_member(&self, node: NodeId) -> bool {
        let hg = self.hashgraph.lock().await;
        hg.is_member(&node)
    }

    /// The number of known peers (observability helper).
    pub async fn peer_count(&self) -> usize {
        self.peers.lock().await.len()
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

        let mut outbound: HashMap<NodeId, TcpTransport> = HashMap::new();
        loop {
            if stop.load(Ordering::Acquire) {
                break;
            }
            tokio::time::sleep(self.sync_interval).await;
            if stop.load(Ordering::Acquire) {
                break;
            }

            let peer = self.peers.lock().await.random_peer();
            let Some(peer) = peer else { continue };

            let transport = match outbound.entry(peer.node_id) {
                Entry::Occupied(entry) => entry.into_mut(),
                Entry::Vacant(entry) => {
                    let mut transport = TcpTransport::new(self.identity.clone());
                    if transport.connect(&peer).await.is_err() {
                        continue;
                    }
                    entry.insert(transport)
                }
            };

            let registry = self.registry.lock().await.clone();
            let round = tokio::time::timeout(
                self.sync_timeout,
                run_sync(
                    transport,
                    &self.hashgraph,
                    &registry,
                    self.node_id,
                    &self.signing_key,
                    peer.node_id,
                ),
            )
            .await;

            let round = match round {
                Ok(result) => result,
                Err(_) => Err(GossipError::Sync(format!(
                    "sync round with peer {peer:?} timed out after {:?}",
                    self.sync_timeout
                ))),
            };

            if round.is_err() {
                outbound.remove(&peer.node_id);
            } else {
                // Piggyback any pending checkpoint signatures on this sync
                // round (Phase 3). Sigs are re-sent on every successful sync
                // until the round's checkpoint is accepted — the peer that
                // needs one the most is exactly the one that fell behind.
                self.gossip_checkpoint_sigs(transport).await;
            }

            // Decode newly finalized events, drive any membership
            // activations, and emit checkpoints for newly decided rounds.
            self.process_finalized_rounds().await;
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
                    let hash = event.hash();
                    hg.round_received(&hash).map(|rr| (event, rr))
                })
                .collect()
        };

        if !finalized.is_empty() {
            // Phase B: execute finalized events one round at a time,
            // capturing the deterministic state hash after each round's
            // events. Hashing per round — rather than hashing the state once
            // at the end of the batch — is what makes every node compute the
            // *identical* state hash for a given round's checkpoint
            // regardless of how many later rounds landed in the same batch;
            // without it, two nodes producing a checkpoint for the same round
            // at different finalization points would sign different bytes and
            // their signatures would never verify against each other.
            let state_hashes = {
                let pre_batch_hash: [u8; 32] = {
                    let executor = self.executor.lock().await;
                    Sha256::digest(executor.state().to_bytes()).into()
                };
                let mut activation = self.activation.lock().await;
                let mut executor = self.executor.lock().await;
                let mut by_round: BTreeMap<u64, Vec<(Event, u64)>> = BTreeMap::new();
                for pair in &finalized {
                    by_round.entry(pair.1).or_default().push(pair.clone());
                }
                // Round 0 never exists as an event round; it is the sentinel
                // holding the state hash before this batch, which is the
                // correct value for any decided round that ordered no events.
                let mut hashes: BTreeMap<u64, [u8; 32]> = BTreeMap::new();
                hashes.insert(0, pre_batch_hash);
                let ActivationState { pending, processed_through_round, .. } = &mut *activation;
                for (round, events) in by_round {
                    if round <= *processed_through_round {
                        continue;
                    }
                    executor.bucket_finalized(pending, processed_through_round, &events);
                    hashes.insert(round, Sha256::digest(executor.state().to_bytes()).into());
                }
                hashes
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
                    if let MembershipOp::Add { node, key, addr } = op {
                        let already_member = {
                            let hg = self.hashgraph.lock().await;
                            hg.is_member(&node)
                        };
                        if already_member {
                            continue;
                        }

                        let key: VerifyingKey = *key;
                        // Build the post-join registry from the roster active at
                        // the activation round (which still excludes the new node).
                        let mut new_registry = {
                            let hg = self.hashgraph.lock().await;
                            hg.registry_at_round(activation_round)
                        };
                        new_registry.register(node, key);

                        // Atomic: structural growth + roster schedule in one call.
                        {
                            let mut hg = self.hashgraph.lock().await;
                            hg.add_member(node, activation_round, new_registry);
                        }

                        // Keep the event-verification registry in sync so the new
                        // node's events can be verified and inserted.
                        {
                            let mut registry = self.registry.lock().await;
                            registry.register(node, key);
                        }

                        // TLS-pin the new peer, deriving the fingerprint from its
                        // Ed25519 key (same derivation as boot-time peers).
                        {
                            let mut pm = self.peers.lock().await;
                            pm.add_peer_from_key(node, &key, addr);
                        }
                    }
                }
            }

            // Phase D: produce checkpoints for every round decided since the
            // last pass, using the per-round state hashes captured above.
            self.produce_pending_checkpoints(&state_hashes).await;
        } else {
            // No newly finalized events: no rounds were newly ordered, but a
            // round may still have just been decided. The empty hash map's
            // round-0 sentinel falls back to the current (unchanged) state.
            let state_hashes = BTreeMap::from([(0, {
                let executor = self.executor.lock().await;
                Sha256::digest(executor.state().to_bytes()).into()
            })]);
            self.produce_pending_checkpoints(&state_hashes).await;
        }
    }

    /// Emits a checkpoint for every round decided since the last pass, in
    /// ascending order. A round is decided when all its witnesses have a
    /// final fame decision (`is_round_decided`), which is exactly the point
    /// at which its ordering can no longer change.
    async fn produce_pending_checkpoints(&self, state_hashes: &BTreeMap<u64, [u8; 32]>) {
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
            self.produce_checkpoint(round, state_hashes).await;
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
    async fn produce_checkpoint(&self, round: u64, state_hashes: &BTreeMap<u64, [u8; 32]>) {
        let state_hash = *state_hashes
            .range(..=round)
            .next_back()
            .map(|(_, hash)| hash)
            .expect("the round-0 sentinel always present");
        let payload = {
            let hg = self.hashgraph.lock().await;
            hg.checkpoint_payload(round, state_hash)
        };
        let Some(payload) = payload else { return };

        let signature = self.signing_key.sign(&payload.signing_bytes());
        let own_sig = CheckpointSig {
            round,
            signer: self.node_id,
            sig: primitives::Signature::new(signature.to_bytes()),
        };
        self.outbound_checkpoint_sigs.lock().await.push(own_sig.clone());

        let roster = {
            let hg = self.hashgraph.lock().await;
            hg.registry_at_round(round)
        };

        let pending = {
            let mut pending = self.pending_checkpoint_sigs.lock().await;
            pending.remove(&round).unwrap_or_default()
        };

        let accepted = {
            let mut accumulators = self.checkpoint_accumulators.lock().await;
            let accumulator =
                accumulators.entry(round).or_insert_with(|| CheckpointAccumulator::new(payload));
            let mut accepted = accumulator.add_sig(own_sig, &roster);
            for sig in pending {
                if accepted.is_some() {
                    break;
                }
                if verify_checkpoint_sig(&sig, &accumulator.signing_bytes(), &roster) {
                    accepted = accumulator.add_sig(sig, &roster);
                }
            }
            if accepted.is_some() {
                accumulators.remove(&round);
            }
            accepted
        };
        if let Some(accepted) = accepted {
            self.accept_checkpoint(accepted).await;
        }
    }

    /// Feeds an inbound `CheckpointSig` into the accumulator for its round.
    /// The signature is verified against the roster active at that round
    /// before it is counted. If this node has not yet produced its own
    /// checkpoint for the round (so it has no payload to verify against),
    /// the signature is buffered and flushed when `produce_checkpoint` runs.
    async fn feed_checkpoint_sig(&self, sig: CheckpointSig) {
        let signing_bytes = {
            let accumulators = self.checkpoint_accumulators.lock().await;
            accumulators.get(&sig.round).map(CheckpointAccumulator::signing_bytes)
        };
        let Some(signing_bytes) = signing_bytes else {
            self.pending_checkpoint_sigs.lock().await.entry(sig.round).or_default().push(sig);
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
            let accepted = accumulators.get_mut(&round).and_then(|acc| acc.add_sig(sig, &roster));
            if accepted.is_some() {
                accumulators.remove(&round);
            }
            accepted
        };
        if let Some(accepted) = accepted {
            self.accept_checkpoint(accepted).await;
        }
    }

    /// Records an accepted checkpoint and prunes history below it, keeping a
    /// `RETENTION_ROUNDS` margin so a peer that fell behind can still
    /// delta-sync.
    async fn accept_checkpoint(&self, accepted: SignedCheckpoint) {
        let round = accepted.payload.round;
        {
            let mut signed = self.signed_checkpoints.lock().await;
            signed.push(accepted);
            signed.sort_by_key(|c| c.payload.round);
        }
        let prune_before_round = round.saturating_sub(RETENTION_ROUNDS);
        let mut hg = self.hashgraph.lock().await;
        hg.prune_before_round(prune_before_round);
    }

    /// The public inbound entry for a checkpoint signature — mirrors the
    /// `Frame::CheckpointSig` handling in `handle_inbound` so tests can
    /// exercise the same path without a live connection.
    pub async fn submit_checkpoint_sig(&self, sig: CheckpointSig) {
        let decided = {
            let hg = self.hashgraph.lock().await;
            hg.is_round_decided(sig.round)
        };
        if decided {
            self.feed_checkpoint_sig(sig).await;
        } else {
            self.pending_checkpoint_sigs.lock().await.entry(sig.round).or_default().push(sig);
        }
    }

    /// The signing bytes the node's checkpoint for `round` is over, if one
    /// has been produced. Tests use this to craft valid signatures.
    pub async fn checkpoint_signing_bytes(&self, round: u64) -> Option<[u8; 72]> {
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

    /// Sends every pending checkpoint signature on the given transport. Own
    /// signatures are re-sent on each successful sync until the round's
    /// checkpoint is accepted, so a peer that missed one delivery still
    /// accumulates them.
    async fn gossip_checkpoint_sigs(&self, transport: &mut (impl SyncTransport + Send)) {
        let sigs = self.outbound_checkpoint_sigs.lock().await.clone();
        for sig in sigs {
            if transport.send_frame(&Frame::CheckpointSig(sig)).await.is_err() {
                return;
            }
        }
    }

    async fn accept_loop(self: Arc<Self>, listener: TcpListener) {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(accepted) => accepted,
                Err(_) => continue,
            };
            tokio::spawn(self.clone().handle_inbound(stream));
        }
    }

    async fn handle_inbound(self: Arc<Self>, stream: TcpStream) {
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

        loop {
            let frame = match transport.recv_frame().await {
                Ok(frame) => frame,
                Err(_) => return,
            };
            match frame {
                Frame::SyncRequest(request) => {
                    let events = {
                        let hashgraph = self.hashgraph.lock().await;
                        match delta_events(&hashgraph, &request.known) {
                            Ok(events) => events,
                            Err(_) => return,
                        }
                    };
                    let response = Frame::SyncResponse(SyncResponse { events });
                    if transport.send_frame(&response).await.is_err() {
                        return;
                    }
                }
                Frame::Event(event) => {
                    let registry = self.registry.lock().await.clone();
                    if insert_verified(&self.hashgraph, &registry, event).await.is_err() {
                        return;
                    }
                }
                Frame::CheckpointSig(sig) => {
                    self.submit_checkpoint_sig(sig).await;
                }
                Frame::SyncResponse(_) => return,
            }
        }
    }
}

/// Verifies `sig` over `signing_bytes` against the key registered for
/// `sig.signer` in the roster active at the signature's round. A signature
/// from a member not in that roster (e.g. a node that joined later) is
/// rejected.
fn verify_checkpoint_sig(
    sig: &CheckpointSig,
    signing_bytes: &[u8; 72],
    roster: &MembershipRegistry,
) -> bool {
    let Ok(key) = roster.key_for(&sig.signer) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(sig.sig.as_bytes());
    key.verify_strict(signing_bytes, &signature).is_ok()
}
