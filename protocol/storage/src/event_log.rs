//! The Fjall-backed append-only event log (Phase 8, point 1).
//!
//! Every verified event is appended on insert, keyed by `EventHash`, in a
//! two-partition layout inside one Fjall `Database`:
//!
//! - `by_seq`: a monotonically increasing `u64` BE key -> encoded
//!   [`consensus::RetainedEvent`]. The key is the log's own global insertion
//!   counter (not the event's per-creator sequence number), so the partition
//!   preserves insertion order — which is topological order — for replay.
//! - `by_hash`: `EventHash` -> the same encoded record, for dedup, lookup,
//!   and pruning.
//!
//! plus a `roster` keyspace holding the persisted roster history, so a
//! restart can verify each replayed event against the roster active at its
//! birth round.
//!
//! The log is decoupled from the checkpoint (`.cp`) files: the
//! checkpoint commits state and roster at a round; the log carries the
//! complete retained event set since the prune floor.

use std::path::Path;
use std::sync::Mutex;
use std::sync::atomic::{
    AtomicU64,
    Ordering,
};

use consensus::{
    RetainedEvent,
    decode_retained_event,
    encode_retained_event,
};
use crypto::Hashable;
use fjall::{
    Database,
    Keyspace,
    KeyspaceCreateOptions,
    PersistMode,
};
use primitives::EventHash;

use crate::Result;
use crate::error::EventLogError;

/// Subdirectory (under the data dir) holding the Fjall event log database.
pub const EVENT_LOG_SUBDIR: &str = "eventlog";

const BY_SEQ: &str = "by_seq";
const BY_HASH: &str = "by_hash";
const ROSTER: &str = "roster";
const ROSTER_HISTORY_KEY: &[u8] = b"history";

/// The durable, replayable event store of a consensus node.
///
/// All writes are serialized through an internal `Mutex` (appends, ordering
/// updates, pruning) so the `by_seq` counter and the two-keyspace updates
/// stay atomic with respect to one another. Reads (replay, contains) are
/// lock-free.
pub struct EventLog {
    db: Database,
    by_seq: Keyspace,
    by_hash: Keyspace,
    roster: Keyspace,
    next_seq: AtomicU64,
    write_lock: Mutex<()>,
}

impl EventLog {
    /// Opens (creating if needed) the event log database under `data_dir`.
    pub fn open(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join(EVENT_LOG_SUBDIR);
        let db = Database::builder(&dir).open()?;
        let by_seq = db.keyspace(BY_SEQ, KeyspaceCreateOptions::default)?;
        let by_hash = db.keyspace(BY_HASH, KeyspaceCreateOptions::default)?;
        let roster = db.keyspace(ROSTER, KeyspaceCreateOptions::default)?;
        let next_seq = Self::recover_next_seq(&by_seq)?;
        Ok(Self {
            db,
            by_seq,
            by_hash,
            roster,
            next_seq: AtomicU64::new(next_seq),
            write_lock: Mutex::new(()),
        })
    }

    /// The next `by_seq` key: one past the highest persisted key, so appends
    /// after a reopen never collide with previously written records.
    fn recover_next_seq(by_seq: &Keyspace) -> Result<u64> {
        let Some(guard) = by_seq.last_key_value() else {
            return Ok(0);
        };
        let key = guard.key()?;
        let bytes: &[u8] = &key;
        let last = u64::from_be_bytes(
            bytes
                .get(..8)
                .ok_or_else(|| EventLogError::Corrupt("by_seq key too short".into()))?
                .try_into()
                .map_err(|_| EventLogError::Corrupt("by_seq key not u64 BE".into()))?,
        );
        Ok(last + 1)
    }

    /// Appends `record` to the log. Idempotent by `EventHash`: a second
    /// append of an already-stored event is a no-op (except that a
    /// newly-known `round_received` is merged in, covering the case where a
    /// reconnect teacher's retained event was ordered after the learner's own
    /// append). Returns `true` when a new record was appended.
    pub fn append(&self, record: &RetainedEvent) -> Result<bool> {
        let hash = record.event.hash();
        let _guard = self.write_lock.lock().map_err(|_| EventLogError::Poisoned)?;
        if let Some(existing) = self.by_hash.get(hash.as_bytes().as_slice())? {
            let (log_seq, mut stored) = decode_value(&existing)
                .ok_or_else(|| EventLogError::Corrupt("stored record undecodable".into()))?;
            if stored.round_received.is_none() && record.round_received.is_some() {
                stored.round_received = record.round_received;
                self.write_both(log_seq, hash.as_bytes().as_slice(), &stored)?;
            }
            return Ok(false);
        }
        let log_seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        self.write_both(log_seq, hash.as_bytes().as_slice(), record)?;
        Ok(true)
    }

    /// Records the finalized `round_received` of an already-logged event. A
    /// no-op when the event is not in the log (it may predate logging) or its
    /// ordering is already recorded.
    pub fn set_round_received(&self, hash: &EventHash, round_received: u64) -> Result<()> {
        let _guard = self.write_lock.lock().map_err(|_| EventLogError::Poisoned)?;
        let Some(existing) = self.by_hash.get(hash.as_bytes().as_slice())? else {
            return Ok(());
        };
        let (log_seq, mut stored) = decode_value(&existing)
            .ok_or_else(|| EventLogError::Corrupt("stored record undecodable".into()))?;
        if stored.round_received == Some(round_received) {
            return Ok(());
        }
        stored.round_received = Some(round_received);
        self.write_both(log_seq, hash.as_bytes().as_slice(), &stored)
    }

    /// Replays the complete logged event set in insertion (topological)
    /// order. The caller is responsible for signature-verifying each record
    /// before inserting it into a graph.
    pub fn replay(&self) -> Result<Vec<RetainedEvent>> {
        let mut records = Vec::new();
        for guard in self.by_seq.iter() {
            let (_, value) = guard.into_inner()?;
            let (_, record) = decode_value(&value)
                .ok_or_else(|| EventLogError::Corrupt("stored record undecodable".into()))?;
            records.push(record);
        }
        Ok(records)
    }

    /// Whether `hash` is present in the log.
    pub fn contains(&self, hash: &EventHash) -> Result<bool> {
        Ok(self.by_hash.get(hash.as_bytes().as_slice())?.is_some())
    }

    /// The number of logged events.
    pub fn event_count(&self) -> Result<usize> {
        Ok(self.by_seq.len()?)
    }

    /// Removes every record whose hash is in `hashes` from both keyspaces.
    /// Unknown hashes are skipped (a record may predate logging).
    pub fn prune(&self, hashes: &[EventHash]) -> Result<()> {
        if hashes.is_empty() {
            return Ok(());
        }
        let _guard = self.write_lock.lock().map_err(|_| EventLogError::Poisoned)?;
        let mut batch = self.db.batch();
        for hash in hashes {
            let Some(existing) = self.by_hash.get(hash.as_bytes().as_slice())? else {
                continue;
            };
            let (log_seq, _) = decode_value(&existing)
                .ok_or_else(|| EventLogError::Corrupt("stored record undecodable".into()))?;
            batch.remove(&self.by_seq, log_seq.to_be_bytes());
            batch.remove(&self.by_hash, hash.as_bytes().as_slice());
        }
        if !batch.is_empty() {
            batch.commit()?;
        }
        Ok(())
    }

    /// The persisted roster history (encoded via `consensus::encode_roster_history`),
    /// if one has been written.
    pub fn roster_history(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.roster.get(ROSTER_HISTORY_KEY)?.map(|value| value.to_vec()))
    }

    /// Persists the roster history. Idempotent; overwrites the previous
    /// snapshot (roster history only grows with membership changes).
    pub fn set_roster_history(&self, bytes: &[u8]) -> Result<()> {
        self.roster.insert(ROSTER_HISTORY_KEY, bytes)?;
        Ok(())
    }

    /// Flushes the journal to disk, making all previously appended records
    /// durable against power loss. Without it, the log is still crash-safe
    /// (consistent after a crash), but recent writes may not survive a
    /// power cut.
    pub fn flush(&self) -> Result<()> {
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// Writes `record` under both `log_seq` (in `by_seq`) and `hash` (in
    /// `by_hash`) atomically.
    fn write_both(&self, log_seq: u64, hash: &[u8], record: &RetainedEvent) -> Result<()> {
        let value = encode_value(log_seq, record);
        let mut batch = self.db.batch();
        batch.insert(&self.by_seq, log_seq.to_be_bytes(), value.as_slice());
        batch.insert(&self.by_hash, hash, value.as_slice());
        batch.commit()?;
        Ok(())
    }
}

/// The durable-event-store interface the gossip layer and daemon drive.
///
/// Each method is a lossy wrapper over the fallible [`EventLog`] operation
/// (errors are logged and dropped), mirroring the node's checkpoint-sink
/// pattern so the consensus-hot path never fails on storage hiccups.
pub trait EventSink: Send + Sync {
    /// Appends a freshly inserted event (with its record metadata) to the
    /// log.
    fn append(&self, record: &RetainedEvent);
    /// Records that `hash`'s `roundReceived` is `round_received`.
    fn set_round_received(&self, hash: &EventHash, round_received: u64);
    /// Persists the encoded roster history.
    fn set_roster_history(&self, bytes: &[u8]);
    /// Removes the given events from the log, mirroring an in-memory prune.
    fn prune(&self, hashes: &[EventHash]);
    /// Flushes pending writes to disk.
    fn flush(&self);
}

impl EventSink for EventLog {
    fn append(&self, record: &RetainedEvent) {
        if let Err(e) = EventLog::append(self, record) {
            eprintln!("[event-log] failed to append event: {e}");
        }
    }

    fn set_round_received(&self, hash: &EventHash, round_received: u64) {
        if let Err(e) = EventLog::set_round_received(self, hash, round_received) {
            eprintln!("[event-log] failed to record round_received: {e}");
        }
    }

    fn set_roster_history(&self, bytes: &[u8]) {
        if let Err(e) = EventLog::set_roster_history(self, bytes) {
            eprintln!("[event-log] failed to persist roster history: {e}");
        }
    }

    fn prune(&self, hashes: &[EventHash]) {
        if let Err(e) = EventLog::prune(self, hashes) {
            eprintln!("[event-log] failed to prune: {e}");
        }
    }

    fn flush(&self) {
        if let Err(e) = EventLog::flush(self) {
            eprintln!("[event-log] failed to flush: {e}");
        }
    }
}

/// The stored value in both keyspaces: `[log_seq: u64 BE] || [encoded
/// RetainedEvent]`. The leading `log_seq` lets a `by_hash` lookup locate the
/// corresponding `by_seq` record for pruning.
fn encode_value(log_seq: u64, record: &RetainedEvent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + 64);
    buf.extend_from_slice(&log_seq.to_be_bytes());
    buf.extend_from_slice(&encode_retained_event(record));
    buf
}

fn decode_value(bytes: &[u8]) -> Option<(u64, RetainedEvent)> {
    if bytes.len() < 8 {
        return None;
    }
    let log_seq = u64::from_be_bytes(bytes[..8].try_into().ok()?);
    let record = decode_retained_event(&bytes[8..])?;
    Some((log_seq, record))
}

#[cfg(test)]
mod tests {
    use consensus::RetainedEvent;
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        UnsignedEvent,
    };
    use tempfile::tempdir;

    use super::*;

    fn sample_record(creator: u64, seq: u64, round: u64) -> RetainedEvent {
        let event =
            UnsignedEvent::new(NodeId::new(creator), None, None, Timestamp::new(seq), Vec::new())
                .finalize(Signature::new([seq as u8; 64]));
        RetainedEvent { event, seq, round, ancestor_seqs: vec![seq], round_received: None }
    }

    fn record_hash(record: &RetainedEvent) -> EventHash {
        record.event.hash()
    }

    #[test]
    fn append_replays_in_insertion_order() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let records: Vec<RetainedEvent> = (1..=3).map(|i| sample_record(i, i, 1)).collect();
        for record in &records {
            assert!(log.append(record).expect("appends"), "fresh append");
        }
        let replayed = log.replay().expect("replays");
        assert_eq!(replayed, records);
    }

    #[test]
    fn append_is_idempotent_by_hash() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let record = sample_record(1, 1, 1);
        assert!(log.append(&record).expect("first append"));
        assert!(!log.append(&record).expect("duplicate append"));
        assert!(!log.append(&record).expect("triplicate append"));
        assert_eq!(log.event_count().expect("count"), 1);
        assert_eq!(log.replay().expect("replays"), vec![record]);
    }

    #[test]
    fn set_round_received_merges_ordering() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let record = sample_record(1, 1, 1);
        let hash = record_hash(&record);
        log.append(&record).expect("append");
        log.set_round_received(&hash, 5).expect("set order");

        let replayed = log.replay().expect("replays");
        assert_eq!(replayed.len(), 1);
        assert_eq!(replayed[0].round_received, Some(5));
    }

    #[test]
    fn append_merges_incoming_round_received() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let mut record = sample_record(1, 1, 1);
        log.append(&record).expect("append");
        // A reconnect teacher delivers the same event, already ordered.
        record.round_received = Some(4);
        assert!(!log.append(&record).expect("dedup append"));
        let replayed = log.replay().expect("replays");
        assert_eq!(replayed[0].round_received, Some(4));
    }

    #[test]
    fn prune_removes_exactly_the_given_hashes() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let a = sample_record(1, 1, 1);
        let b = sample_record(2, 2, 1);
        let c = sample_record(3, 3, 1);
        for record in [&a, &b, &c] {
            log.append(record).expect("append");
        }
        log.prune(&[record_hash(&a), record_hash(&c)]).expect("prune");
        let replayed = log.replay().expect("replays");
        assert_eq!(replayed, vec![b]);
        assert!(!log.contains(&record_hash(&a)).expect("a pruned"));
    }

    #[test]
    fn prune_skips_unknown_hashes() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        let a = sample_record(1, 1, 1);
        log.append(&a).expect("append");
        log.prune(&[EventHash::new([0xAB; 32])]).expect("prune unknown");
        assert_eq!(log.event_count().expect("count"), 1);
    }

    #[test]
    fn roster_history_round_trips() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        assert!(log.roster_history().expect("empty history").is_none());
        log.set_roster_history(b"roster-history").expect("write");
        assert_eq!(log.roster_history().expect("read"), Some(b"roster-history".to_vec()));
    }

    #[test]
    fn reopen_continues_the_sequence() {
        let dir = tempdir().expect("temp dir");
        let first = EventLog::open(dir.path()).expect("opens");
        first.append(&sample_record(1, 1, 1)).expect("append");
        first.append(&sample_record(2, 2, 1)).expect("append");
        drop(first);

        let second = EventLog::open(dir.path()).expect("reopens");
        second.append(&sample_record(3, 3, 1)).expect("append");
        let replayed = second.replay().expect("replays");
        assert_eq!(replayed.len(), 3);
        let hashes: Vec<EventHash> = replayed.iter().map(record_hash).collect();
        assert_eq!(hashes.len(), 3);
        let unique: std::collections::HashSet<EventHash> = hashes.into_iter().collect();
        assert_eq!(unique.len(), 3, "reopened log must not collide log seq keys");
    }

    #[test]
    fn flush_survives_reopen() {
        let dir = tempdir().expect("temp dir");
        let log = EventLog::open(dir.path()).expect("opens");
        log.append(&sample_record(7, 7, 1)).expect("append");
        log.flush().expect("flush");
        drop(log);

        let reopened = EventLog::open(dir.path()).expect("reopens");
        assert_eq!(reopened.event_count().expect("count"), 1);
    }
}
