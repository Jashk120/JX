//! The Fjall-backed KV state database (Phase 8, "Merkle tree state").
//!
//! A separate Fjall database (under `<data>/statedb/`) holding the executor's
//! key-value state in an LSM partition with a write-ahead log, replacing the
//! old `BTreeMap`-backed `State`. Two keyspaces:
//!
//! - `state`: the live key-value state. Every applied `Put`/`Delete` writes
//!   here (WAL), so a crash never loses the last applied operations beyond
//!   what the next accepted checkpoint snapshot re-establishes.
//! - `snap`: per-accepted-checkpoint-round snapshots (`State::to_bytes()`),
//!   keyed by round. This is the durable source a restart uses to restore,
//!   verify, and serve the exact state at the checkpoint round — it replaces
//!   the old per-round `.snap` files.
//!
//! The `state` keyspace holds the *live* state, which runs ahead of the last
//! accepted checkpoint. The `snap` keyspace holds the state *at* each accepted
//! round, which is what the signed checkpoint commits to; verification on
//! restart therefore reads from `snap`, never from the live partition.

use std::path::Path;
use std::sync::Arc;

use fjall::{
    Database,
    Keyspace,
    KeyspaceCreateOptions,
    PersistMode,
};

use crate::error::StateDbResult;

/// Subdirectory (under the data dir) holding the Fjall state database.
pub const STATE_DB_SUBDIR: &str = "statedb";

const STATE: &str = "state";
const SNAP: &str = "snap";
const META: &str = "meta";
const WATERMARK_KEY: &[u8] = b"last_timestamp";

/// The durable KV state of a consensus node.
pub struct StateDb {
    db: Database,
    state: Keyspace,
    snap: Keyspace,
    meta: Keyspace,
}

impl StateDb {
    /// Opens (creating if needed) the state database under `data_dir`.
    pub fn open(data_dir: &Path) -> StateDbResult<Self> {
        let dir = data_dir.join(STATE_DB_SUBDIR);
        let db = Database::builder(&dir).open()?;
        let state = db.keyspace(STATE, KeyspaceCreateOptions::default)?;
        let snap = db.keyspace(SNAP, KeyspaceCreateOptions::default)?;
        let meta = db.keyspace(META, KeyspaceCreateOptions::default)?;
        Ok(Self { db, state, snap, meta })
    }

    /// A shared handle to the live state keyspace, for [`crate::State`].
    pub fn state_keyspace(&self) -> Arc<Keyspace> {
        Arc::new(self.state.clone())
    }

    /// Persists `bytes` as the state snapshot of accepted checkpoint `round`.
    /// Overwrites any earlier snapshot for the round.
    pub fn snapshot(&self, round: u64, bytes: &[u8]) -> StateDbResult<()> {
        self.snap.insert(round.to_be_bytes(), bytes)?;
        Ok(())
    }

    /// Persists `bytes` as the state snapshot of accepted checkpoint `round`
    /// and flushes the database so the snapshot is durable before the
    /// checkpoint file is considered persisted. Used by `accept_checkpoint` to
    /// ensure a crash between snapshot insert and checkpoint persist cannot
    /// leave a checkpoint that references a missing snapshot on restart.
    pub fn snapshot_and_flush(&self, round: u64, bytes: &[u8]) -> StateDbResult<()> {
        self.snap.insert(round.to_be_bytes(), bytes)?;
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// The persisted state snapshot for accepted checkpoint `round`, if any.
    pub fn snapshot_for(&self, round: u64) -> StateDbResult<Option<Vec<u8>>> {
        Ok(self.snap.get(round.to_be_bytes())?.map(|value| value.as_slice().to_vec()))
    }

    /// Removes every snapshot for a round strictly below `keep_from_round`,
    /// mirroring the in-memory retention window. Idempotent.
    pub fn prune_snapshots_before(&self, keep_from_round: u64) -> StateDbResult<()> {
        let mut batch = self.db.batch();
        for guard in self.snap.iter() {
            let (key, _) = guard.into_inner()?;
            let bytes: &[u8] = &key;
            let Some(round) = bytes.get(..8).and_then(|head| head.try_into().ok()) else {
                continue;
            };
            if u64::from_be_bytes(round) < keep_from_round {
                batch.remove(&self.snap, bytes);
            }
        }
        if !batch.is_empty() {
            batch.commit()?;
        }
        Ok(())
    }

    /// Removes every entry from the live state keyspace, leaving it empty.
    /// Used when rebuilding state from wire bytes over a previously-used
    /// database (restart recovery, reconnect apply).
    pub fn clear_state(&self) -> StateDbResult<()> {
        let mut batch = self.db.batch();
        for guard in self.state.iter() {
            let (key, _) = guard.into_inner()?;
            let bytes: &[u8] = &key;
            batch.remove(&self.state, bytes);
        }
        if !batch.is_empty() {
            batch.commit()?;
        }
        Ok(())
    }

    /// Flushes the journal to disk, making all writes durable against power
    /// loss. Without it, the database is still crash-safe (consistent after a
    /// crash), but recent writes may not survive a power cut.
    pub fn flush(&self) -> StateDbResult<()> {
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// Persists the monotonic `last_timestamp` watermark (millis since epoch)
    /// for this node's own events. Stored in the `meta` keyspace so it is
    /// durable across restarts alongside the checkpoint snapshots. Overwrites
    /// any earlier value.
    pub fn set_watermark(&self, watermark: u64) -> StateDbResult<()> {
        self.meta.insert(WATERMARK_KEY, watermark.to_be_bytes())?;
        Ok(())
    }

    /// Persists the watermark and flushes the database so it is durable before
    /// the checkpoint file is considered persisted.
    pub fn set_watermark_and_flush(&self, watermark: u64) -> StateDbResult<()> {
        self.meta.insert(WATERMARK_KEY, watermark.to_be_bytes())?;
        self.db.persist(PersistMode::SyncAll)?;
        Ok(())
    }

    /// The persisted `last_timestamp` watermark, if any.
    pub fn watermark(&self) -> StateDbResult<Option<u64>> {
        Ok(self
            .meta
            .get(WATERMARK_KEY)?
            .map(|v| u64::from_be_bytes(v.as_slice().try_into().unwrap_or([0u8; 8]))))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn open_creates_empty_keyspaces() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        assert_eq!(db.state_keyspace().len().expect("len"), 0);
        assert!(db.snapshot_for(1).expect("no snapshot").is_none());
    }

    #[test]
    fn state_keyspace_round_trips_entries() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let kv = db.state_keyspace();
        kv.insert(b"k", b"v").expect("insert");
        kv.insert(b"a", b"1").expect("insert");
        let value = kv.get(b"k").expect("get").expect("present");
        assert_eq!(value.as_slice(), b"v");
        assert_eq!(kv.len().expect("len"), 2);
        kv.remove(b"k").expect("remove");
        assert!(kv.get(b"k").expect("get").is_none());
    }

    #[test]
    fn snapshot_round_trips_and_overwrites() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        assert!(db.snapshot_for(3).expect("empty").is_none());
        db.snapshot(3, b"bytes-v1").expect("snapshot");
        assert_eq!(db.snapshot_for(3).expect("present"), Some(b"bytes-v1".to_vec()));
        db.snapshot(3, b"bytes-v2").expect("overwrite");
        assert_eq!(db.snapshot_for(3).expect("present"), Some(b"bytes-v2".to_vec()));
    }

    #[test]
    fn prune_snapshots_removes_only_old_rounds() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        for round in [1u64, 2, 3, 4] {
            db.snapshot(round, &[round as u8]).expect("snapshot");
        }
        db.prune_snapshots_before(3).expect("prune");
        assert!(db.snapshot_for(1).expect("pruned").is_none());
        assert!(db.snapshot_for(2).expect("pruned").is_none());
        assert_eq!(db.snapshot_for(3).expect("kept"), Some(vec![3]));
        assert_eq!(db.snapshot_for(4).expect("kept"), Some(vec![4]));
    }

    #[test]
    fn clear_state_empties_the_live_partition() {
        let dir = tempdir().expect("temp dir");
        let db = StateDb::open(dir.path()).expect("opens");
        let kv = db.state_keyspace();
        kv.insert(b"k", b"v").expect("insert");
        db.clear_state().expect("clear");
        assert_eq!(kv.len().expect("len"), 0);
    }

    #[test]
    fn reopen_round_trips_snapshots() {
        let dir = tempdir().expect("temp dir");
        {
            let db = StateDb::open(dir.path()).expect("opens");
            db.snapshot(7, b"bytes").expect("snapshot");
            db.flush().expect("flush");
        }
        let reopened = StateDb::open(dir.path()).expect("reopens");
        assert_eq!(reopened.snapshot_for(7).expect("present"), Some(b"bytes".to_vec()));
    }
}
