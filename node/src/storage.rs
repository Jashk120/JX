//! Checkpoint persistence for a running node.
//!
//! Every accepted [`SignedCheckpoint`] is written under `<data>/checkpoints/`
//! as:
//!
//! ```text
//! checkpoint-<round>.cp    consensus::encode_signed_checkpoint(checkpoint)
//! ```
//!
//! The per-round state snapshot that used to live in a `.snap` file next to
//! the checkpoint now lives in the Fjall state database's `snap` keyspace
//! (`<data>/statedb/`, see `state::StateDb`) — the exact state bytes at the
//! checkpoint round are restored and verified from there on restart.
//!
//! Writes are atomic (temp file + `sync_all` + rename), so a crash mid-write
//! never leaves a torn file. Older rounds are pruned alongside in-memory
//! retention, mirroring `RETENTION_ROUNDS`. The retained event graph is not
//! persisted — a restarting node reloads state and roster from its latest
//! checkpoint and reconnects from a live peer for the event window.

use std::fs;
use std::path::{
    Path,
    PathBuf,
};

use anyhow::{
    Context,
    Result,
};
use consensus::{
    SignedCheckpoint,
    encode_signed_checkpoint,
};
use gossip::CheckpointSink;

/// Subdirectory (under the data dir) holding checkpoint files.
pub const CHECKPOINT_SUBDIR: &str = "checkpoints";

/// Checkpoint files at or below this many rounds older than the newest one
/// are pruned, mirroring `consensus::RETENTION_ROUNDS`.
pub const PRUNE_RETENTION_ROUNDS: u64 = consensus::RETENTION_ROUNDS;

/// A persisted checkpoint. The state bytes that hash to its committed
/// `state_hash` are not stored here — they live in the state database's
/// `snap` keyspace, keyed by this round.
#[derive(Clone, Debug)]
pub struct PersistedCheckpoint {
    pub checkpoint: SignedCheckpoint,
}

/// Filesystem-backed checkpoint storage rooted at a data directory.
pub struct Storage {
    dir: PathBuf,
}

impl Storage {
    /// Opens (creating if needed) the checkpoint storage under `data_dir`.
    pub fn new(data_dir: &Path) -> Result<Self> {
        let dir = data_dir.join(CHECKPOINT_SUBDIR);
        fs::create_dir_all(&dir)
            .with_context(|| format!("creating checkpoint dir {}", dir.display()))?;
        Ok(Self { dir })
    }

    /// Atomically persists `checkpoint`.
    pub fn persist(&self, checkpoint: &SignedCheckpoint) -> Result<()> {
        let round = checkpoint.payload.round;
        let checkpoint_path = self.checkpoint_path(round);
        atomic_write(&checkpoint_path, &encode_signed_checkpoint(checkpoint))
            .with_context(|| format!("writing checkpoint {round}"))?;
        Ok(())
    }

    /// Deletes every checkpoint file for a round strictly below
    /// `keep_from_round`. Idempotent; missing files are fine.
    pub fn prune_before(&self, keep_from_round: u64) -> Result<()> {
        for round in self.rounds()? {
            if round < keep_from_round {
                self.remove_round(round);
            }
        }
        Ok(())
    }

    /// The persisted checkpoint with the highest round, if any.
    pub fn latest(&self) -> Result<Option<PersistedCheckpoint>> {
        let Some(round) = self.rounds()?.into_iter().max() else {
            return Ok(None);
        };
        self.load_round(round).map(Some)
    }

    /// The persisted checkpoint for `round`, if any.
    pub fn load_round(&self, round: u64) -> Result<PersistedCheckpoint> {
        let checkpoint_path = self.checkpoint_path(round);
        let checkpoint_bytes = fs::read(&checkpoint_path)
            .with_context(|| format!("reading checkpoint {}", checkpoint_path.display()))?;
        let checkpoint = consensus::decode_signed_checkpoint(&checkpoint_bytes)
            .with_context(|| format!("decoding checkpoint {}", checkpoint_path.display()))?;
        Ok(PersistedCheckpoint { checkpoint })
    }

    /// The rounds that have a persisted checkpoint file, ascending.
    pub fn rounds(&self) -> Result<Vec<u64>> {
        let mut rounds = Vec::new();
        for entry in
            fs::read_dir(&self.dir).with_context(|| format!("listing {}", self.dir.display()))?
        {
            let entry = entry.context("listing checkpoint dir")?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(round) =
                name.strip_prefix("checkpoint-").and_then(|rest| rest.strip_suffix(".cp"))
            else {
                continue;
            };
            if let Ok(round) = round.parse::<u64>() {
                rounds.push(round);
            }
        }
        rounds.sort_unstable();
        Ok(rounds)
    }

    fn checkpoint_path(&self, round: u64) -> PathBuf {
        self.dir.join(format!("checkpoint-{round}.cp"))
    }

    fn remove_round(&self, round: u64) {
        let _ = fs::remove_file(self.checkpoint_path(round));
        // Remove any legacy `.snap` file from a pre-Fjall-state data dir, so
        // pruning also cleans up the old per-round serialized state blobs.
        let _ = fs::remove_file(self.dir.join(format!("checkpoint-{round}.snap")));
    }
}

/// The daemon's checkpoint sink: persist each accepted checkpoint and prune
/// the files for rounds outside the in-memory retention window. Registered on
/// a [`gossip::GossipNode`] via `set_checkpoint_sink`.
///
/// The node invokes `persist` synchronously on its async task, so I/O here is
/// deliberately small (one small file per accept); failures are logged by the
/// caller, which swallows them rather than failing the sync loop.
impl CheckpointSink for Storage {
    fn persist(&self, checkpoint: &SignedCheckpoint) {
        let round = checkpoint.payload.round;
        if let Err(e) = Storage::persist(self, checkpoint) {
            eprintln!("[jkaind] failed to persist checkpoint {round}: {e:#}");
            return;
        }
        let keep_from = round.saturating_sub(PRUNE_RETENTION_ROUNDS);
        if let Err(e) = Storage::prune_before(self, keep_from) {
            eprintln!("[jkaind] failed to prune checkpoint files below {keep_from}: {e:#}");
        }
    }
}

/// Writes `bytes` to `path` atomically via the shared helper which also
/// fsyncs the containing directory so the rename is durable.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    storage::atomic::atomic_write(path, bytes)
        .with_context(|| format!("atomic write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use crypto::MembershipRegistry;
    use ed25519_dalek::SigningKey;
    use primitives::{
        NodeId,
        Signature,
    };
    use rand::rngs::OsRng;

    use super::*;

    fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            registry.register(NodeId::new(id), SigningKey::generate(&mut OsRng).verifying_key());
        }
        registry
    }

    fn signed_checkpoint(round: u64, members: &[u64]) -> SignedCheckpoint {
        let roster = registry_of(members);
        let payload = consensus::CheckpointPayload::new(round, [round as u8; 32], roster);
        let sigs = members
            .iter()
            .map(|&signer| consensus::CheckpointSig {
                round,
                signer: NodeId::new(signer),
                sig: Signature::new([signer as u8; 64]),
            })
            .collect();
        SignedCheckpoint { payload, sigs }
    }

    fn temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("temp dir")
    }

    #[test]
    fn persist_latest_round_trips() {
        let tmp = temp_dir();
        let storage = Storage::new(tmp.path()).expect("storage opens");
        let checkpoint = signed_checkpoint(3, &[1, 2]);
        storage.persist(&checkpoint).expect("persist");

        let loaded = storage.latest().expect("latest").expect("a checkpoint");
        assert_eq!(loaded.checkpoint, checkpoint);
    }

    #[test]
    fn latest_picks_highest_round() {
        let tmp = temp_dir();
        let storage = Storage::new(tmp.path()).expect("storage opens");
        for round in [1, 5, 3] {
            storage.persist(&signed_checkpoint(round, &[1, 2])).expect("persist");
        }
        let latest = storage.latest().expect("latest").expect("a checkpoint");
        assert_eq!(latest.checkpoint.payload.round, 5);
    }

    #[test]
    fn latest_is_none_for_empty_storage() {
        let tmp = temp_dir();
        let storage = Storage::new(tmp.path()).expect("storage opens");
        assert!(storage.latest().expect("latest").is_none());
    }

    #[test]
    fn prune_removes_old_rounds_only() {
        let tmp = temp_dir();
        let storage = Storage::new(tmp.path()).expect("storage opens");
        for round in [1, 2, 3, 4] {
            storage.persist(&signed_checkpoint(round, &[1, 2])).expect("persist");
        }
        storage.prune_before(3).expect("prune");
        assert_eq!(storage.rounds().expect("rounds"), vec![3, 4]);
        assert!(storage.latest().expect("latest").is_some());
        assert!(storage.load_round(3).is_ok());
        assert!(storage.load_round(4).is_ok());
        assert!(storage.load_round(1).is_err());
    }

    #[test]
    fn atomic_write_leaves_no_temp_files() {
        let tmp = temp_dir();
        let storage = Storage::new(tmp.path()).expect("storage opens");
        let checkpoint = signed_checkpoint(2, &[1, 2]);
        storage.persist(&checkpoint).expect("persist");
        let entries: Vec<String> = fs::read_dir(storage.dir.clone())
            .expect("read dir")
            .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
            .collect();
        assert!(entries.iter().all(|n| !n.starts_with(".tmp-")), "no temp files left: {entries:?}");
    }
}
