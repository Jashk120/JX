//! Record stream files (`.rsf`): one file per decided round, written on
//! checkpoint acceptance.
//!
//! Each file carries the round's finalized transactions in consensus order
//! (from [`Hashgraph::consensus_order`]) plus the round's threshold-signed
//! [`SignedCheckpoint`] — the state-root anchor that makes the file
//! source-agnostic. Files chain through the §5 running hash: file `r+1`'s
//! `start_running_hash` equals file `r`'s `end_running_hash`, enforced by the
//! reader. The deterministic order source means record files are byte-identical
//! across the cluster for the rounds a node has written.
//!
//! The [`RecordStreamWriter`] consumes an ordered channel on a background task,
//! so the consensus hot path (`accept_checkpoint`) never blocks on disk: the
//! notifier assembles the items in memory (briefly holding the graph lock) and
//! the writer task performs the atomic file + signature writes.

use std::fs;
use std::path::{
    Path,
    PathBuf,
};
use std::sync::Arc;

use consensus::{
    Hashgraph,
    SignedCheckpoint,
};
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::sync::{
    Mutex,
    mpsc,
    oneshot,
};

use crate::convert::{
    check_round_consistency,
    digest_hash_object,
    hash_object_digest,
    record_items_for_round,
    signed_checkpoint_to_proto,
};
use crate::error::{
    Result,
    StreamError,
};
use crate::{
    RECORD_FILE_PREFIX,
    RECORD_FILE_SUFFIX,
    STREAM_VERSION,
    pb,
    record_file_name,
    running_hash,
    signature,
    signature_file_name,
};

/// The sink a `GossipNode` notifies from `accept_checkpoint` whenever a round
/// reaches the threshold-signed quorum. Implementations must not block on disk
/// (the writer queues the file for its background task).
pub trait RecordSink: Send + Sync {
    /// Assembles the round's record items and queues the `.rsf` file.
    fn persist(
        &self,
        checkpoint: &SignedCheckpoint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// One message on the record writer's ordered channel.
enum RecordStreamMsg {
    Write {
        checkpoint: SignedCheckpoint,
        items: Vec<pb::RecordItem>,
    },
    /// A test/daemon barrier: acknowledged once every earlier message has been
    /// written to disk.
    Barrier {
        ack: oneshot::Sender<()>,
    },
}

/// Writes the per-round record stream: `<dir>/round-<r>.rsf` plus its
/// `<dir>/round-<r>.rsf_sig` signature file. Construct with
/// [`RecordStreamWriter::open`]; register it on a node via
/// `set_record_sink`.
pub struct RecordStreamWriter {
    hashgraph: Arc<Mutex<Hashgraph>>,
    sender: mpsc::UnboundedSender<RecordStreamMsg>,
    _task: tokio::task::JoinHandle<()>,
}

impl RecordStreamWriter {
    /// Opens (creating if needed) the record stream under `dir`, resuming the
    /// running-hash chain and file numbering from the highest existing `.rsf`,
    /// and spawns the background writer task.
    pub fn open(
        dir: &Path,
        signing_key: SigningKey,
        hashgraph: Arc<Mutex<Hashgraph>>,
    ) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let (next_round, running_hash) = resume_state(dir)?;
        let (sender, receiver) = mpsc::unbounded_channel();
        let writer_dir = dir.to_path_buf();
        let task =
            tokio::spawn(run_writer(writer_dir, signing_key, receiver, (next_round, running_hash)));
        Ok(Self { hashgraph, sender, _task: task })
    }

    /// Queues the record file for `checkpoint`'s round. The items are
    /// assembled from the hashgraph's consensus order for that round — which is
    /// final and immutable by the time a checkpoint for it is accepted. A
    /// duplicate or older round is a no-op.
    pub async fn submit(&self, checkpoint: &SignedCheckpoint) {
        let round = checkpoint.payload.round;
        let items = {
            let hashgraph = self.hashgraph.lock().await;
            record_items_for_round(&hashgraph, round)
        };
        self.submit_items(checkpoint.clone(), items);
    }

    /// Queues a fully assembled record file (used directly by tests and by
    /// [`Self::submit`], which assembles the items from the hashgraph).
    pub fn submit_items(&self, checkpoint: SignedCheckpoint, items: Vec<pb::RecordItem>) {
        let round = checkpoint.payload.round;
        let msg = RecordStreamMsg::Write { checkpoint, items };
        if self.sender.send(msg).is_err() {
            eprintln!("[stream] record writer task is gone; dropping round {round}");
        }
    }

    /// Awaits until every previously queued file has been written to disk.
    pub async fn barrier(&self) {
        let (ack, receiver) = oneshot::channel();
        if self.sender.send(RecordStreamMsg::Barrier { ack }).is_err() {
            return;
        }
        let _ = receiver.await;
    }
}

impl RecordSink for RecordStreamWriter {
    fn persist(
        &self,
        checkpoint: &SignedCheckpoint,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        let checkpoint = checkpoint.clone();
        Box::pin(async move { self.submit(&checkpoint).await })
    }
}

/// The record writer's background loop: writes files strictly in round order.
async fn run_writer(
    dir: PathBuf,
    signing_key: SigningKey,
    mut receiver: mpsc::UnboundedReceiver<RecordStreamMsg>,
    mut state: (u64, [u8; 32]),
) {
    while let Some(message) = receiver.recv().await {
        match message {
            RecordStreamMsg::Write { checkpoint, items } => {
                let round = checkpoint.payload.round;
                if round < state.0 {
                    // Already written (e.g. a duplicate notification).
                    continue;
                }
                let write =
                    write_record_file(&dir, &signing_key, &checkpoint, &items, &mut state.1);
                if let Err(e) = write {
                    eprintln!("[stream] failed to write record stream file for round {round}: {e}");
                    continue;
                }
                state.0 = round + 1;
            }
            RecordStreamMsg::Barrier { ack } => {
                let _ = ack.send(());
            }
        }
    }
}

/// Builds, signs, and atomically writes one record file, advancing
/// `running_hash` past the round. The signature file is written first so a
/// crash between the two writes can only leave an orphaned signature — never a
/// stream file without its signature.
fn write_record_file(
    dir: &Path,
    signing_key: &SigningKey,
    checkpoint: &SignedCheckpoint,
    items: &[pb::RecordItem],
    running_hash: &mut [u8; 32],
) -> Result<()> {
    let round = checkpoint.payload.round;
    let start_hash = *running_hash;
    let end_hash = chain_items(start_hash, items);
    let file = pb::RecordStreamFile {
        version: STREAM_VERSION,
        round,
        start_running_hash: Some(digest_hash_object(start_hash)),
        items: items.to_vec(),
        end_running_hash: Some(digest_hash_object(end_hash)),
        checkpoint: Some(signed_checkpoint_to_proto(checkpoint)),
    };
    let file_bytes = file.encode_to_vec();
    let metadata = signature::metadata_bytes(STREAM_VERSION, &start_hash, &end_hash, Some(round));
    let signature_file = signature::build_signature_file(&file_bytes, &metadata, signing_key);
    let file_name = record_file_name(round);
    signature::write_signature_file(&dir.join(signature_file_name(&file_name)), &signature_file)?;
    signature::write_atomic(&dir.join(file_name), &file_bytes)?;
    *running_hash = end_hash;
    Ok(())
}

/// Folds every item's serialized form into the chain, returning the running
/// hash after the last item.
fn chain_items(start: [u8; 32], items: &[pb::RecordItem]) -> [u8; 32] {
    let mut current = start;
    for item in items {
        let bytes = item.encode_to_vec();
        current = running_hash::chain_hash(&current, &running_hash::item_hash(&bytes));
    }
    current
}

/// Scans `dir` for existing record files, returning `(next_round,
/// running_hash)` for the writer to resume from: the round after the highest
/// written one, chained from that file's `end_running_hash` (or the seed for
/// an empty directory).
fn resume_state(dir: &Path) -> Result<(u64, [u8; 32])> {
    let mut highest: Option<(u64, [u8; 32])> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(round) = name
            .strip_prefix(RECORD_FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(RECORD_FILE_SUFFIX))
        else {
            continue;
        };
        let Ok(round) = round.parse::<u64>() else { continue };
        let bytes = fs::read(entry.path())?;
        let file = read_record_stream_file(&bytes)?;
        let Some(end_hash) = file.end_running_hash.as_ref().and_then(hash_object_digest) else {
            return Err(StreamError::Malformed(format!(
                "record file {name} has an invalid end_running_hash"
            )));
        };
        if highest.as_ref().is_none_or(|(best, _)| round > *best) {
            highest = Some((round, end_hash));
        }
    }
    match highest {
        Some((round, end_hash)) => Ok((round + 1, end_hash)),
        None => Ok((1, running_hash::CHAIN_SEED)),
    }
}

/// Decodes and structurally validates a record stream file: the version, the
/// round/checkpoint consistency, and the presence of both running-hash
/// commitments.
pub fn read_record_stream_file(bytes: &[u8]) -> Result<pb::RecordStreamFile> {
    let file = pb::RecordStreamFile::decode(bytes)?;
    if file.encoded_len() != bytes.len() {
        // prost tolerates trailing bytes; a mirror must not.
        return Err(StreamError::TrailingBytes);
    }
    if file.version != STREAM_VERSION {
        return Err(StreamError::BadVersion(file.version));
    }
    check_round_consistency(&file)?;
    if file.start_running_hash.as_ref().and_then(hash_object_digest).is_none()
        || file.end_running_hash.as_ref().and_then(hash_object_digest).is_none()
    {
        return Err(StreamError::Malformed(
            "record stream file is missing a running-hash commitment".into(),
        ));
    }
    Ok(file)
}

/// The `.rsf` files present in `dir`, ascending by round.
pub fn record_files_in(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(round) = name
            .strip_prefix(RECORD_FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(RECORD_FILE_SUFFIX))
        else {
            continue;
        };
        if let Ok(round) = round.parse::<u64>() {
            files.push((round, entry.path()));
        }
    }
    files.sort_by_key(|(round, _)| *round);
    Ok(files)
}

#[cfg(test)]
mod tests {
    use crypto::MembershipRegistry;
    use primitives::NodeId;

    use super::*;

    fn registry_of(members: &[u64]) -> MembershipRegistry {
        let mut registry = MembershipRegistry::new();
        for &id in members {
            registry
                .register(NodeId::new(id), SigningKey::from_bytes(&[id as u8; 32]).verifying_key());
        }
        registry
    }

    fn checkpoint_for(round: u64, members: &[u64]) -> SignedCheckpoint {
        let roster = registry_of(members);
        let payload = consensus::CheckpointPayload::new(round, [round as u8; 32], roster);
        SignedCheckpoint { payload, sigs: Vec::new() }
    }

    fn empty_hashgraph() -> Arc<Mutex<Hashgraph>> {
        Arc::new(Mutex::new(consensus::Hashgraph::new(&registry_of(&[1, 2, 3]))))
    }

    #[tokio::test]
    async fn record_file_round_trips_and_chains() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = RecordStreamWriter::open(
            dir.path(),
            SigningKey::from_bytes(&[1; 32]),
            empty_hashgraph(),
        )
        .expect("opens");
        for round in [1, 2, 3] {
            let items = vec![pb::RecordItem {
                event_hash: vec![round as u8; 32],
                tx_index: 0,
                tx_payload: vec![round as u8; 4],
            }];
            writer.submit_items(checkpoint_for(round, &[1, 2, 3]), items);
        }
        writer.barrier().await;
        let mut previous_end: Option<[u8; 32]> = None;
        for (round, path) in record_files_in(dir.path()).expect("files").into_iter() {
            let bytes = fs::read(&path).expect("read");
            let file = read_record_stream_file(&bytes).expect("decodes");
            assert_eq!(file.round, round);
            let start = hash_object_digest(file.start_running_hash.as_ref().expect("start"))
                .expect("start hash");
            let end =
                hash_object_digest(file.end_running_hash.as_ref().expect("end")).expect("end hash");
            match previous_end {
                None => {
                    assert_eq!(start, running_hash::CHAIN_SEED, "first file starts at the seed")
                }
                Some(previous) => {
                    assert_eq!(start, previous, "file {round} chains from the previous file")
                }
            }
            previous_end = Some(end);
        }
    }

    #[tokio::test]
    async fn resume_continues_the_chain() {
        let dir = tempfile::tempdir().expect("temp dir");
        let hashgraph = empty_hashgraph();
        let first = RecordStreamWriter::open(
            dir.path(),
            SigningKey::from_bytes(&[1; 32]),
            hashgraph.clone(),
        )
        .expect("opens");
        first.submit_items(checkpoint_for(2, &[1, 2, 3]), Vec::new());
        first.barrier().await;
        drop(first);

        let resumed =
            RecordStreamWriter::open(dir.path(), SigningKey::from_bytes(&[1; 32]), hashgraph)
                .expect("reopens");
        resumed.submit_items(checkpoint_for(3, &[1, 2, 3]), Vec::new());
        resumed.barrier().await;

        let files = record_files_in(dir.path()).expect("files");
        assert_eq!(files.len(), 2);
        let two = read_record_stream_file(&fs::read(&files[0].1).expect("read")).expect("round 2");
        let three =
            read_record_stream_file(&fs::read(&files[1].1).expect("read")).expect("round 3");
        let end_two =
            hash_object_digest(two.end_running_hash.as_ref().expect("end")).expect("hash");
        let start_three =
            hash_object_digest(three.start_running_hash.as_ref().expect("start")).expect("hash");
        assert_eq!(
            start_three, end_two,
            "the resumed writer chains from the highest existing file"
        );
    }
}
