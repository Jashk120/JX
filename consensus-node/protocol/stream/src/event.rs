//! Event stream files (`.esf`): every gossip event a node inserts, in
//! insertion (= topological) order — the offline DAG source.
//!
//! The writer registers as a second [`storage::EventSink`] next to the
//! `EventLog`, so `append` fires once per newly inserted verified event in the
//! exact order the graph persists them. Events are buffered on a background
//! task and the current file is closed — `.esf` plus its `.esf_sig` — every
//! fixed event count ([`crate::DEFAULT_EVENTS_PER_FILE`] by default); a
//! count-based window (not a clock) keeps file boundaries deterministic. Files
//! chain through the §5 running hash, so a reader rejects any discontinuity.
//!
//! `round_received` is deliberately not backfilled: a freshly inserted event
//! is appended with `None`, and a mirror that needs a round→event mapping gets
//! it from the record stream. Events a reconnect teacher delivered already
//! ordered carry their `round_received` through.

use std::fs;
use std::path::{
    Path,
    PathBuf,
};

use consensus::RetainedEvent;
use ed25519_dalek::SigningKey;
use prost::Message;
use tokio::sync::{
    mpsc,
    oneshot,
};

use crate::convert::{
    digest_hash_object,
    hash_object_digest,
    retained_event_to_proto,
};
use crate::error::{
    Result,
    StreamError,
};
use crate::{
    EVENT_FILE_PREFIX,
    EVENT_FILE_SUFFIX,
    STREAM_VERSION,
    event_file_name,
    pb,
    running_hash,
    signature,
    signature_file_name,
};

/// One message on the event writer's ordered channel.
enum EventStreamMsg {
    Append(Box<RetainedEvent>),
    /// Finalize the current file even if the event window has not filled.
    Flush,
    /// A test/daemon barrier: acknowledged once every earlier message has been
    /// written to disk.
    Barrier {
        ack: oneshot::Sender<()>,
    },
}

/// The in-progress file state of the event writer's background task.
struct WriterState {
    /// The index of the file currently being accumulated.
    next_index: u64,
    /// The running hash after every event appended so far.
    running_hash: [u8; 32],
    /// The running hash before the current file's first event: the file's
    /// `start_running_hash`.
    file_start_hash: [u8; 32],
    /// Events accumulated into the current file.
    buffer: Vec<pb::Event>,
}

impl WriterState {
    fn from_resume(next_index: u64, running_hash: [u8; 32]) -> Self {
        Self { next_index, running_hash, file_start_hash: running_hash, buffer: Vec::new() }
    }

    /// Closes the current file: the next one starts at the current running
    /// hash, so the chain stays continuous.
    fn advance(&mut self) {
        self.next_index += 1;
        self.file_start_hash = self.running_hash;
        self.buffer.clear();
    }
}

/// Appends every freshly inserted verified event to the `.esf` files, in
/// insertion order, on a background task. Construct with
/// [`EventStreamWriter::open`]; register it on a node via
/// `set_event_stream_sink`.
pub struct EventStreamWriter {
    sender: mpsc::UnboundedSender<EventStreamMsg>,
    _task: tokio::task::JoinHandle<()>,
}

impl EventStreamWriter {
    /// Opens (creating if needed) the event stream under `dir`, resuming the
    /// running-hash chain from the highest existing `.esf`, and spawns the
    /// background writer task. `events_per_file` sets the fixed event-count
    /// window that closes a file.
    pub fn open(dir: &Path, signing_key: SigningKey, events_per_file: usize) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let (next_index, running_hash) = resume_state(dir)?;
        let (sender, receiver) = mpsc::unbounded_channel();
        let writer_dir = dir.to_path_buf();
        let task = tokio::spawn(run_writer(
            writer_dir,
            signing_key,
            events_per_file,
            receiver,
            WriterState::from_resume(next_index, running_hash),
        ));
        Ok(Self { sender, _task: task })
    }

    /// Awaits until every previously queued append has been written to disk.
    pub async fn barrier(&self) {
        let (ack, receiver) = oneshot::channel();
        if self.sender.send(EventStreamMsg::Barrier { ack }).is_err() {
            return;
        }
        let _ = receiver.await;
    }
}

impl storage::EventSink for EventStreamWriter {
    /// Queues a freshly inserted event for the writer task. Non-blocking, so
    /// the consensus hot path never waits on disk.
    fn append(&self, record: &RetainedEvent) {
        if self.sender.send(EventStreamMsg::Append(Box::new(record.clone()))).is_err() {
            eprintln!("[stream] event writer task is gone; dropping event append");
        }
    }

    /// Ordering is not backfilled into the event stream; a mirror that needs
    /// a round→event mapping reads the record stream instead.
    fn set_round_received(&self, _hash: &primitives::EventHash, _round_received: u64) {}

    /// The event stream carries no roster history.
    fn set_roster_history(&self, _bytes: &[u8]) {}

    /// Event files are immutable once written; pruning only affects live
    /// graph memory, not the stream.
    fn prune(&self, _hashes: &[primitives::EventHash]) {}

    /// Closes the current file if it holds any events, so a flush leaves the
    /// stream durable up to the last appended event.
    fn flush(&self) {
        if self.sender.send(EventStreamMsg::Flush).is_err() {
            eprintln!("[stream] event writer task is gone; drop during flush");
        }
    }
}

/// The event writer's background loop: accumulates events and closes a file
/// every `events_per_file` appends (or on `Flush`).
async fn run_writer(
    dir: PathBuf,
    signing_key: SigningKey,
    events_per_file: usize,
    mut receiver: mpsc::UnboundedReceiver<EventStreamMsg>,
    mut state: WriterState,
) {
    while let Some(message) = receiver.recv().await {
        match message {
            EventStreamMsg::Append(record) => {
                let event = retained_event_to_proto(&record);
                let bytes = event.encode_to_vec();
                state.running_hash =
                    running_hash::chain_hash(&state.running_hash, &running_hash::item_hash(&bytes));
                state.buffer.push(event);
                if state.buffer.len() >= events_per_file {
                    if let Err(e) = write_event_file(&dir, &signing_key, &state) {
                        eprintln!("[stream] failed to write event stream file: {e}");
                    }
                    state.advance();
                }
            }
            EventStreamMsg::Flush => {
                if state.buffer.is_empty() {
                    continue;
                }
                if let Err(e) = write_event_file(&dir, &signing_key, &state) {
                    eprintln!("[stream] failed to flush event stream file: {e}");
                }
                state.advance();
            }
            EventStreamMsg::Barrier { ack } => {
                let _ = ack.send(());
            }
        }
    }
}

/// Builds, signs, and atomically writes the current file: `events-<n>.esf`
/// plus its `.esf_sig`. The signature file is written first so a crash
/// between the two writes can only leave an orphaned signature — never a
/// stream file without its signature.
fn write_event_file(dir: &Path, signing_key: &SigningKey, state: &WriterState) -> Result<()> {
    let file = pb::EventStreamFile {
        version: STREAM_VERSION,
        start_running_hash: Some(digest_hash_object(state.file_start_hash)),
        events: state.buffer.clone(),
        end_running_hash: Some(digest_hash_object(state.running_hash)),
    };
    let file_bytes = file.encode_to_vec();
    let metadata = signature::metadata_bytes(
        STREAM_VERSION,
        &state.file_start_hash,
        &state.running_hash,
        None,
    );
    let signature_file = signature::build_signature_file(&file_bytes, &metadata, signing_key);
    let file_name = event_file_name(state.next_index);
    signature::write_signature_file(&dir.join(signature_file_name(&file_name)), &signature_file)?;
    signature::write_atomic(&dir.join(file_name), &file_bytes)?;
    Ok(())
}

/// Scans `dir` for existing event files, returning `(next_index,
/// running_hash)` for the writer to resume from: the index after the highest
/// written one, chained from that file's `end_running_hash` (or the seed for
/// an empty directory).
fn resume_state(dir: &Path) -> Result<(u64, [u8; 32])> {
    let mut highest: Option<(u64, [u8; 32])> = None;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(index) = name
            .strip_prefix(EVENT_FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(EVENT_FILE_SUFFIX))
        else {
            continue;
        };
        let Ok(index) = index.parse::<u64>() else { continue };
        let bytes = fs::read(entry.path())?;
        let file = read_event_stream_file(&bytes)?;
        let Some(end_hash) = file.end_running_hash.as_ref().and_then(hash_object_digest) else {
            return Err(StreamError::Malformed(format!(
                "event file {name} has an invalid end_running_hash"
            )));
        };
        if highest.as_ref().is_none_or(|(best, _)| index > *best) {
            highest = Some((index, end_hash));
        }
    }
    match highest {
        Some((index, end_hash)) => Ok((index + 1, end_hash)),
        None => Ok((0, running_hash::CHAIN_SEED)),
    }
}

/// Decodes and structurally validates an event stream file: the version and
/// the presence of both running-hash commitments.
pub fn read_event_stream_file(bytes: &[u8]) -> Result<pb::EventStreamFile> {
    let file = pb::EventStreamFile::decode(bytes)?;
    if file.encoded_len() != bytes.len() {
        // prost tolerates trailing bytes; a mirror must not.
        return Err(StreamError::TrailingBytes);
    }
    if file.version != STREAM_VERSION {
        return Err(StreamError::BadVersion(file.version));
    }
    if file.start_running_hash.as_ref().and_then(hash_object_digest).is_none()
        || file.end_running_hash.as_ref().and_then(hash_object_digest).is_none()
    {
        return Err(StreamError::Malformed(
            "event stream file is missing a running-hash commitment".into(),
        ));
    }
    Ok(file)
}

/// The `.esf` files present in `dir`, ascending by index.
pub fn event_files_in(dir: &Path) -> Result<Vec<(u64, PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(index) = name
            .strip_prefix(EVENT_FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(EVENT_FILE_SUFFIX))
        else {
            continue;
        };
        if let Ok(index) = index.parse::<u64>() {
            files.push((index, entry.path()));
        }
    }
    files.sort_by_key(|(index, _)| *index);
    Ok(files)
}

#[cfg(test)]
mod tests {
    use primitives::{
        NodeId,
        Signature,
        Timestamp,
        Transaction,
        UnsignedEvent,
    };
    use storage::EventSink;

    use super::*;

    fn sample_record(seq: u64, round: u64) -> RetainedEvent {
        let event = UnsignedEvent::new(
            NodeId::new(1),
            None,
            None,
            Timestamp::new(seq),
            vec![Transaction::from_bytes(vec![seq as u8])],
        )
        .finalize(Signature::new([seq as u8; 64]));
        RetainedEvent { event, seq, round, ancestor_seqs: vec![seq], round_received: None }
    }

    #[tokio::test]
    async fn writes_windows_and_chains_files() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = EventStreamWriter::open(dir.path(), SigningKey::from_bytes(&[1; 32]), 2)
            .expect("opens");
        for seq in 1..=5 {
            writer.append(&sample_record(seq, 1));
        }
        writer.barrier().await;
        let files = event_files_in(dir.path()).expect("files");
        assert_eq!(files.len(), 2, "5 events in windows of 2 close 2 files");
        let first = read_event_stream_file(&fs::read(&files[0].1).expect("read")).expect("first");
        let second = read_event_stream_file(&fs::read(&files[1].1).expect("read")).expect("second");
        assert_eq!(first.events.len(), 2);
        assert_eq!(second.events.len(), 2, "the 5th event is buffered, not yet written");
        let start_second =
            hash_object_digest(second.start_running_hash.as_ref().expect("start")).expect("hash");
        let end_first =
            hash_object_digest(first.end_running_hash.as_ref().expect("end")).expect("hash");
        assert_eq!(start_second, end_first, "file boundaries chain");
    }

    #[tokio::test]
    async fn flush_closes_the_current_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let writer = EventStreamWriter::open(dir.path(), SigningKey::from_bytes(&[1; 32]), 100)
            .expect("opens");
        writer.append(&sample_record(1, 1));
        writer.flush();
        writer.barrier().await;
        let files = event_files_in(dir.path()).expect("files");
        assert_eq!(files.len(), 1);
        let file = read_event_stream_file(&fs::read(&files[0].1).expect("read")).expect("decodes");
        assert_eq!(file.events.len(), 1);
        let start =
            hash_object_digest(file.start_running_hash.as_ref().expect("start")).expect("hash");
        assert_eq!(start, running_hash::CHAIN_SEED, "the first file starts at the seed");
    }

    #[tokio::test]
    async fn resume_continues_the_chain() {
        let dir = tempfile::tempdir().expect("temp dir");
        let first = EventStreamWriter::open(dir.path(), SigningKey::from_bytes(&[1; 32]), 100)
            .expect("opens");
        first.append(&sample_record(1, 1));
        first.flush();
        first.barrier().await;
        drop(first);

        let resumed = EventStreamWriter::open(dir.path(), SigningKey::from_bytes(&[1; 32]), 100)
            .expect("reopens");
        resumed.append(&sample_record(2, 1));
        resumed.flush();
        resumed.barrier().await;

        let files = event_files_in(dir.path()).expect("files");
        assert_eq!(files.len(), 2);
        let one = read_event_stream_file(&fs::read(&files[0].1).expect("read")).expect("first");
        let two = read_event_stream_file(&fs::read(&files[1].1).expect("read")).expect("second");
        assert_eq!(one.events.len(), 1);
        assert_eq!(two.events.len(), 1);
        let end_one =
            hash_object_digest(one.end_running_hash.as_ref().expect("end")).expect("hash");
        let start_two =
            hash_object_digest(two.start_running_hash.as_ref().expect("start")).expect("hash");
        assert_eq!(start_two, end_one, "the resumed writer chains from the highest existing file");
    }
}
