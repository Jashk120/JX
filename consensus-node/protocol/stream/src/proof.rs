use std::fs;
use std::path::Path;

use consensus::{
    RecordsRootItem,
    build_records_proofs as consensus_build_proofs,
    compute_records_root,
};
use prost::Message;

use crate::error::{
    Result,
    StreamError,
};
use crate::{
    RECORD_FILE_PREFIX,
    RECORD_PROOF_SUFFIX,
    STREAM_VERSION,
    pb,
    record_proof_file_name,
};

pub fn build_records_proofs_from_items(items: &[pb::RecordItem]) -> Vec<pb::ProofEntry> {
    let rr_items: Vec<RecordsRootItem> = items
        .iter()
        .filter_map(|it| {
            let hash: [u8; 32] = it.event_hash.clone().try_into().ok()?;
            Some(RecordsRootItem {
                event_hash: hash,
                tx_index: it.tx_index,
                tx_payload: it.tx_payload.clone(),
            })
        })
        .collect();
    if rr_items.len() != items.len() {
        return Vec::new();
    }
    build_records_proofs(&rr_items)
}

pub fn build_records_proofs(items: &[RecordsRootItem]) -> Vec<pb::ProofEntry> {
    let proofs = consensus_build_proofs(items);
    proofs
        .into_iter()
        .map(|p| pb::ProofEntry {
            item_index: p.item_index,
            proof_steps: p
                .steps
                .into_iter()
                .map(|s| pb::ProofStep {
                    sibling_hash: s.sibling_hash.to_vec(),
                    sibling_is_right: s.sibling_is_right,
                })
                .collect(),
        })
        .collect()
}

pub fn compute_records_root_with_proofs(
    items: &[RecordsRootItem],
) -> ([u8; 32], Vec<pb::ProofEntry>) {
    let root = compute_records_root(items);
    let proofs = build_records_proofs(items);
    (root, proofs)
}

pub fn verify_proof(root: &[u8; 32], item: &RecordsRootItem, proof: &pb::ProofEntry) -> bool {
    if proof.item_index as usize >= usize::MAX {
        return false;
    }
    let native_steps: Vec<consensus::RecordsProofStep> = proof
        .proof_steps
        .iter()
        .filter_map(|s| {
            let hash: [u8; 32] = s.sibling_hash.clone().try_into().ok()?;
            Some(consensus::RecordsProofStep {
                sibling_hash: hash,
                sibling_is_right: s.sibling_is_right,
            })
        })
        .collect();
    if native_steps.len() != proof.proof_steps.len() {
        return false;
    }
    let native = consensus::RecordsProof { item_index: proof.item_index, steps: native_steps };
    consensus::verify_records_proof(root, item, &native)
}

pub fn write_records_proof_file(dir: &Path, round: u64, proofs: &[pb::ProofEntry]) -> Result<()> {
    let file = pb::RecordsProofFile { version: STREAM_VERSION, round, proofs: proofs.to_vec() };
    let bytes = file.encode_to_vec();
    let name = record_proof_file_name(round);
    crate::signature::write_atomic(&dir.join(name), &bytes)
}

pub fn read_records_proof_file(bytes: &[u8]) -> Result<pb::RecordsProofFile> {
    let file = pb::RecordsProofFile::decode(bytes)?;
    if file.encoded_len() != bytes.len() {
        return Err(StreamError::TrailingBytes);
    }
    if file.version != STREAM_VERSION {
        return Err(StreamError::BadVersion(file.version));
    }
    for entry in &file.proofs {
        for step in &entry.proof_steps {
            if step.sibling_hash.len() != 32 {
                return Err(StreamError::Malformed(format!(
                    "proof step sibling_hash must be 32 bytes, got {}",
                    step.sibling_hash.len()
                )));
            }
        }
    }
    Ok(file)
}

pub fn proof_files_in(dir: &Path) -> Result<Vec<(u64, std::path::PathBuf)>> {
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Some(round) = name
            .strip_prefix(RECORD_FILE_PREFIX)
            .and_then(|rest| rest.strip_suffix(RECORD_PROOF_SUFFIX))
        else {
            continue;
        };
        if let Ok(round) = round.parse::<u64>() {
            files.push((round, entry.path()));
        }
    }
    files.sort_by_key(|(r, _)| *r);
    Ok(files)
}

#[cfg(test)]
mod tests {
    use consensus::RecordsRootItem;
    use prost::Message;

    use super::*;

    fn item(event_byte: u8, tx_index: u32, payload: &[u8]) -> RecordsRootItem {
        RecordsRootItem { event_hash: [event_byte; 32], tx_index, tx_payload: payload.to_vec() }
    }

    #[test]
    fn proofs_verify_against_root_and_count_matches() {
        let items = vec![
            item(1, 0, b"a"),
            item(2, 1, b"b"),
            item(3, 0, b"c"),
            item(4, 2, b"d"),
            item(5, 0, b"e"),
        ];
        let (root, proofs) = compute_records_root_with_proofs(&items);
        assert_eq!(proofs.len(), items.len());
        for (i, proof) in proofs.iter().enumerate() {
            assert_eq!(proof.item_index as usize, i);
            assert!(verify_proof(&root, &items[i], proof));
        }
    }

    #[test]
    fn tampered_sibling_fails_verification() {
        let items = vec![item(1, 0, b"a"), item(2, 0, b"b"), item(3, 0, b"c")];
        let (root, mut proofs) = compute_records_root_with_proofs(&items);
        assert!(verify_proof(&root, &items[0], &proofs[0]));
        if proofs[0].proof_steps.is_empty() {
            // singleton case has no steps; tamper different proof
            assert!(!proofs.is_empty());
        } else {
            proofs[0].proof_steps[0].sibling_hash[0] ^= 0xff;
            assert!(!verify_proof(&root, &items[0], &proofs[0]));
        }
        // Also flip sibling_is_right if steps exist for 3 items
        let mut p2 = proofs[1].clone();
        if !p2.proof_steps.is_empty() {
            p2.proof_steps[0].sibling_is_right = !p2.proof_steps[0].sibling_is_right;
            assert!(!verify_proof(&root, &items[1], &p2));
        }
    }

    #[test]
    fn empty_round_has_no_proofs() {
        let items: Vec<RecordsRootItem> = Vec::new();
        let (root, proofs) = compute_records_root_with_proofs(&items);
        assert_eq!(root, consensus::compute_records_root(&[]));
        assert!(proofs.is_empty());
        let dir = tempfile::tempdir().expect("temp dir");
        write_records_proof_file(dir.path(), 7, &proofs).expect("write empty");
        let bytes = std::fs::read(dir.path().join(record_proof_file_name(7))).expect("read");
        let file = read_records_proof_file(&bytes).expect("decode");
        assert_eq!(file.version, STREAM_VERSION);
        assert_eq!(file.round, 7);
        assert!(file.proofs.is_empty());
    }

    #[test]
    fn padded_three_items_yields_two_steps() {
        let items = vec![item(1, 0, b"a"), item(2, 0, b"b"), item(3, 0, b"c")];
        let (_, proofs) = compute_records_root_with_proofs(&items);
        assert_eq!(proofs.len(), 3);
        for proof in &proofs {
            assert_eq!(proof.proof_steps.len(), 2, "3 items padded to 4 => 2 steps");
            for step in &proof.proof_steps {
                assert_eq!(step.sibling_hash.len(), 32);
            }
        }
        // Singleton round has zero steps
        let solo = vec![item(9, 0, b"solo")];
        let (_, solo_proofs) = compute_records_root_with_proofs(&solo);
        assert_eq!(solo_proofs.len(), 1);
        assert_eq!(solo_proofs[0].proof_steps.len(), 0);
        // Two items => 1 step each
        let two = vec![item(1, 0, b"a"), item(2, 0, b"b")];
        let (_, two_proofs) = compute_records_root_with_proofs(&two);
        for p in &two_proofs {
            assert_eq!(p.proof_steps.len(), 1);
        }
    }

    #[test]
    fn proof_file_rejects_bad_version_and_trailing_and_hash_len() {
        let items = vec![item(1, 0, b"a")];
        let (_, proofs) = compute_records_root_with_proofs(&items);
        let mut file =
            pb::RecordsProofFile { version: STREAM_VERSION, round: 1, proofs: proofs.clone() };
        let mut bytes = file.encode_to_vec();
        // Trailing bytes
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(read_records_proof_file(&trailing).is_err());
        // Bad version
        file.version = 99;
        let bad_bytes = file.encode_to_vec();
        assert!(read_records_proof_file(&bad_bytes).is_err());
        // Bad hash length
        let mut bad_proofs = proofs;
        if !bad_proofs.is_empty() && bad_proofs[0].proof_steps.is_empty() {
            // add a step with bad length for this case
            bad_proofs[0]
                .proof_steps
                .push(pb::ProofStep { sibling_hash: vec![0u8; 3], sibling_is_right: true });
        } else if !bad_proofs.is_empty() {
            bad_proofs[0].proof_steps[0].sibling_hash = vec![0u8; 3];
        }
        let bad_file =
            pb::RecordsProofFile { version: STREAM_VERSION, round: 1, proofs: bad_proofs };
        let bad_bytes2 = bad_file.encode_to_vec();
        assert!(read_records_proof_file(&bad_bytes2).is_err());
        // Ensure original valid decodes
        bytes = pb::RecordsProofFile { version: STREAM_VERSION, round: 1, proofs: vec![] }
            .encode_to_vec();
        assert!(read_records_proof_file(&bytes).is_ok());
    }
}
