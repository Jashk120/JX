package stream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	blst "github.com/supranational/blst/bindings/go"
	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

const (
	hashAlgorithmSHA256 = 0
	hashLengthSHA256    = 32
	sigTypeEd25519      = 0
	sigLengthEd25519    = 64
)

var CheckpointDST = []byte("JKAIN-CHECKPOINT-BLS-V1")

var recordsRootDST = []byte("JKAIN-RECORDS-ROOT-V1")

func VerifyEventFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
	if len(pubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("missing verifying key: pubkey is required (H-4)")
	}
	if sig == nil {
		return fmt.Errorf("missing signature file for event stream file")
	}
	var esf pb.EventStreamFile
	if err := unmarshalStrict(fileBytes, &esf); err != nil {
		return fmt.Errorf("unmarshal EventStreamFile: %w", err)
	}
	if esf.Version != Version {
		return fmt.Errorf("unsupported version %d", esf.Version)
	}
	start, err := runningHashOrErr(esf.StartRunningHash)
	if err != nil {
		return err
	}
	end, err := runningHashOrErr(esf.EndRunningHash)
	if err != nil {
		return err
	}
	if err := verifyRunningHashEvent(start, end, esf.Events); err != nil {
		return err
	}
	metadata := metadataBytes(esf.Version, start, end, 0, false)
	return verifySignatureObjects(sig, fileBytes, metadata, pubKey)
}

func VerifyRecordFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey, trustedRosterHash []byte) error {
	_ = pubKey
	var rsf pb.RecordStreamFile
	if err := unmarshalStrict(fileBytes, &rsf); err != nil {
		return fmt.Errorf("unmarshal RecordStreamFile: %w", err)
	}
	if rsf.Version != Version {
		return fmt.Errorf("unsupported version %d", rsf.Version)
	}
	start, err := runningHashOrErr(rsf.StartRunningHash)
	if err != nil {
		return err
	}
	end, err := runningHashOrErr(rsf.EndRunningHash)
	if err != nil {
		return err
	}
	if err := verifyRunningHashRecord(start, end, rsf.Items); err != nil {
		return err
	}
	if rsf.Checkpoint == nil {
		return fmt.Errorf("record stream file has no checkpoint anchor")
	}
	if rsf.Checkpoint.Round != rsf.Round {
		return fmt.Errorf("record stream file round %d disagrees with its checkpoint round %d",
			rsf.Round, rsf.Checkpoint.Round)
	}
	if err := ValidateStateDiffs(rsf.StateDiffs); err != nil {
		return fmt.Errorf("state_diffs invalid: %w", err)
	}
	if err := verifyCheckpointBinding(rsf.Checkpoint, rsf.Items, trustedRosterHash); err != nil {
		return err
	}
	_ = sig
	return nil
}

func VerifyCheckpointFile(ckptBytes []byte, trustedRosterHash []byte) error {
	var ckpt pb.SignedCheckpoint
	if err := unmarshalStrict(ckptBytes, &ckpt); err != nil {
		return fmt.Errorf("unmarshal SignedCheckpoint: %w", err)
	}
	if err := verifyCheckpointQuorum(&ckpt, trustedRosterHash); err != nil {
		return err
	}
	return nil
}

func runningHashOrErr(h *pb.HashObject) ([32]byte, error) {
	var out [32]byte
	if h == nil {
		return out, fmt.Errorf("missing running hash")
	}
	if h.Algorithm != hashAlgorithmSHA256 || h.Length != hashLengthSHA256 || len(h.Hash) != hashLengthSHA256 {
		return out, fmt.Errorf("invalid running hash object: algorithm=%d length=%d hashLen=%d",
			h.Algorithm, h.Length, len(h.Hash))
	}
	copy(out[:], h.Hash)
	return out, nil
}

func metadataBytes(version uint32, start, end [32]byte, round uint64, hasRound bool) []byte {
	size := 4 + len(start) + len(end)
	if hasRound {
		size += 8
	}
	out := make([]byte, 0, size)
	var ver [4]byte
	binary.BigEndian.PutUint32(ver[:], version)
	out = append(out, ver[:]...)
	out = append(out, start[:]...)
	out = append(out, end[:]...)
	if hasRound {
		var r [8]byte
		binary.BigEndian.PutUint64(r[:], round)
		out = append(out, r[:]...)
	}
	return out
}

func verifySignatureObjects(sig *pb.SignatureFile, fileBytes, metadata []byte, pubKey ed25519.PublicKey) error {
	fileDigest := sha256.Sum256(fileBytes)
	if err := verifySignatureObject(sig.FileSignature, fileDigest, pubKey); err != nil {
		return fmt.Errorf("file signature invalid: %w", err)
	}
	metadataDigest := sha256.Sum256(metadata)
	if err := verifySignatureObject(sig.MetadataSignature, metadataDigest, pubKey); err != nil {
		return fmt.Errorf("metadata signature invalid: %w", err)
	}
	return nil
}

func verifySignatureObject(so *pb.SignatureObject, expected [32]byte, pubKey ed25519.PublicKey) error {
	if so == nil {
		return fmt.Errorf("missing signature object")
	}
	if so.Type != sigTypeEd25519 || so.Length != sigLengthEd25519 {
		return fmt.Errorf("unsupported signature type %d or length %d", so.Type, so.Length)
	}
	if so.HashObject == nil {
		return fmt.Errorf("missing hash object")
	}
	if so.HashObject.Algorithm != hashAlgorithmSHA256 || so.HashObject.Length != hashLengthSHA256 {
		return fmt.Errorf("unsupported hash algorithm %d or length %d",
			so.HashObject.Algorithm, so.HashObject.Length)
	}
	if !bytes.Equal(so.HashObject.Hash, expected[:]) {
		return fmt.Errorf("committed digest mismatch")
	}
	if len(so.Signature) != ed25519.SignatureSize {
		return fmt.Errorf("signature is %d bytes, want %d", len(so.Signature), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pubKey, expected[:], so.Signature) {
		return fmt.Errorf("ed25519 verification failed")
	}
	return nil
}

func deterministicMarshal(m proto.Message) ([]byte, error) {
	return proto.MarshalOptions{Deterministic: true}.Marshal(m)
}

func verifyRunningHashEvent(start, end [32]byte, events []*pb.Event) error {
	cur := start
	for _, ev := range events {
		b, err := deterministicMarshal(ev)
		if err != nil {
			return fmt.Errorf("marshal event for hash: %w", err)
		}
		cur = ChainHash(cur, ItemHash(b))
	}
	if cur != end {
		return fmt.Errorf("running hash mismatch: got %x want %x", cur, end[:])
	}
	return nil
}

func verifyRunningHashRecord(start, end [32]byte, items []*pb.RecordItem) error {
	cur := start
	for _, it := range items {
		b, err := deterministicMarshal(it)
		if err != nil {
			return fmt.Errorf("marshal record item for hash: %w", err)
		}
		cur = ChainHash(cur, ItemHash(b))
	}
	if cur != end {
		return fmt.Errorf("running hash mismatch: got %x want %x", cur, end[:])
	}
	return nil
}

func emptyHash() [32]byte {
	return sha256.Sum256([]byte{0x00})
}

func leafHash(item *pb.RecordItem) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	eh := item.EventHash
	if len(eh) != 32 {
		h.Write(eh)
	} else {
		h.Write(eh)
	}
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], item.TxIndex)
	h.Write(idx[:])
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(item.TxPayload)))
	h.Write(l[:])
	h.Write(item.TxPayload)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func internalHash(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x02})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func singletonHash(child [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(child[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func combineHash(left, right [32]byte) [32]byte {
	empty := emptyHash()
	leftEmpty := left == empty
	rightEmpty := right == empty
	switch {
	case leftEmpty && rightEmpty:
		return empty
	case leftEmpty && !rightEmpty:
		return singletonHash(right)
	case !leftEmpty && rightEmpty:
		return singletonHash(left)
	default:
		return internalHash(left, right)
	}
}

func ComputeRecordsRoot(items []*pb.RecordItem) [32]byte {
	if len(items) == 0 {
		return emptyHash()
	}
	leaves := make([][32]byte, len(items))
	for i, it := range items {
		leaves[i] = leafHash(it)
	}
	paddedLen := 1
	for paddedLen < len(leaves) {
		paddedLen <<= 1
	}
	for len(leaves) < paddedLen {
		leaves = append(leaves, emptyHash())
	}
	level := leaves
	for len(level) > 1 {
		next := make([][32]byte, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			next[i/2] = combineHash(level[i], level[i+1])
		}
		level = next
	}
	return level[0]
}

func VerifyRecordsProof(root [32]byte, item *pb.RecordItem, proof *pb.ProofEntry) bool {
	if proof == nil {
		return false
	}
	cur := leafHash(item)
	for _, step := range proof.ProofSteps {
		if len(step.SiblingHash) != 32 {
			return false
		}
		var sib [32]byte
		copy(sib[:], step.SiblingHash)
		if step.SiblingIsRight {
			cur = combineHash(cur, sib)
		} else {
			cur = combineHash(sib, cur)
		}
	}
	return cur == root
}

func ValidateStateDiffs(diffs []*pb.StateDiff) error {
	if len(diffs) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(diffs))
	var prev []byte
	for i, d := range diffs {
		if len(d.Key) == 0 {
			return fmt.Errorf("state_diff[%d] has empty key", i)
		}
		if _, dup := seen[string(d.Key)]; dup {
			return fmt.Errorf("state_diff duplicate key %x at index %d", d.Key, i)
		}
		seen[string(d.Key)] = struct{}{}
		if i > 0 && bytes.Compare(prev, d.Key) >= 0 {
			return fmt.Errorf("state_diffs not sorted at index %d", i)
		}
		prev = d.Key
	}
	return nil
}

func CheckpointSigningBytes(cp *pb.SignedCheckpoint) [136]byte {
	var out [136]byte
	binary.BigEndian.PutUint64(out[0:8], cp.Round)
	copy(out[8:40], cp.RecordsRoot)
	copy(out[40:72], cp.StateHash)
	copy(out[72:104], cp.RosterHash)
	copy(out[104:136], cp.PrevCheckpointHash)
	return out
}

func CheckpointSigningBytesHash(cp *pb.SignedCheckpoint) [32]byte {
	b := CheckpointSigningBytes(cp)
	return sha256.Sum256(b[:])
}

func VerifyPrevCheckpointHash(cur *pb.SignedCheckpoint, prev *pb.SignedCheckpoint) error {
	if cur == nil {
		return fmt.Errorf("nil checkpoint")
	}
	var expected [32]byte
	if prev == nil {
		expected = [32]byte{}
	} else {
		expected = CheckpointSigningBytesHash(prev)
	}
	if len(cur.PrevCheckpointHash) != 32 {
		if prev == nil && len(cur.PrevCheckpointHash) == 0 {
			return nil
		}
		return fmt.Errorf("prev_checkpoint_hash is %d bytes, want 32", len(cur.PrevCheckpointHash))
	}
	if !bytes.Equal(cur.PrevCheckpointHash, expected[:]) {
		return fmt.Errorf("prev_checkpoint_hash mismatch: expected %x got %x", expected, cur.PrevCheckpointHash)
	}
	return nil
}

func VerifyRecordsProofFile(proofFile *pb.RecordsProofFile, items []*pb.RecordItem, recordsRoot []byte) error {
	if proofFile == nil {
		return fmt.Errorf("nil proof file")
	}
	if proofFile.Version != Version {
		return fmt.Errorf("unsupported proof file version %d", proofFile.Version)
	}
	if len(recordsRoot) != 32 {
		return fmt.Errorf("recordsRoot is %d bytes, want 32", len(recordsRoot))
	}
	var root [32]byte
	copy(root[:], recordsRoot)
	if len(items) == 0 {
		if len(proofFile.Proofs) != 0 {
			return fmt.Errorf("empty items must have zero proofs, got %d", len(proofFile.Proofs))
		}
		return nil
	}
	if len(proofFile.Proofs) != len(items) {
		return fmt.Errorf("proof count %d != items count %d", len(proofFile.Proofs), len(items))
	}
	for i, entry := range proofFile.Proofs {
		if entry == nil {
			return fmt.Errorf("proof entry %d is nil", i)
		}
		if int(entry.ItemIndex) != i {
			return fmt.Errorf("proof entry %d has item_index %d", i, entry.ItemIndex)
		}
		for _, step := range entry.ProofSteps {
			if len(step.SiblingHash) != 32 {
				return fmt.Errorf("proof %d step sibling_hash is %d bytes, want 32", i, len(step.SiblingHash))
			}
		}
		if !VerifyRecordsProof(root, items[i], entry) {
			return fmt.Errorf("proof verification failed for item %d", i)
		}
	}
	return nil
}

func ReadAndVerifyRecordsProofFile(dir string, round uint64, items []*pb.RecordItem, recordsRoot []byte) error {
	path := filepath.Join(dir, RecordProofFileName(round))
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read proof sidecar %s: %w", path, err)
	}
	var pf pb.RecordsProofFile
	if err := unmarshalStrict(b, &pf); err != nil {
		return fmt.Errorf("unmarshal proof file %s: %w", path, err)
	}
	if pf.Round != round {
		return fmt.Errorf("proof file round %d != expected %d", pf.Round, round)
	}
	return VerifyRecordsProofFile(&pf, items, recordsRoot)
}

func VerifyRecordsProofFileBytes(b []byte, items []*pb.RecordItem, recordsRoot []byte, expectedRound uint64) error {
	var pf pb.RecordsProofFile
	if err := unmarshalStrict(b, &pf); err != nil {
		return fmt.Errorf("unmarshal proof file: %w", err)
	}
	if pf.Round != expectedRound {
		return fmt.Errorf("proof file round %d != expected %d", pf.Round, expectedRound)
	}
	return VerifyRecordsProofFile(&pf, items, recordsRoot)
}

func rosterCanonicalBytes(members []*pb.CheckpointRosterMember) ([]byte, error) {
	type entry struct {
		key    []byte
		blsKey []byte
	}
	mByID := make(map[uint64]entry, len(members))
	for _, m := range members {
		if len(m.Key) != 32 {
			return nil, fmt.Errorf("roster member %d has a %d-byte ed25519 key, want 32", m.NodeId, len(m.Key))
		}
		if len(m.BlsKey) != 48 {
			return nil, fmt.Errorf("roster member %d has a %d-byte bls_key, want 48", m.NodeId, len(m.BlsKey))
		}
		mByID[m.NodeId] = entry{key: m.Key, blsKey: m.BlsKey}
	}
	ids := make([]uint64, 0, len(mByID))
	for id := range mByID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	buf := make([]byte, 0, len(ids)*88)
	for _, id := range ids {
		e := mByID[id]
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], id)
		buf = append(buf, be[:]...)
		buf = append(buf, e.key...)
		buf = append(buf, e.blsKey...)
	}
	return buf, nil
}

func verifyCheckpointBinding(cp *pb.SignedCheckpoint, items []*pb.RecordItem, trustedRosterHash []byte) error {
	if len(cp.StateHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint state hash is %d bytes, want %d", len(cp.StateHash), hashLengthSHA256)
	}
	if len(cp.RosterHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint roster hash is %d bytes, want %d", len(cp.RosterHash), hashLengthSHA256)
	}
	if len(cp.RecordsRoot) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint records_root is %d bytes, want %d", len(cp.RecordsRoot), hashLengthSHA256)
	}
	if len(cp.PrevCheckpointHash) != 0 && len(cp.PrevCheckpointHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint prev_checkpoint_hash is %d bytes, want %d", len(cp.PrevCheckpointHash), hashLengthSHA256)
	}
	computed := ComputeRecordsRoot(items)
	if !bytes.Equal(computed[:], cp.RecordsRoot) {
		return fmt.Errorf("records_root mismatch: computed %x got %x", computed, cp.RecordsRoot)
	}
	return verifyCheckpointQuorum(cp, trustedRosterHash)
}

func verifyCheckpointQuorum(cp *pb.SignedCheckpoint, trustedRosterHash []byte) error {
	if len(cp.StateHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint state hash is %d bytes, want %d", len(cp.StateHash), hashLengthSHA256)
	}
	if len(cp.RosterHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint roster hash is %d bytes, want %d", len(cp.RosterHash), hashLengthSHA256)
	}
	if len(cp.RecordsRoot) != hashLengthSHA256 && len(cp.RecordsRoot) != 0 {
		return fmt.Errorf("checkpoint records_root is %d bytes, want %d", len(cp.RecordsRoot), hashLengthSHA256)
	}
	if len(cp.PrevCheckpointHash) != 0 && len(cp.PrevCheckpointHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint prev_checkpoint_hash is %d bytes, want %d", len(cp.PrevCheckpointHash), hashLengthSHA256)
	}
	rosterBytes, err := rosterCanonicalBytes(cp.RosterSnapshot)
	if err != nil {
		return err
	}
	rosterDigest := sha256.Sum256(rosterBytes)
	if !bytes.Equal(rosterDigest[:], cp.RosterHash) {
		return fmt.Errorf("embedded roster snapshot does not hash to roster_hash")
	}
	if len(trustedRosterHash) != 0 {
		if len(trustedRosterHash) != hashLengthSHA256 {
			return fmt.Errorf("trusted roster hash is %d bytes, want %d", len(trustedRosterHash), hashLengthSHA256)
		}
		if !bytes.Equal(cp.RosterHash, trustedRosterHash) {
			return fmt.Errorf("roster hash does not match trusted roster hash")
		}
	}
	if len(cp.AggregateSig) != 96 {
		return fmt.Errorf("checkpoint aggregate_sig is %d bytes, want 96", len(cp.AggregateSig))
	}
	signerSet := make(map[uint64]struct{}, len(cp.Signers))
	var distinct []uint64
	for _, s := range cp.Signers {
		if _, ok := signerSet[s]; ok {
			return fmt.Errorf("duplicate signer %d", s)
		}
		signerSet[s] = struct{}{}
		distinct = append(distinct, s)
	}
	total := len(cp.RosterSnapshot)
	{
		ids := make(map[uint64]struct{}, total)
		for _, m := range cp.RosterSnapshot {
			ids[m.NodeId] = struct{}{}
		}
		total = len(ids)
	}
	if total == 0 {
		return fmt.Errorf("empty roster snapshot")
	}
	if len(distinct)*3 <= total*2 {
		return fmt.Errorf("checkpoint quorum not met: %d valid of %d (need >2/3)", len(distinct), total)
	}
	keyByID := make(map[uint64][]byte, len(cp.RosterSnapshot))
	blsKeyByID := make(map[uint64][]byte, len(cp.RosterSnapshot))
	for _, m := range cp.RosterSnapshot {
		keyByID[m.NodeId] = m.Key
		blsKeyByID[m.NodeId] = m.BlsKey
	}
	for _, s := range distinct {
		if _, ok := keyByID[s]; !ok {
			return fmt.Errorf("signer %d not in roster snapshot", s)
		}
	}
	sort.Slice(distinct, func(i, j int) bool { return distinct[i] < distinct[j] })
	pks := make([]*blst.P1Affine, 0, len(distinct))
	for _, id := range distinct {
		blsBytes := blsKeyByID[id]
		pk := new(blst.P1Affine).Uncompress(blsBytes)
		if pk == nil {
			return fmt.Errorf("invalid bls_key for signer %d", id)
		}
		if !pk.KeyValidate() {
			return fmt.Errorf("bls_key for signer %d failed subgroup check", id)
		}
		pks = append(pks, pk)
	}
	sig := new(blst.P2Affine).Uncompress(cp.AggregateSig)
	if sig == nil {
		return fmt.Errorf("invalid aggregate_sig")
	}
	if !sig.SigValidate(false) {
		return fmt.Errorf("aggregate_sig failed signature validation")
	}
	var signingBytes [136]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], cp.Round)
	copy(signingBytes[8:40], cp.RecordsRoot)
	copy(signingBytes[40:72], cp.StateHash)
	copy(signingBytes[72:104], cp.RosterHash)
	if len(cp.PrevCheckpointHash) == 32 {
		copy(signingBytes[104:136], cp.PrevCheckpointHash)
	}
	if sig.FastAggregateVerify(false, pks, signingBytes[:], CheckpointDST) {
		return nil
	}
	if len(cp.PrevCheckpointHash) == 0 {
		var signingBytes104 [104]byte
		copy(signingBytes104[:], signingBytes[:104])
		if sig.FastAggregateVerify(false, pks, signingBytes104[:], CheckpointDST) {
			return nil
		}
	}
	return fmt.Errorf("BLS aggregate verification failed")
}
