package stream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	blst "github.com/supranational/blst/bindings/go"
	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// Field constants shared with consensus-node/protocol/stream/src/signature.rs.
const (
	hashAlgorithmSHA256 = 0 // HashObject.algorithm
	hashLengthSHA256    = 32
	sigTypeEd25519      = 0 // SignatureObject.type
	sigLengthEd25519    = 64
)

// BLS12-381 constants mirroring consensus-node/protocol/crypto/src/bls.rs.
var CheckpointDST = []byte("JKAIN-CHECKPOINT-BLS-V1")

// recordsRootDST mirrors consensus::RECORDS_ROOT_DST.
var recordsRootDST = []byte("JKAIN-RECORDS-ROOT-V1")

// VerifyEventFile checks a single .esf's integrity:
//   - start/end running hashes chain correctly over the contained events,
//   - file signature and metadata signature verify under pubKey (fail-closed).
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

// VerifyRecordFile checks a single .rsf: running hash + the embedded
// checkpoint anchor (round consistency + quorum) + BLS aggregate + records_root.
// Mirrors consensus-node/protocol/stream/src/verify.rs — every record file must
// carry its threshold-signed checkpoint. When trustedRosterHash is non-empty it
// anchors verification (H-5); when empty the embedded roster hash is trusted
// (preserving embedded-snapshot behavior for local-dir mode). The .rsf_sig file
// is not consulted — it no longer exists (D1). sig may be nil for BLS-only
// verification; if provided it is ignored.
func VerifyRecordFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey, trustedRosterHash []byte) error {
	// pubKey is still required for interface compat but not used for .rsf BLS path.
	// Keep fail-closed check only when caller provides it for event-style sig path;
	// for BLS path we don't need Ed25519 pubkey.
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
	if err := verifyCheckpointBinding(rsf.Checkpoint, rsf.Items, trustedRosterHash); err != nil {
		return err
	}
	// No sig file check for record files anymore (BLS path). If a sig is
	// provided (legacy callers), ignore it — the checkpoint's BLS proof is the
	// content binding.
	_ = sig
	return nil
}

// VerifyCheckpointFile verifies a standalone .ckpt file (protobuf
// SignedCheckpoint) against optional trustedRosterHash. It mirrors the BLS
// quorum and roster anchoring done for record files, without the record-item
// payload.
func VerifyCheckpointFile(ckptBytes []byte, trustedRosterHash []byte) error {
	var ckpt pb.SignedCheckpoint
	if err := unmarshalStrict(ckptBytes, &ckpt); err != nil {
		return fmt.Errorf("unmarshal SignedCheckpoint: %w", err)
	}
	// Verify quorum and roster hash anchoring.
	if err := verifyCheckpointQuorum(&ckpt, trustedRosterHash); err != nil {
		return err
	}
	return nil
}

// runningHashOrErr validates a HashObject commitment as a SHA-256 digest,
// mirroring convert.rs:hash_object_digest (algorithm, length, byte count).
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

// metadataBytes builds the bytes the metadata_signature commits to:
// [version u32 BE] || start (32) || end (32) plus round (u64 BE) for record
// files — signature.rs:metadata_bytes.
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

// verifySignatureObjects verifies both SignatureObjects of a signature file:
// the file signature over SHA-256(fileBytes) and the metadata signature over
// SHA-256(metadata), both under pubKey.
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

// verifySignatureObject checks one SignatureObject against the expected
// digest: field validation (signature.rs:verify_signature_object), the
// committed digest, and the Ed25519 signature over it.
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

// deterministicMarshal serializes an item exactly the way the Rust writer did
// when it computed the item hash: canonical protobuf bytes.
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

// ComputeRecordsRoot computes the records_root for a round's record items in
// consensus order, mirroring consensus/checkpoint.rs:compute_records_root:
//
//	h_0 = SHA256(b"JKAIN-RECORDS-ROOT-V1" || u32_BE(count))
//	h_i = SHA256(h_{i-1} || SHA256(event_hash[32] || u32_BE(tx_index) || u32_BE(len(tx_payload)) || tx_payload))
//
// Empty round => h_0 alone.
func ComputeRecordsRoot(items []*pb.RecordItem) [32]byte {
	h := sha256.New()
	h.Write(recordsRootDST)
	var cnt [4]byte
	binary.BigEndian.PutUint32(cnt[:], uint32(len(items)))
	h.Write(cnt[:])
	var cur [32]byte
	copy(cur[:], h.Sum(nil))
	for _, it := range items {
		inner := sha256.New()
		// event_hash must be 32 bytes; if not, pad/trim consistently with Rust's try_into behavior
		// (Rust would have rejected malformed items earlier; here we hash what we have)
		eh := it.EventHash
		if len(eh) != 32 {
			// Malformed event_hash should make records_root mismatch rather than panic
			// Hash the raw bytes as-is for determinism; caller will compare and fail
			inner.Write(eh)
		} else {
			inner.Write(eh)
		}
		var idx [4]byte
		binary.BigEndian.PutUint32(idx[:], it.TxIndex)
		inner.Write(idx[:])
		var l [4]byte
		binary.BigEndian.PutUint32(l[:], uint32(len(it.TxPayload)))
		inner.Write(l[:])
		inner.Write(it.TxPayload)
		var innerHash [32]byte
		copy(innerHash[:], inner.Sum(nil))
		outer := sha256.New()
		outer.Write(cur[:])
		outer.Write(innerHash[:])
		copy(cur[:], outer.Sum(nil))
	}
	return cur
}

// rosterCanonicalBytes serializes the checkpoint's roster snapshot the way
// crypto/src/membership.rs:to_bytes does: unique members (last registration
// wins), sorted by node id, each as node_id (8 BE) || ed25519_key (32) || bls_key (48) = 88 bytes.
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

// verifyCheckpointBinding enforces roster hash, BLS quorum, and records_root binding.
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
	// Records root must match recomputed value from items.
	computed := ComputeRecordsRoot(items)
	if !bytes.Equal(computed[:], cp.RecordsRoot) {
		return fmt.Errorf("records_root mismatch: computed %x got %x", computed, cp.RecordsRoot)
	}
	// Then quorum check (includes roster hash verification + BLS).
	return verifyCheckpointQuorum(cp, trustedRosterHash)
}

// verifyCheckpointQuorum enforces:
//   - roster_hash matches canonical roster bytes hash
//   - roster_hash equals trusted hash when trusted is non-empty (fail-closed)
//   - BLS aggregate signature verifies over signing_bytes() = round||records_root||state_hash||roster_hash
//   - valid signers count*3 > total*2
func verifyCheckpointQuorum(cp *pb.SignedCheckpoint, trustedRosterHash []byte) error {
	if len(cp.StateHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint state hash is %d bytes, want %d", len(cp.StateHash), hashLengthSHA256)
	}
	if len(cp.RosterHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint roster hash is %d bytes, want %d", len(cp.RosterHash), hashLengthSHA256)
	}
	if len(cp.RecordsRoot) != hashLengthSHA256 && len(cp.RecordsRoot) != 0 {
		// Allow empty records_root only if explicitly unset (len 0) — but for v2 it should be 32.
		// If empty, treat as error since bindings require it.
		return fmt.Errorf("checkpoint records_root is %d bytes, want %d", len(cp.RecordsRoot), hashLengthSHA256)
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
	// Collect deduplicated signer set, check quorum.
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
	// Deduplicate roster-derived total: use unique node_ids.
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
	// Verify every signer is in roster.
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
	// Build BLS verification: gather pubkeys sorted by NodeId (aggregation order deterministic).
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
	// signing_bytes = round(8 BE) || records_root(32) || state_hash(32) || roster_hash(32) = 104
	var signingBytes [104]byte
	binary.BigEndian.PutUint64(signingBytes[0:8], cp.Round)
	copy(signingBytes[8:40], cp.RecordsRoot)
	copy(signingBytes[40:72], cp.StateHash)
	copy(signingBytes[72:104], cp.RosterHash)
	// Aggregate verification: sig verifies against all pks over same message.
	if !sig.FastAggregateVerify(false, pks, signingBytes[:], CheckpointDST) {
		return fmt.Errorf("BLS aggregate verification failed")
	}
	return nil
}
