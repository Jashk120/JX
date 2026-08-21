package stream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

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

// VerifyEventFile checks a single .esf's integrity:
//   - start/end running hashes chain correctly over the contained events,
//   - file signature and metadata signature (if a sig is provided) verify.
//
// Signature verification runs only when both sig and pubKey are non-nil;
// structural and chain checks always run.
func VerifyEventFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
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
	if sig != nil && pubKey != nil {
		metadata := metadataBytes(esf.Version, start, end, 0, false)
		return verifySignatureObjects(sig, fileBytes, metadata, pubKey)
	}
	return nil
}

// VerifyRecordFile checks a single .rsf: running hash + the embedded
// checkpoint anchor (round consistency + quorum) + optional sig. Mirrors
// consensus-node/protocol/stream/src/verify.rs — every record file must carry
// its threshold-signed checkpoint.
func VerifyRecordFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
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
	if err := verifyCheckpointQuorum(rsf.Checkpoint); err != nil {
		return err
	}
	if sig != nil && pubKey != nil {
		metadata := metadataBytes(rsf.Version, start, end, rsf.Round, true)
		return verifySignatureObjects(sig, fileBytes, metadata, pubKey)
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

// rosterCanonicalBytes serializes the checkpoint's roster snapshot the way
// crypto/src/membership.rs:to_bytes does: unique members (last registration
// wins), sorted by node id, each as node_id (8 BE) || key (32).
func rosterCanonicalBytes(members []*pb.CheckpointRosterMember) ([]byte, error) {
	keyByID := make(map[uint64][]byte, len(members))
	for _, m := range members {
		if len(m.Key) != hashLengthSHA256 {
			return nil, fmt.Errorf("roster member %d has a %d-byte key, want %d",
				m.NodeId, len(m.Key), hashLengthSHA256)
		}
		keyByID[m.NodeId] = m.Key
	}
	ids := make([]uint64, 0, len(keyByID))
	for id := range keyByID {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	buf := make([]byte, 0, len(ids)*40)
	for _, id := range ids {
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], id)
		buf = append(buf, be[:]...)
		buf = append(buf, keyByID[id]...)
	}
	return buf, nil
}

// verifyCheckpointQuorum enforces the full mirror-side quorum proof:
//   - state_hash and roster_hash are 32 bytes,
//   - the embedded roster snapshot hashes (canonical form) to roster_hash,
//   - every distinct, round-matching Ed25519 signature verifies over
//     round (8 BE) || state_hash || roster_hash — checkpoint.rs:signing_bytes,
//   - valid*3 > total*2 decides.
func verifyCheckpointQuorum(cp *pb.SignedCheckpoint) error {
	if len(cp.StateHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint state hash is %d bytes, want %d", len(cp.StateHash), hashLengthSHA256)
	}
	if len(cp.RosterHash) != hashLengthSHA256 {
		return fmt.Errorf("checkpoint roster hash is %d bytes, want %d", len(cp.RosterHash), hashLengthSHA256)
	}
	rosterBytes, err := rosterCanonicalBytes(cp.RosterSnapshot)
	if err != nil {
		return err
	}
	rosterDigest := sha256.Sum256(rosterBytes)
	if !bytes.Equal(rosterDigest[:], cp.RosterHash) {
		return fmt.Errorf("embedded roster snapshot does not hash to roster_hash")
	}
	total := len(cp.RosterSnapshot)
	if total == 0 {
		return fmt.Errorf("empty roster snapshot")
	}
	keyByID := make(map[uint64]ed25519.PublicKey, total)
	for _, m := range cp.RosterSnapshot {
		keyByID[m.NodeId] = ed25519.PublicKey(m.Key)
	}
	signingBytes := make([]byte, 0, 72)
	var roundBE [8]byte
	binary.BigEndian.PutUint64(roundBE[:], cp.Round)
	signingBytes = append(signingBytes, roundBE[:]...)
	signingBytes = append(signingBytes, cp.StateHash...)
	signingBytes = append(signingBytes, cp.RosterHash...)
	valid := 0
	seen := make(map[uint64]bool, total)
	for _, s := range cp.Sigs {
		if s.Round != cp.Round {
			continue
		}
		if seen[s.Signer] {
			continue
		}
		pk, ok := keyByID[s.Signer]
		if !ok {
			continue
		}
		if len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pk, signingBytes, s.Sig) {
			valid++
			seen[s.Signer] = true
		}
	}
	if valid*3 <= total*2 {
		return fmt.Errorf("checkpoint quorum not met: %d valid of %d (need >2/3)", valid, total)
	}
	return nil
}
