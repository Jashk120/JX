package stream

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// VerifyEventFile checks a single .esf's integrity:
//   - start/end running hashes chain correctly over the contained events,
//   - file signature and metadata signature (if a sig is provided) verify.
func VerifyEventFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
	var esf pb.EventStreamFile
	if err := proto.Unmarshal(fileBytes, &esf); err != nil {
		return fmt.Errorf("unmarshal EventStreamFile: %w", err)
	}
	if esf.Version != Version {
		return fmt.Errorf("unsupported version %d", esf.Version)
	}
	if esf.StartRunningHash == nil || esf.EndRunningHash == nil {
		return fmt.Errorf("missing running hash")
	}
	if err := verifyRunningHashEvent(&esf); err != nil {
		return err
	}
	if sig != nil {
		if err := verifySignatureFile(fileBytes, &esf, sig, pubKey); err != nil {
			return err
		}
	}
	return nil
}

// VerifyRecordFile checks a single .rsf: running hash + optional sig + quorum.
func VerifyRecordFile(fileBytes []byte, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
	var rsf pb.RecordStreamFile
	if err := proto.Unmarshal(fileBytes, &rsf); err != nil {
		return fmt.Errorf("unmarshal RecordStreamFile: %w", err)
	}
	if rsf.Version != Version {
		return fmt.Errorf("unsupported version %d", rsf.Version)
	}
	if rsf.StartRunningHash == nil || rsf.EndRunningHash == nil {
		return fmt.Errorf("missing running hash")
	}
	if err := verifyRunningHashRecord(&rsf); err != nil {
		return err
	}
	if sig != nil {
		if err := verifySignatureFileRecord(fileBytes, &rsf, sig, pubKey); err != nil {
			return err
		}
	}
	if rsf.Checkpoint != nil {
		if err := verifyCheckpointQuorum(rsf.Checkpoint); err != nil {
			return err
		}
	}
	return nil
}

func verifyRunningHashEvent(esf *pb.EventStreamFile) error {
	var cur [32]byte
	copy(cur[:], esf.StartRunningHash.Hash)
	for _, ev := range esf.Events {
		b, err := proto.Marshal(ev)
		if err != nil {
			return fmt.Errorf("marshal event for hash: %w", err)
		}
		ih := ItemHash(b)
		cur = ChainHash(cur, ih)
	}
	if !bytes.Equal(cur[:], esf.EndRunningHash.Hash) {
		return fmt.Errorf("running hash mismatch: got %x want %x", cur, esf.EndRunningHash.Hash)
	}
	return nil
}

func verifyRunningHashRecord(rsf *pb.RecordStreamFile) error {
	var cur [32]byte
	copy(cur[:], rsf.StartRunningHash.Hash)
	for _, it := range rsf.Items {
		b, err := proto.Marshal(it)
		if err != nil {
			return fmt.Errorf("marshal record item for hash: %w", err)
		}
		ih := ItemHash(b)
		cur = ChainHash(cur, ih)
	}
	if !bytes.Equal(cur[:], rsf.EndRunningHash.Hash) {
		return fmt.Errorf("running hash mismatch: got %x want %x", cur, rsf.EndRunningHash.Hash)
	}
	return nil
}

func verifySignatureFile(fileBytes []byte, esf *pb.EventStreamFile, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
	// File signature: Ed25519 over SHA-256 of whole file bytes.
	h := sha256.Sum256(fileBytes)
	if sig.FileSignature == nil || sig.FileSignature.HashObject == nil {
		return fmt.Errorf("missing file signature")
	}
	if !bytes.Equal(h[:], sig.FileSignature.HashObject.Hash) {
		return fmt.Errorf("file hash mismatch in signature file")
	}
	if !ed25519.Verify(pubKey, h[:], sig.FileSignature.Signature) {
		return fmt.Errorf("file signature invalid")
	}
	// Metadata signature: hash of (version || start || end) – mirror the Rust verifier's
	// metadata commitment shape. We hash the concatenation of the three hashes.
	metaH := metadataHashEvent(esf)
	if sig.MetadataSignature == nil || sig.MetadataSignature.HashObject == nil {
		return fmt.Errorf("missing metadata signature")
	}
	if !bytes.Equal(metaH[:], sig.MetadataSignature.HashObject.Hash) {
		return fmt.Errorf("metadata hash mismatch")
	}
	if !ed25519.Verify(pubKey, metaH[:], sig.MetadataSignature.Signature) {
		return fmt.Errorf("metadata signature invalid")
	}
	return nil
}

func verifySignatureFileRecord(fileBytes []byte, rsf *pb.RecordStreamFile, sig *pb.SignatureFile, pubKey ed25519.PublicKey) error {
	h := sha256.Sum256(fileBytes)
	if sig.FileSignature == nil || sig.FileSignature.HashObject == nil {
		return fmt.Errorf("missing file signature")
	}
	if !bytes.Equal(h[:], sig.FileSignature.HashObject.Hash) {
		return fmt.Errorf("file hash mismatch in signature file")
	}
	if !ed25519.Verify(pubKey, h[:], sig.FileSignature.Signature) {
		return fmt.Errorf("file signature invalid")
	}
	metaH := metadataHashRecord(rsf)
	if sig.MetadataSignature == nil || sig.MetadataSignature.HashObject == nil {
		return fmt.Errorf("missing metadata signature")
	}
	if !bytes.Equal(metaH[:], sig.MetadataSignature.HashObject.Hash) {
		return fmt.Errorf("metadata hash mismatch")
	}
	if !ed25519.Verify(pubKey, metaH[:], sig.MetadataSignature.Signature) {
		return fmt.Errorf("metadata signature invalid")
	}
	return nil
}

func metadataHashEvent(esf *pb.EventStreamFile) [32]byte {
	h := sha256.New()
	// Simple deterministic commitment: version BE + start_hash + end_hash.
	var ver [4]byte
	ver[0] = byte(esf.Version >> 24)
	ver[1] = byte(esf.Version >> 16)
	ver[2] = byte(esf.Version >> 8)
	ver[3] = byte(esf.Version)
	h.Write(ver[:])
	if esf.StartRunningHash != nil {
		h.Write(esf.StartRunningHash.Hash)
	}
	if esf.EndRunningHash != nil {
		h.Write(esf.EndRunningHash.Hash)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func metadataHashRecord(rsf *pb.RecordStreamFile) [32]byte {
	h := sha256.New()
	var ver [4]byte
	ver[0] = byte(rsf.Version >> 24)
	ver[1] = byte(rsf.Version >> 16)
	ver[2] = byte(rsf.Version >> 8)
	ver[3] = byte(rsf.Version)
	h.Write(ver[:])
	if rsf.StartRunningHash != nil {
		h.Write(rsf.StartRunningHash.Hash)
	}
	if rsf.EndRunningHash != nil {
		h.Write(rsf.EndRunningHash.Hash)
	}
	var round [8]byte
	round[0] = byte(rsf.Round >> 56)
	round[1] = byte(rsf.Round >> 48)
	round[2] = byte(rsf.Round >> 40)
	round[3] = byte(rsf.Round >> 32)
	round[4] = byte(rsf.Round >> 24)
	round[5] = byte(rsf.Round >> 16)
	round[6] = byte(rsf.Round >> 8)
	round[7] = byte(rsf.Round)
	h.Write(round[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// verifyCheckpointQuorum enforces valid*3 > total*2 over the embedded roster.
func verifyCheckpointQuorum(cp *pb.SignedCheckpoint) error {
	total := len(cp.RosterSnapshot)
	if total == 0 {
		return fmt.Errorf("empty roster snapshot")
	}
	// Count valid Ed25519 signatures over (round || state_hash) – simplified check:
	// each sig must be 64 bytes and verify against the roster entry's key.
	valid := 0
	keyByID := make(map[uint64]ed25519.PublicKey, total)
	for _, m := range cp.RosterSnapshot {
		keyByID[m.NodeId] = ed25519.PublicKey(m.Key)
	}
	// Message signed is round (8BE) || state_hash.
	msg := make([]byte, 8+len(cp.StateHash))
	msg[0] = byte(cp.Round >> 56)
	msg[1] = byte(cp.Round >> 48)
	msg[2] = byte(cp.Round >> 40)
	msg[3] = byte(cp.Round >> 32)
	msg[4] = byte(cp.Round >> 24)
	msg[5] = byte(cp.Round >> 16)
	msg[6] = byte(cp.Round >> 8)
	msg[7] = byte(cp.Round)
	copy(msg[8:], cp.StateHash)
	for _, s := range cp.Sigs {
		pk, ok := keyByID[s.Signer]
		if !ok {
			continue
		}
		if len(s.Sig) != ed25519.SignatureSize {
			continue
		}
		if ed25519.Verify(pk, msg, s.Sig) {
			valid++
		}
	}
	if valid*3 <= total*2 {
		return fmt.Errorf("checkpoint quorum not met: %d valid of %d (need >2/3)", valid, total)
	}
	return nil
}
