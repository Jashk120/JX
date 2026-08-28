package stream

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

type goldenFile struct {
	RecordsRootVectors  []recordVector  `json:"records_root_vectors"`
	SigningBytesVectors []signingVector `json:"signing_bytes_vectors"`
	DiffEncodingVectors []diffVector    `json:"diff_encoding_vectors"`
}
type recordVector struct {
	Name            string           `json:"name"`
	Items           []recordItemJSON `json:"items"`
	ExpectedRootHex string           `json:"expected_root_hex"`
}
type recordItemJSON struct {
	EventHashHex string `json:"event_hash_hex"`
	TxIndex      uint32 `json:"tx_index"`
	TxPayloadHex string `json:"tx_payload_hex"`
}
type signingVector struct {
	Name                    string `json:"name"`
	Round                   uint64 `json:"round"`
	RecordsRootHex          string `json:"records_root_hex"`
	StateHashHex            string `json:"state_hash_hex"`
	RosterHashHex           string `json:"roster_hash_hex"`
	PrevCheckpointHashHex   string `json:"prev_checkpoint_hash_hex"`
	ExpectedSigningBytesHex string `json:"expected_signing_bytes_hex"`
}
type diffVector struct {
	Name  string      `json:"name"`
	Diffs []diffEntry `json:"diffs"`
}
type diffEntry struct {
	KeyHex   string  `json:"key_hex"`
	ValueHex *string `json:"value_hex"`
	ProtoHex string  `json:"proto_hex"`
}

func loadGolden(t *testing.T) goldenFile {
	t.Helper()
	path := filepath.Join("testdata", "plan2_golden.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden json: %v", err)
	}
	var g goldenFile
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("unmarshal golden json: %v", err)
	}
	return g
}

func mustDecodeHex(t *testing.T, s string) []byte {
	t.Helper()
	if s == "" {
		return []byte{}
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex decode %q: %v", s, err)
	}
	return b
}
func mustDecodeHex32(t *testing.T, s string) [32]byte {
	t.Helper()
	b := mustDecodeHex(t, s)
	if len(b) != 32 {
		t.Fatalf("hex %q is %d bytes, want 32", s, len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out
}

func TestGoldenRecordsRoot(t *testing.T) {
	g := loadGolden(t)
	if len(g.RecordsRootVectors) < 6 {
		t.Fatalf("need at least 6 records_root vectors, got %d", len(g.RecordsRootVectors))
	}
	hasThree := false
	for _, v := range g.RecordsRootVectors {
		if len(v.Items) == 3 {
			hasThree = true
		}
	}
	if !hasThree {
		t.Fatal("need at least one 3-item vector to exercise padding/singleton")
	}
	for _, vec := range g.RecordsRootVectors {
		var items []*pb.RecordItem
		for _, it := range vec.Items {
			eh := mustDecodeHex(t, it.EventHashHex)
			if len(eh) != 32 {
				t.Fatalf("vector %q bad event_hash len %d", vec.Name, len(eh))
			}
			payload := mustDecodeHex(t, it.TxPayloadHex)
			items = append(items, &pb.RecordItem{
				EventHash: eh,
				TxIndex:   it.TxIndex,
				TxPayload: payload,
			})
		}
		root := ComputeRecordsRoot(items)
		exp := mustDecodeHex32(t, vec.ExpectedRootHex)
		if root != exp {
			t.Fatalf("records_root mismatch vector %q (%d items): got %x want %x", vec.Name, len(items), root, exp)
		}
		if vec.Name == "empty_0" {
			empty := emptyHash()
			if root != empty {
				t.Fatalf("empty root vector %q: got %x want empty %x", vec.Name, root, empty)
			}
		}
	}
}

func TestGoldenSigningBytes(t *testing.T) {
	g := loadGolden(t)
	if len(g.SigningBytesVectors) < 5 {
		t.Fatalf("need at least 5 signing_bytes vectors, got %d", len(g.SigningBytesVectors))
	}
	hasGenesis := false
	hasChained := false
	zeros := "0000000000000000000000000000000000000000000000000000000000000000"
	for _, v := range g.SigningBytesVectors {
		if v.PrevCheckpointHashHex == zeros {
			hasGenesis = true
		} else {
			hasChained = true
		}
	}
	if !hasGenesis {
		t.Fatal("need at least one genesis (prev zeros) vector")
	}
	if !hasChained {
		t.Fatal("need at least one chained non-zero prev vector")
	}
	for _, vec := range g.SigningBytesVectors {
		rr := mustDecodeHex(t, vec.RecordsRootHex)
		sh := mustDecodeHex(t, vec.StateHashHex)
		rh := mustDecodeHex(t, vec.RosterHashHex)
		prev := mustDecodeHex(t, vec.PrevCheckpointHashHex)
		for _, p := range []struct {
			name string
			b    []byte
		}{{"rr", rr}, {"sh", sh}, {"rh", rh}, {"prev", prev}} {
			if len(p.b) != 32 {
				t.Fatalf("vector %q %s len %d want 32", vec.Name, p.name, len(p.b))
			}
		}
		cp := &pb.SignedCheckpoint{
			Round:              vec.Round,
			RecordsRoot:        rr,
			StateHash:          sh,
			RosterHash:         rh,
			PrevCheckpointHash: prev,
		}
		signing := CheckpointSigningBytes(cp)
		if len(signing) != 136 {
			t.Fatalf("vector %q signing len %d want 136", vec.Name, len(signing))
		}
		exp := mustDecodeHex(t, vec.ExpectedSigningBytesHex)
		if len(exp) != 136 {
			t.Fatalf("vector %q expected len %d want 136", vec.Name, len(exp))
		}
		if string(signing[:]) != string(exp) {
			t.Fatalf("signing_bytes mismatch vector %q:\n got %x\nwant %x", vec.Name, signing, exp)
		}
		// Also verify that the bytes are exactly round||rr||sh||rh||prev.
		var manual [136]byte
		manual[0] = byte(vec.Round >> 56)
		manual[1] = byte(vec.Round >> 48)
		manual[2] = byte(vec.Round >> 40)
		manual[3] = byte(vec.Round >> 32)
		manual[4] = byte(vec.Round >> 24)
		manual[5] = byte(vec.Round >> 16)
		manual[6] = byte(vec.Round >> 8)
		manual[7] = byte(vec.Round)
		copy(manual[8:40], rr)
		copy(manual[40:72], sh)
		copy(manual[72:104], rh)
		copy(manual[104:136], prev)
		if signing != manual {
			t.Fatalf("vector %q manual 136B mismatch", vec.Name)
		}
	}
}

func TestGoldenDiffEncoding(t *testing.T) {
	g := loadGolden(t)
	if len(g.DiffEncodingVectors) < 5 {
		t.Fatalf("need at least 5 diff vectors, got %d", len(g.DiffEncodingVectors))
	}
	for _, vec := range g.DiffEncodingVectors {
		// Sorted check and proto hex equality.
		var prev []byte
		var diffs []*pb.StateDiff
		for i, e := range vec.Diffs {
			key := mustDecodeHex(t, e.KeyHex)
			if len(key) == 0 {
				t.Fatalf("vector %q entry %d has empty key", vec.Name, i)
			}
			if i > 0 && string(prev) >= string(key) {
				t.Fatalf("vector %q not sorted at index %d: prev %x >= key %x", vec.Name, i, prev, key)
			}
			prev = key
			var val []byte
			if e.ValueHex != nil {
				v := mustDecodeHex(t, *e.ValueHex)
				val = v
			} else {
				val = nil
			}
			d := &pb.StateDiff{Key: key}
			// Set Value presence: nil means tombstone (absent), non-nil means present.
			// For Go protobuf with optional bytes as oneof, we set Value to val and preserve presence via proto field.
			if e.ValueHex != nil {
				// non-nil even if empty slice
				if val == nil {
					val = []byte{}
				}
				d.Value = val
			} else {
				d.Value = nil
			}
			// Marshal deterministic and compare to expected hex.
			b, err := proto.MarshalOptions{Deterministic: true}.Marshal(d)
			if err != nil {
				t.Fatalf("vector %q marshal diff %d: %v", vec.Name, i, err)
			}
			exp := mustDecodeHex(t, e.ProtoHex)
			if string(b) != string(exp) {
				t.Fatalf("diff proto mismatch vector %q key %x:\n got %x\nwant %x", vec.Name, key, b, exp)
			}
			// Decode back and check tombstone vs value.
			var decoded pb.StateDiff
			if err := proto.Unmarshal(b, &decoded); err != nil {
				t.Fatalf("vector %q unmarshal diff %d: %v", vec.Name, i, err)
			}
			if string(decoded.Key) != string(key) {
				t.Fatalf("vector %q decoded key mismatch", vec.Name)
			}
			if e.ValueHex == nil {
				// Tombstone: value should be absent (nil or empty with no presence).
				// Use proto presence check via reflection: Value == nil or len==0 with no presence both decode to nil.
				// For determinism, we check that GetValue is empty and proto has no presence.
				if decoded.Value != nil && len(decoded.Value) != 0 {
					t.Fatalf("vector %q expected tombstone nil value, got %x", vec.Name, decoded.Value)
				}
				// Ensure the re-marshaled tombstone still matches expected (no value field).
				if len(b) != len(exp) {
					t.Fatalf("vector %q tombstone encoding length mismatch", vec.Name)
				}
			} else {
				expVal := mustDecodeHex(t, *e.ValueHex)
				if string(decoded.Value) != string(expVal) {
					t.Fatalf("vector %q value mismatch: got %x want %x", vec.Name, decoded.Value, expVal)
				}
			}
			diffs = append(diffs, d)
		}
		// Whole-vector ValidateStateDiffs and sorted check via Go helper.
		if err := ValidateStateDiffs(diffs); err != nil {
			t.Fatalf("vector %q ValidateStateDiffs failed: %v", vec.Name, err)
		}
		// Also verify that encoding each diff individually and round-tripping preserves sorted order.
		if vec.Name == "empty" && len(vec.Diffs) != 0 {
			t.Fatalf("vector empty should have no diffs")
		}
		// Cross-check that Go's sorted order matches Rust's (lexicographic bytes.Compare).
		keys := make([][]byte, len(diffs))
		for i, d := range diffs {
			keys[i] = d.Key
		}
		sorted := make([][]byte, len(keys))
		copy(sorted, keys)
		sort.Slice(sorted, func(i, j int) bool { return string(sorted[i]) < string(sorted[j]) })
		for i := range keys {
			if string(keys[i]) != string(sorted[i]) {
				t.Fatalf("vector %q keys not sorted", vec.Name)
			}
		}
	}
}

func TestGoldenDiffTombstoneVsEmptyValue(t *testing.T) {
	tomb := &pb.StateDiff{Key: []byte("k"), Value: nil}
	emptyVal := &pb.StateDiff{Key: []byte("k"), Value: []byte{}}
	// Tombstone should marshal without value field; empty value includes 0x12 0x00.
	tombBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(tomb)
	emptyBytes, _ := proto.MarshalOptions{Deterministic: true}.Marshal(emptyVal)
	if string(tombBytes) == string(emptyBytes) {
		t.Fatal("tombstone vs empty value must have different protobuf bytes")
	}
	// Expected encodings: tomb "0a016b", empty "0a016b1200"
	if hex.EncodeToString(tombBytes) != "0a016b" {
		t.Fatalf("tombstone encoding got %x want 0a016b", tombBytes)
	}
	if hex.EncodeToString(emptyBytes) != "0a016b1200" {
		t.Fatalf("empty value encoding got %x want 0a016b1200", emptyBytes)
	}
}

func TestGoldenDiffRejectsUnsortedOrDuplicate(t *testing.T) {
	// Unsorted should fail ValidateStateDiffs.
	unsorted := []*pb.StateDiff{
		{Key: []byte("b"), Value: []byte("1")},
		{Key: []byte("a"), Value: []byte("2")},
	}
	if err := ValidateStateDiffs(unsorted); err == nil {
		t.Fatal("unsorted diffs should fail validation")
	}
	dup := []*pb.StateDiff{
		{Key: []byte("a"), Value: []byte("1")},
		{Key: []byte("a"), Value: []byte("2")},
	}
	if err := ValidateStateDiffs(dup); err == nil {
		t.Fatal("duplicate keys should fail validation")
	}
	emptyKey := []*pb.StateDiff{
		{Key: []byte{}, Value: []byte("1")},
	}
	if err := ValidateStateDiffs(emptyKey); err == nil {
		t.Fatal("empty key should fail validation")
	}
}
