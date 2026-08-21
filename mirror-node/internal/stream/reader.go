package stream

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// SigFileVersion is the single version byte prefixing every signature file,
// mirroring consensus-node/protocol/stream/src/signature.rs:SIG_FILE_VERSION.
const SigFileVersion = 1

// unmarshalStrict decodes b into m, rejecting unknown fields and trailing
// bytes. prost tolerates trailing bytes; a mirror must not (the Rust readers
// enforce the same rule via encoded_len comparison).
func unmarshalStrict(b []byte, m proto.Message) error {
	opts := proto.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(b, m); err != nil {
		return err
	}
	if proto.Size(m) != len(b) {
		return fmt.Errorf("message has %d trailing or unknown bytes (%d decoded)", len(b)-proto.Size(m), proto.Size(m))
	}
	return nil
}

// ReadEventFile reads and unmarshals an .esf file at path.
func ReadEventFile(path string) (*pb.EventStreamFile, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f pb.EventStreamFile
	if err := unmarshalStrict(b, &f); err != nil {
		return nil, nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &f, b, nil
}

// ReadRecordFile reads and unmarshals a .rsf file at path.
func ReadRecordFile(path string) (*pb.RecordStreamFile, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f pb.RecordStreamFile
	if err := unmarshalStrict(b, &f); err != nil {
		return nil, nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &f, b, nil
}

// streamIndex extracts the numeric index between prefix and suffix in name.
func streamIndex(name, prefix, suffix string) (uint64, bool) {
	rest, ok := strings.CutPrefix(name, prefix)
	if !ok {
		return 0, false
	}
	mid, ok := strings.CutSuffix(rest, suffix)
	if !ok {
		return 0, false
	}
	index, err := strconv.ParseUint(mid, 10, 64)
	if err != nil {
		return 0, false
	}
	return index, true
}

// listStreamFiles returns the paths of numbered stream files in dir,
// ascending by numeric index. Only names whose index parses as u64 are
// included, matching consensus-node/protocol/stream event_files_in /
// record_files_in.
func listStreamFiles(dir, prefix, suffix string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	type indexed struct {
		index uint64
		path  string
	}
	var files []indexed
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if index, ok := streamIndex(e.Name(), prefix, suffix); ok {
			files = append(files, indexed{index, filepath.Join(dir, e.Name())})
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i].index < files[j].index })
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.path
	}
	return out, nil
}

// ListEventFiles returns sorted .esf paths in dir.
func ListEventFiles(dir string) ([]string, error) {
	return listStreamFiles(dir, EventFilePrefix, EventFileSuffix)
}

// ListRecordFiles returns sorted .rsf paths in dir.
func ListRecordFiles(dir string) ([]string, error) {
	return listStreamFiles(dir, RecordFilePrefix, RecordFileSuffix)
}

// ReadSignatureFile reads a .esf_sig / .rsf_sig companion. The on-disk layout
// is [SigFileVersion byte][protobuf SignatureFile], as written by the Rust
// writer; both signature objects must carry their hash objects.
func ReadSignatureFile(path string) (*pb.SignatureFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, fmt.Errorf("signature file %s is empty", path)
	}
	if b[0] != SigFileVersion {
		return nil, fmt.Errorf("unsupported signature file version %d in %s", b[0], path)
	}
	var sf pb.SignatureFile
	if err := unmarshalStrict(b[1:], &sf); err != nil {
		return nil, fmt.Errorf("unmarshal sig %s: %w", path, err)
	}
	if sf.FileSignature == nil || sf.FileSignature.HashObject == nil ||
		sf.MetadataSignature == nil || sf.MetadataSignature.HashObject == nil {
		return nil, fmt.Errorf("signature file %s is missing a signature or its hash object", path)
	}
	return &sf, nil
}
