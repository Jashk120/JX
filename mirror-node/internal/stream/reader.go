package stream

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	"github.com/JKaIN/mirror-node/internal/stream/pb"
)

// ReadEventFile reads and unmarshals an .esf file at path.
func ReadEventFile(path string) (*pb.EventStreamFile, []byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var f pb.EventStreamFile
	if err := proto.Unmarshal(b, &f); err != nil {
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
	if err := proto.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return &f, b, nil
}

// ListEventFiles returns sorted .esf paths in dir.
func ListEventFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), EventFilePrefix) && strings.HasSuffix(e.Name(), EventFileSuffix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// ListRecordFiles returns sorted .rsf paths in dir.
func ListRecordFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), RecordFilePrefix) && strings.HasSuffix(e.Name(), RecordFileSuffix) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// ReadSignatureFile reads a .esf_sig / .rsf_sig companion.
func ReadSignatureFile(path string) (*pb.SignatureFile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var sf pb.SignatureFile
	if err := proto.Unmarshal(b, &sf); err != nil {
		return nil, fmt.Errorf("unmarshal sig %s: %w", path, err)
	}
	return &sf, nil
}
