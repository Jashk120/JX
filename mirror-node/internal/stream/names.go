package stream

import "fmt"

const (
	Version              = 1
	StreamsSubdir        = "streams"
	DefaultEventsPerFile = 10000

	EventFilePrefix = "events-"
	EventFileSuffix = ".esf"
	EventSigSuffix  = ".esf_sig"

	RecordFilePrefix = "round-"
	RecordFileSuffix = ".rsf"
	RecordSigSuffix  = ".rsf_sig"

	EventFileIndexWidth = 8
)

// EventFileName returns the n-th event file name, zero-padded.
func EventFileName(index uint64) string {
	return fmt.Sprintf("%s%0*d%s", EventFilePrefix, EventFileIndexWidth, index, EventFileSuffix)
}

// RecordFileName returns the record file name for a round.
func RecordFileName(round uint64) string {
	return fmt.Sprintf("%s%d%s", RecordFilePrefix, round, RecordFileSuffix)
}

// EventFileIndex extracts the numeric index from an event file name; ok is
// false for names that are not event stream files. Inverse of EventFileName.
func EventFileIndex(name string) (index uint64, ok bool) {
	return streamIndex(name, EventFilePrefix, EventFileSuffix)
}

// RecordFileRound extracts the round from a record file name; ok is false for
// names that are not record stream files. Inverse of RecordFileName.
func RecordFileRound(name string) (round uint64, ok bool) {
	return streamIndex(name, RecordFilePrefix, RecordFileSuffix)
}

// SignatureFileName returns the companion .sig name for a stream file.
// Mirrors consensus-node/protocol/stream/src/lib.rs:signature_file_name —
// unknown names fall back to the record signature suffix.
func SignatureFileName(streamFileName string) string {
	switch {
	case len(streamFileName) > len(EventFileSuffix) && streamFileName[len(streamFileName)-len(EventFileSuffix):] == EventFileSuffix:
		return streamFileName[:len(streamFileName)-len(EventFileSuffix)] + EventSigSuffix
	case len(streamFileName) > len(RecordFileSuffix) && streamFileName[len(streamFileName)-len(RecordFileSuffix):] == RecordFileSuffix:
		return streamFileName[:len(streamFileName)-len(RecordFileSuffix)] + RecordSigSuffix
	default:
		return streamFileName + RecordSigSuffix
	}
}
