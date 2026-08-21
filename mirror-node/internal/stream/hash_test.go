package stream

import (
	"testing"
)

func TestChainIsDeterministicAndOrderDependent(t *testing.T) {
	a := ItemHash([]byte("alpha"))
	b := ItemHash([]byte("beta"))
	ab := ChainHash(ChainSeed, a)
	ab2 := ChainHash(ChainSeed, a)
	ba := ChainHash(ChainSeed, b)
	if ab != ab2 {
		t.Fatal("chain not deterministic")
	}
	if ab == ba {
		t.Fatal("order must matter")
	}
	forward := ChainHash(ab, b)
	backward := ChainHash(ba, a)
	if forward == backward {
		t.Fatal("forward vs backward must differ")
	}
}

func TestItemAndChainDomainSeparated(t *testing.T) {
	if ItemHash([]byte("x")) == ItemHash([]byte("y")) {
		t.Fatal("distinct payloads must differ")
	}
	payload := ItemHash([]byte("payload"))
	chained := ChainHash(ChainSeed, payload)
	if payload == chained {
		t.Fatal("item vs chain domain must differ")
	}
}

func TestFileNaming(t *testing.T) {
	if got := EventFileName(0); got != "events-00000000.esf" {
		t.Fatalf("got %q", got)
	}
	if got := EventFileName(42); got != "events-00000042.esf" {
		t.Fatalf("got %q", got)
	}
	if got := RecordFileName(7); got != "round-7.rsf" {
		t.Fatalf("got %q", got)
	}
	if got := SignatureFileName("round-7.rsf"); got != "round-7.rsf_sig" {
		t.Fatalf("got %q", got)
	}
	if got := SignatureFileName("events-00000042.esf"); got != "events-00000042.esf_sig" {
		t.Fatalf("got %q", got)
	}
}
