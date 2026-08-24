package config

import (
	"testing"
)

func TestValidateFailsClosedWithoutPubKeyOrTrustedHash(t *testing.T) {
	cfg := Default()
	cfg.PubKeyHex = ""
	cfg.TrustedRosterHashHex = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with missing pubkey")
	}
	cfg.PubKeyHex = "00"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with short pubkey hex")
	}
	// 64 hex chars but invalid hex
	cfg.PubKeyHex = "zz0000000000000000000000000000000000000000000000000000000000000000"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with non-hex pubkey")
	}
	// valid pubkey but missing trusted
	cfg.PubKeyHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	cfg.TrustedRosterHashHex = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error with missing trusted hash")
	}
	cfg.TrustedRosterHashHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid config should pass: %v", err)
	}
	// PubKey parsing
	if _, err := cfg.PubKey(); err != nil {
		t.Fatalf("PubKey parse: %v", err)
	}
	if _, err := cfg.TrustedRosterHash(); err != nil {
		t.Fatalf("TrustedRosterHash parse: %v", err)
	}
}

func TestDecodeHex32Strict(t *testing.T) {
	if _, err := decodeHex32Strict("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "test"); err != nil {
		t.Fatalf("valid hex should pass: %v", err)
	}
	if _, err := decodeHex32Strict("00112233", "test"); err == nil {
		t.Fatal("short hex should fail")
	}
	if _, err := decodeHex32Strict("zz112233445566778899aabbccddeeff00112233445566778899aabbccddeeff", "test"); err == nil {
		t.Fatal("non-hex should fail")
	}
	if _, err := decodeHex32Strict("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00", "test"); err == nil {
		t.Fatal("long hex should fail")
	}
}
