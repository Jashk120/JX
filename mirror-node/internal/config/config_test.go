package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
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

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "mirror.toml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing temp config: %v", err)
	}
	return path
}

const (
	testPubKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testHash   = "112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00"
)

func TestLoadFullTOMLFile(t *testing.T) {
	path := writeTempConfig(t, `
streams_dir = "./custom/streams"
db_path = "postgres://mirror:mirror@localhost:5432/mirror?sslmode=disable"
api_addr = ":9090"
log_level = "debug"
pubkey = "`+testPubKey+`"
trusted_roster_hash = "`+testHash+`"
block_node_url = "http://block-node:8080"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.StreamsDir != "./custom/streams" {
		t.Errorf("StreamsDir = %q", cfg.StreamsDir)
	}
	if cfg.DBPath != "postgres://mirror:mirror@localhost:5432/mirror?sslmode=disable" {
		t.Errorf("DBPath = %q", cfg.DBPath)
	}
	if cfg.APIAddr != ":9090" {
		t.Errorf("APIAddr = %q", cfg.APIAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q", cfg.LogLevel)
	}
	if cfg.PubKeyHex != testPubKey {
		t.Errorf("PubKeyHex = %q", cfg.PubKeyHex)
	}
	if cfg.TrustedRosterHashHex != testHash {
		t.Errorf("TrustedRosterHashHex = %q", cfg.TrustedRosterHashHex)
	}
	if cfg.BlockNodeURL != "http://block-node:8080" {
		t.Errorf("BlockNodeURL = %q", cfg.BlockNodeURL)
	}
}

func TestLoadPartialTOMLKeepsDefaults(t *testing.T) {
	path := writeTempConfig(t, `
pubkey = "`+testPubKey+`"
trusted_roster_hash = "`+testHash+`"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	def := Default()
	if cfg.StreamsDir != def.StreamsDir {
		t.Errorf("StreamsDir = %q, want default %q", cfg.StreamsDir, def.StreamsDir)
	}
	if cfg.DBPath != def.DBPath {
		t.Errorf("DBPath = %q, want default %q", cfg.DBPath, def.DBPath)
	}
	if cfg.APIAddr != def.APIAddr {
		t.Errorf("APIAddr = %q, want default %q", cfg.APIAddr, def.APIAddr)
	}
	if cfg.LogLevel != def.LogLevel {
		t.Errorf("LogLevel = %q, want default %q", cfg.LogLevel, def.LogLevel)
	}
}

func TestLoadMissingFileErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "absent.toml")); err == nil {
		t.Fatal("expected error loading missing file")
	}
}

func TestLoadOptionalMissingFileReturnsDefaults(t *testing.T) {
	// Defaults are fail-closed: no file means no pubkey, so LoadOptional
	// returns defaults-shaped validation errors, exactly like running
	// with no configuration at all.
	_, err := LoadOptional(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("expected validation error for missing required keys")
	}
}

func TestLoadInvalidTOMLErrors(t *testing.T) {
	path := writeTempConfig(t, "not [valid toml ===")
	if _, err := Load(path); err == nil {
		t.Fatal("expected error parsing invalid TOML")
	}
}

func TestEnvOverridesTOMLDBPath(t *testing.T) {
	path := writeTempConfig(t, `
db_path = "./from-file.db"
pubkey = "`+testPubKey+`"
trusted_roster_hash = "`+testHash+`"
`)
	const envDSN = "postgres://mirror:secret@localhost:5432/mirror?sslmode=disable"
	t.Setenv(EnvDBPath, envDSN)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DBPath != envDSN {
		t.Errorf("DBPath = %q, want env override %q", cfg.DBPath, envDSN)
	}
}

func TestFileConfigRoundTrip(t *testing.T) {
	fc := FileConfig{
		StreamsDir:           "./data/streams",
		DBPath:               "./data/mirror.db",
		APIAddr:              ":8080",
		LogLevel:             "info",
		PubKeyHex:            testPubKey,
		TrustedRosterHashHex: testHash,
		BlockNodeURL:         "",
	}
	var out FileConfig
	b, err := toml.Marshal(fc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := toml.Decode(string(b), &out); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out != fc {
		t.Fatalf("round trip mismatch: %+v != %+v", out, fc)
	}
}
