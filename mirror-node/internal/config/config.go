package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all runtime configuration for the mirror node.
type Config struct {
	// StreamsDir is the directory watched for .esf / .rsf files.
	// Typically <consensus-data>/streams or a replicated copy.
	StreamsDir string `env:"MIRROR_STREAMS_DIR"`

	// DBPath is the mirror's local state (e.g. SQLite/Postgres DSN or directory).
	DBPath string `env:"MIRROR_DB_PATH"`

	// APIAddr is the HTTP API listen address, e.g. ":8080".
	APIAddr string `env:"MIRROR_API_ADDR"`

	// LogLevel controls structured logging: debug, info, warn, error.
	LogLevel string `env:"MIRROR_LOG_LEVEL"`

	// PubKeyHex is the Ed25519 verifying key (32 bytes, 64 hex chars) used
	// to verify .sig files. Required; fail-closed if absent or malformed.
	PubKeyHex string `env:"MIRRORD_PUBKEY"`

	// TrustedRosterHashHex is the 32-byte trusted roster hash (64 hex chars)
	// that anchors checkpoint quorum verification. Required; fail-closed if
	// absent. The embedded roster must hash to this value.
	TrustedRosterHashHex string `env:"MIRRORD_TRUSTED_ROSTER_HASH"`
}

// Default returns a Config with sensible local-dev defaults.
func Default() Config {
	return Config{
		StreamsDir: "./data/streams",
		DBPath:     "./data/mirror.db",
		APIAddr:    ":8080",
		LogLevel:   "info",
	}
}

// Load merges defaults, optional config file (not yet implemented), and
// environment variables. Environment wins.
func Load() (Config, error) {
	cfg := Default()

	if v := os.Getenv("MIRROR_STREAMS_DIR"); v != "" {
		cfg.StreamsDir = v
	}
	if v := os.Getenv("MIRROR_DB_PATH"); v != "" {
		cfg.DBPath = v
	}
	if v := os.Getenv("MIRROR_API_ADDR"); v != "" {
		cfg.APIAddr = v
	}
	if v := os.Getenv("MIRROR_LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := os.Getenv("MIRRORD_PUBKEY"); v != "" {
		cfg.PubKeyHex = strings.TrimSpace(v)
	} else if v := os.Getenv("MIRROR_PUBKEY"); v != "" {
		cfg.PubKeyHex = strings.TrimSpace(v)
	}
	if v := os.Getenv("MIRRORD_TRUSTED_ROSTER_HASH"); v != "" {
		cfg.TrustedRosterHashHex = strings.TrimSpace(v)
	} else if v := os.Getenv("MIRROR_TRUSTED_ROSTER_HASH"); v != "" {
		cfg.TrustedRosterHashHex = strings.TrimSpace(v)
	}

	// Allow CLI overrides via explicit env-like map passed through os.Args parsing
	// in cmd/mirrord; nothing more to do here.

	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks required fields.
func (c Config) Validate() error {
	if c.StreamsDir == "" {
		return fmt.Errorf("streams dir must not be empty")
	}
	if c.APIAddr == "" {
		return fmt.Errorf("api addr must not be empty")
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	if c.PubKeyHex == "" {
		return fmt.Errorf("pubkey must not be empty (set --pubkey / MIRRORD_PUBKEY as 64 hex chars)")
	}
	if _, err := c.PubKey(); err != nil {
		return err
	}
	if c.TrustedRosterHashHex == "" {
		return fmt.Errorf("trusted roster hash must not be empty (set --trusted-roster-hash / MIRRORD_TRUSTED_ROSTER_HASH as 64 hex chars)")
	}
	if _, err := c.TrustedRosterHash(); err != nil {
		return err
	}
	return nil
}

func decodeHex32Strict(s string, label string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return out, fmt.Errorf("%s must be 64 hex chars (32 bytes), got %d chars", label, len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("invalid %s hex: %w", label, err)
	}
	copy(out[:], b)
	return out, nil
}

func (c Config) PubKey() (ed25519.PublicKey, error) {
	h, err := decodeHex32Strict(c.PubKeyHex, "pubkey")
	if err != nil {
		return nil, err
	}
	return ed25519.PublicKey(h[:]), nil
}

func (c Config) TrustedRosterHash() ([32]byte, error) {
	return decodeHex32Strict(c.TrustedRosterHashHex, "trusted roster hash")
}

// Port returns the numeric port from APIAddr if parseable.
func (c Config) Port() (int, error) {
	// APIAddr is host:port – extract after last colon.
	for i := len(c.APIAddr) - 1; i >= 0; i-- {
		if c.APIAddr[i] == ':' {
			return strconv.Atoi(c.APIAddr[i+1:])
		}
	}
	return 0, fmt.Errorf("no port in %q", c.APIAddr)
}
