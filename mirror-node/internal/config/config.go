package config

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// DefaultPath is the config file used when --config is not passed.
const DefaultPath = "./mirror.toml"

// Config holds all runtime configuration for the mirror node.
type Config struct {
	// StreamsDir is the directory watched for .esf / .rsf files.
	// Typically <consensus-data>/streams or a replicated copy.
	StreamsDir string

	// DBPath is the mirror's local state (e.g. SQLite/Postgres DSN or directory).
	DBPath string

	// APIAddr is the HTTP API listen address, e.g. ":8080".
	APIAddr string

	// LogLevel controls structured logging: debug, info, warn, error.
	LogLevel string

	// PubKeyHex is the Ed25519 verifying key (32 bytes, 64 hex chars) used
	// to verify .sig files. Required; fail-closed if absent or malformed.
	PubKeyHex string

	// TrustedRosterHashHex is the 32-byte trusted roster hash (64 hex chars)
	// that anchors checkpoint quorum verification. Required; fail-closed if
	// absent. The embedded roster must hash to this value.
	TrustedRosterHashHex string

	// BlockNodeURL is the remote block-node HTTP base URL (e.g.
	// "http://block-node:8080"). When empty the mirror polls the local
	// StreamsDir. When set the mirror polls the block node instead.
	BlockNodeURL string
}

// FileConfig mirrors the TOML file layout (see mirror.toml.example).
type FileConfig struct {
	StreamsDir           string `toml:"streams_dir"`
	DBPath               string `toml:"db_path"`
	APIAddr              string `toml:"api_addr"`
	LogLevel             string `toml:"log_level"`
	PubKeyHex            string `toml:"pubkey"`
	TrustedRosterHashHex string `toml:"trusted_roster_hash"`
	BlockNodeURL         string `toml:"block_node_url"`
}

// EnvDBPath overrides the TOML db_path value. Database DSNs carry
// credentials, so they may live in the environment (or a gitignored .env)
// instead of mirror.toml.
const EnvDBPath = "MIRROR_DB_PATH"

// Default returns a Config with sensible local-dev defaults.
func Default() Config {
	return Config{
		StreamsDir: "./data/streams",
		DBPath:     "./data/mirror.db",
		APIAddr:    ":8080",
		LogLevel:   "info",
	}
}

// Load reads path as TOML and merges it over the defaults, then applies the
// MIRROR_DB_PATH environment override. The file must exist and parse; use
// LoadOptional for the implicit default path.
func Load(path string) (Config, error) {
	var fc FileConfig
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := Default()
	cfg.applyFile(fc)
	applyDBPathEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// LoadOptional behaves like Load but treats a missing file at path as "no
// overrides" and returns the defaults.
func LoadOptional(path string) (Config, error) {
	var fc FileConfig
	if _, err := toml.DecodeFile(path, &fc); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			cfg := Default()
			applyDBPathEnv(&cfg)
			if err := cfg.Validate(); err != nil {
				return Config{}, err
			}
			return cfg, nil
		}
		return Config{}, fmt.Errorf("reading config %s: %w", path, err)
	}
	cfg := Default()
	cfg.applyFile(fc)
	applyDBPathEnv(&cfg)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// applyFile overlays non-empty file values onto c.
func (c *Config) applyFile(fc FileConfig) {
	if v := strings.TrimSpace(fc.StreamsDir); v != "" {
		c.StreamsDir = v
	}
	if v := strings.TrimSpace(fc.DBPath); v != "" {
		c.DBPath = v
	}
	if v := strings.TrimSpace(fc.APIAddr); v != "" {
		c.APIAddr = v
	}
	if v := strings.TrimSpace(fc.LogLevel); v != "" {
		c.LogLevel = v
	}
	if v := strings.TrimSpace(fc.PubKeyHex); v != "" {
		c.PubKeyHex = v
	}
	if v := strings.TrimSpace(fc.TrustedRosterHashHex); v != "" {
		c.TrustedRosterHashHex = v
	}
	if v := strings.TrimSpace(fc.BlockNodeURL); v != "" {
		c.BlockNodeURL = v
	}
}

// applyDBPathEnv overlays EnvDBPath onto c; empty means unset.
func applyDBPathEnv(c *Config) {
	if v := strings.TrimSpace(os.Getenv(EnvDBPath)); v != "" {
		c.DBPath = v
	}
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
		return fmt.Errorf("pubkey must not be empty (set --pubkey or pubkey in mirror.toml, 64 hex chars)")
	}
	if _, err := c.PubKey(); err != nil {
		return err
	}
	if c.TrustedRosterHashHex == "" {
		return fmt.Errorf("trusted roster hash must not be empty (set --trusted-roster-hash or trusted_roster_hash in mirror.toml, 64 hex chars)")
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
