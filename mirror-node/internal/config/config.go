package config

import (
	"fmt"
	"os"
	"strconv"
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
	return nil
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
