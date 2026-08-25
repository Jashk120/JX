package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/JKaIN/mirror-node/internal/api"
	"github.com/JKaIN/mirror-node/internal/config"
	"github.com/JKaIN/mirror-node/internal/ingest"
	"github.com/JKaIN/mirror-node/internal/store"
)

var (
	version = "dev"
)

func main() {
	var (
		configFlag       = flag.String("config", "", "TOML config file; defaults to ./mirror.toml when present")
		streamsDir       = flag.String("streams", "", "streams directory (overrides mirror.toml)")
		dbPath           = flag.String("db", "", "mirror db path or postgres:// DSN (overrides MIRROR_DB_PATH and mirror.toml)")
		addr             = flag.String("addr", "", "API listen addr (overrides mirror.toml)")
		pubkeyFlag       = flag.String("pubkey", "", "Ed25519 verifying key hex 64 chars (overrides mirror.toml)")
		trustedHashFlag  = flag.String("trusted-roster-hash", "", "trusted roster hash hex 64 chars (overrides mirror.toml)")
		blockNodeURLFlag = flag.String("block-node-url", "", "block node base URL (overrides mirror.toml)")
		showVer          = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("mirrord %s\n", version)
		os.Exit(0)
	}

	_ = config.LoadDotEnv("./.env")

	var (
		cfg config.Config
		err error
	)
	if *configFlag != "" {
		cfg, err = config.Load(*configFlag)
	} else {
		cfg, err = config.LoadOptional(config.DefaultPath)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}
	if *streamsDir != "" {
		cfg.StreamsDir = *streamsDir
	}
	if *dbPath != "" {
		cfg.DBPath = *dbPath
	}
	if *addr != "" {
		cfg.APIAddr = *addr
	}
	if *pubkeyFlag != "" {
		cfg.PubKeyHex = *pubkeyFlag
	}
	if *trustedHashFlag != "" {
		cfg.TrustedRosterHashHex = *trustedHashFlag
	}
	if *blockNodeURLFlag != "" {
		cfg.BlockNodeURL = *blockNodeURLFlag
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	level := parseLevel(cfg.LogLevel)
	h := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(h)

	h.Info("starting mirrord", "version", version, "streamsDir", cfg.StreamsDir, "apiAddr", cfg.APIAddr)

	pubKey, err := cfg.PubKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pubkey: %v\n", err)
		os.Exit(1)
	}
	trustedHash, err := cfg.TrustedRosterHash()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid trusted roster hash: %v\n", err)
		os.Exit(1)
	}
	trustedBytes := trustedHash[:]

	// Store: in-memory by default. A --db / db_path value starting with
	// postgres:// (or postgresql://) selects the persistent backend.
	var st store.Store = store.NewMemStore()
	if strings.HasPrefix(cfg.DBPath, "postgres://") || strings.HasPrefix(cfg.DBPath, "postgresql://") {
		pgCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		pgst, err := store.NewPostgresStore(pgCtx, cfg.DBPath)
		cancel()
		if err != nil {
			h.Error("postgres store init failed", "err", err)
			os.Exit(1)
		}
		defer pgst.Close()
		st = pgst
		h.Info("using postgresql store")
	}

	ing := ingest.New(ingest.Config{
		StreamsDir:        cfg.StreamsDir,
		PubKey:            pubKey,
		TrustedRosterHash: trustedBytes,
		BlockNodeURL:      cfg.BlockNodeURL,
	}, st, h)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Start ingester in background.
	go func() {
		if err := ing.Run(ctx); err != nil && err != context.Canceled {
			h.Error("ingester stopped", "err", err)
			stop()
		}
	}()

	// API server.
	srv := &http.Server{
		Addr:    cfg.APIAddr,
		Handler: api.New(st, h).Handler(),
	}
	go func() {
		h.Info("api listening", "addr", cfg.APIAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			h.Error("api server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	h.Info("shutting down")
	ctxShutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctxShutdown)
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
