package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

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
		streamsDir = flag.String("streams", "", "streams directory (overrides MIRROR_STREAMS_DIR)")
		dbPath     = flag.String("db", "", "mirror db path (overrides MIRROR_DB_PATH)")
		addr       = flag.String("addr", "", "API listen addr (overrides MIRROR_API_ADDR)")
		showVer    = flag.Bool("version", false, "print version and exit")
	)
	flag.Parse()

	if *showVer {
		fmt.Printf("mirrord %s\n", version)
		os.Exit(0)
	}

	cfg, err := config.Load()
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
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid config: %v\n", err)
		os.Exit(1)
	}

	level := parseLevel(cfg.LogLevel)
	h := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(h)

	h.Info("starting mirrord", "version", version, "streamsDir", cfg.StreamsDir, "apiAddr", cfg.APIAddr)

	// Store: in-memory for now; swap for persistent backend when available.
	st := store.NewMemStore()

	ing := ingest.New(ingest.Config{
		StreamsDir: cfg.StreamsDir,
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
	_ = srv.Shutdown(context.Background())
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
