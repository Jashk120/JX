// Package ingest watches a consensus streams directory and feeds verified
// files into a Store. It is intentionally simple: poll + verify + store.
package ingest

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/JKaIN/mirror-node/internal/store"
	"github.com/JKaIN/mirror-node/internal/stream"
)

// Config controls the ingester.
type Config struct {
	StreamsDir   string
	PollInterval time.Duration
	// PubKey is the consensus node's Ed25519 verifying key used to check
	// .sig files. If nil, signature verification is skipped (useful for tests).
	PubKey ed25519.PublicKey
}

// Ingester polls the streams directory and ingests new files.
type Ingester struct {
	cfg   Config
	store store.Store
	log   *slog.Logger
}

func New(cfg Config, st store.Store, log *slog.Logger) *Ingester {
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 500 * time.Millisecond
	}
	if log == nil {
		log = slog.Default()
	}
	return &Ingester{cfg: cfg, store: st, log: log}
}

// RunOnce scans the streams directory and ingests any new files.
// It is idempotent; already-seen rounds/files are skipped by the store layer
// (or by tracking highest seen index – here we simply attempt to ingest and
// let failures be logged).
func (ing *Ingester) RunOnce(ctx context.Context) error {
	dir := ing.cfg.StreamsDir

	// Record files.
	rsfPaths, err := stream.ListRecordFiles(dir)
	if err != nil {
		if os.IsNotExist(err) {
			ing.log.Info("streams dir not yet present", "dir", dir)
			return nil
		}
		return fmt.Errorf("list record files: %w", err)
	}
	for _, p := range rsfPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ing.ingestRecord(p); err != nil {
			ing.log.Warn("record ingest failed", "path", p, "err", err)
		}
	}

	// Event files.
	esfPaths, err := stream.ListEventFiles(dir)
	if err != nil {
		return fmt.Errorf("list event files: %w", err)
	}
	for _, p := range esfPaths {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if err := ing.ingestEvent(p); err != nil {
			ing.log.Warn("event ingest failed", "path", p, "err", err)
		}
	}
	return nil
}

// Run polls until ctx is cancelled.
func (ing *Ingester) Run(ctx context.Context) error {
	ticker := time.NewTicker(ing.cfg.PollInterval)
	defer ticker.Stop()
	if err := ing.RunOnce(ctx); err != nil {
		ing.log.Error("initial ingest failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := ing.RunOnce(ctx); err != nil {
				ing.log.Error("ingest tick failed", "err", err)
			}
		}
	}
}

func (ing *Ingester) ingestRecord(path string) error {
	f, raw, err := stream.ReadRecordFile(path)
	if err != nil {
		return err
	}
	// Try to load companion sig.
	sigPath := filepath.Join(filepath.Dir(path), stream.SignatureFileName(filepath.Base(path)))
	sig, err := stream.ReadSignatureFile(sigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read sig %s: %w", sigPath, err)
	}
	if sig != nil && ing.cfg.PubKey != nil {
		if err := stream.VerifyRecordFile(raw, sig, ing.cfg.PubKey); err != nil {
			return fmt.Errorf("verify record %s: %w", path, err)
		}
	} else if ing.cfg.PubKey != nil {
		// Still verify running hash + quorum without sig.
		if err := stream.VerifyRecordFile(raw, nil, nil); err != nil {
			return err
		}
	}
	if err := ing.store.PutRecord(f); err != nil {
		return err
	}
	ing.log.Info("ingested record file", "path", path, "round", f.Round, "items", len(f.Items))
	return nil
}

func (ing *Ingester) ingestEvent(path string) error {
	f, raw, err := stream.ReadEventFile(path)
	if err != nil {
		return err
	}
	sigPath := filepath.Join(filepath.Dir(path), stream.SignatureFileName(filepath.Base(path)))
	sig, err := stream.ReadSignatureFile(sigPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read sig %s: %w", sigPath, err)
	}
	if sig != nil && ing.cfg.PubKey != nil {
		if err := stream.VerifyEventFile(raw, sig, ing.cfg.PubKey); err != nil {
			return fmt.Errorf("verify event %s: %w", path, err)
		}
	} else if ing.cfg.PubKey != nil {
		if err := stream.VerifyEventFile(raw, nil, nil); err != nil {
			return err
		}
	}
	if err := ing.store.PutEvents(f); err != nil {
		return err
	}
	ing.log.Info("ingested event file", "path", path, "events", len(f.Events))
	return nil
}
