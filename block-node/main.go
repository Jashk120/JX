package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const defaultMaxUploadBytes int64 = 256 << 20

func validName(name string) bool {
	if name == "" {
		return false
	}
	if strings.Contains(name, "/") {
		return false
	}
	if strings.Contains(name, "\\") {
		return false
	}
	if name == ".." {
		return false
	}
	if strings.Contains(name, "..") {
		return false
	}
	return true
}

func newHandler(dataDir string, maxUploadBytes int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		escaped := r.URL.EscapedPath()

		// List route: GET /v1/blocks (exact)
		if escaped == "/v1/blocks" {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			entries, err := os.ReadDir(dataDir)
			if err != nil {
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				n := e.Name()
				// Hide temp files created during atomic writes.
				if strings.HasPrefix(n, ".tmp-") {
					continue
				}
				// Only expose valid names; skip stray files with invalid names.
				if !validName(n) {
					continue
				}
				names = append(names, n)
			}
			sort.Strings(names)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			for _, n := range names {
				_, _ = io.WriteString(w, n+"\n")
			}
			return
		}

		// Block routes: /v1/blocks/{name}
		if strings.HasPrefix(escaped, "/v1/blocks/") {
			encodedName := strings.TrimPrefix(escaped, "/v1/blocks/")
			// Reject empty segment or extra slashes (e.g. trailing slash or nested path).
			// encodedName still encoded; a literal "/" indicates multi-segment path.
			if encodedName == "" {
				http.Error(w, "invalid block name", http.StatusBadRequest)
				return
			}
			if strings.Contains(encodedName, "/") {
				http.Error(w, "invalid block name", http.StatusBadRequest)
				return
			}
			decodedName, err := url.PathUnescape(encodedName)
			if err != nil {
				http.Error(w, "invalid block name", http.StatusBadRequest)
				return
			}
			if !validName(decodedName) {
				http.Error(w, "invalid block name", http.StatusBadRequest)
				return
			}
			// At this point encodedName has no "/" but decodedName might
			// contain "/" from %2F — validName already covers it, but double-check
			// encoded slash that was decoded.
			if strings.Contains(decodedName, "/") {
				http.Error(w, "invalid block name", http.StatusBadRequest)
				return
			}

			switch r.Method {
			case http.MethodPut:
				handlePut(w, r, dataDir, decodedName, maxUploadBytes)
			case http.MethodGet:
				handleGet(w, r, dataDir, decodedName)
			case http.MethodHead:
				handleHead(w, r, dataDir, decodedName)
			default:
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			}
			return
		}

		http.NotFound(w, r)
	})
}

func handlePut(w http.ResponseWriter, r *http.Request, dataDir, name string, maxUploadBytes int64) {
	path := filepath.Join(dataDir, name)

	// Bound the request body to prevent unbounded disk exhaustion.
	r.Body = http.MaxBytesReader(w, r.Body, maxUploadBytes)
	if r.ContentLength > maxUploadBytes {
		http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
		return
	}

	// Idempotent: if file already exists, do not rewrite.
	if _, err := os.Stat(path); err == nil {
		// Drain body to reuse connection.
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
				return
			}
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	} else if !os.IsNotExist(err) {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Atomic write via temp file + rename.
	tmp, err := os.CreateTemp(dataDir, ".tmp-*")
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	tmpName := tmp.Name()
	// Ensure cleanup on failure.
	success := false
	defer func() {
		_ = tmp.Close()
		if !success {
			_ = os.Remove(tmpName)
		}
	}()

	if _, err := io.Copy(tmp, r.Body); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, "request entity too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := tmp.Close(); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// tmp is closed; need to reopen check for existence again to preserve
	// idempotency under race: if file appeared while we were writing temp,
	// discard temp and return 200 without overwriting.
	if _, err := os.Stat(path); err == nil {
		_ = os.Remove(tmpName)
		w.WriteHeader(http.StatusOK)
		success = true // temp already removed
		return
	}
	if err := os.Rename(tmpName, path); err != nil {
		// If rename fails because target exists (unlikely on POSIX), treat as success.
		if _, statErr := os.Stat(path); statErr == nil {
			_ = os.Remove(tmpName)
			w.WriteHeader(http.StatusOK)
			success = true
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	success = true
	w.WriteHeader(http.StatusOK)
}

func handleGet(w http.ResponseWriter, _ *http.Request, dataDir, name string) {
	path := filepath.Join(dataDir, name)
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	w.Header().Set("Content-Length", itoa(fi.Size()))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func handleHead(w http.ResponseWriter, _ *http.Request, dataDir, name string) {
	path := filepath.Join(dataDir, name)
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if fi.IsDir() {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Length", itoa(fi.Size()))
	w.WriteHeader(http.StatusOK)
}

func itoa(n int64) string {
	return fmt.Sprintf("%d", n)
}

func main() {
	dataDir := os.Getenv("BLOCK_NODE_DATA_DIR")
	listenAddr := os.Getenv("BLOCK_NODE_LISTEN_ADDR")
	if dataDir == "" {
		log.Fatal("BLOCK_NODE_DATA_DIR is required")
	}
	if listenAddr == "" {
		log.Fatal("BLOCK_NODE_LISTEN_ADDR is required")
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		log.Fatalf("mkdir data dir: %v", err)
	}
	maxUploadBytes := defaultMaxUploadBytes
	if v := os.Getenv("BLOCK_NODE_MAX_UPLOAD_BYTES"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n <= 0 {
			log.Fatalf("invalid BLOCK_NODE_MAX_UPLOAD_BYTES %q: must be a positive integer", v)
		}
		maxUploadBytes = n
	}
	handler := newHandler(dataDir, maxUploadBytes)
	log.Printf("block-node listening on %s dataDir=%s", listenAddr, dataDir)
	if err := http.ListenAndServe(listenAddr, handler); err != nil {
		log.Fatalf("listen: %v", err)
	}
}
