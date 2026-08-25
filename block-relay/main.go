package main

import (
	"bytes"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultPollMS = 500
)

var allowedSuffixes = []string{".esf", ".rsf", ".esf_sig", ".ckpt"}

func isAllowed(name string) bool {
	for _, s := range allowedSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// pushOnce scans dir for allowed regular files not in seen, HEAD-checks
// each against baseURL/v1/blocks/<escaped-name> and PUTs if missing.
// seen is updated for every file that is either already present on the
// remote (HEAD 200) or successfully PUT. Errors are logged and returned
// as the last encountered error (but processing continues for all files).
func pushOnce(dir string, seen map[string]bool, client *http.Client, baseURL string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Printf("error reading streams dir %s: %v", dir, err)
		return err
	}
	var lastErr error
	base := strings.TrimRight(baseURL, "/")
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !isAllowed(name) {
			continue
		}
		if seen[name] {
			log.Printf("skipped %s (seen)", name)
			continue
		}
		// Verify regular file (not symlink to dir etc.)
		info, err := e.Info()
		if err != nil {
			log.Printf("error stating %s: %v", name, err)
			lastErr = err
			continue
		}
		if !info.Mode().IsRegular() {
			continue
		}

		escaped := url.PathEscape(name)
		targetURL := base + "/v1/blocks/" + escaped

		// HEAD check
		req, err := http.NewRequest(http.MethodHead, targetURL, nil) //nolint:noctx
		if err != nil {
			log.Printf("error building HEAD for %s: %v", name, err)
			lastErr = err
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("error HEAD %s: %v", name, err)
			lastErr = err
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			log.Printf("skipped %s (remote has it)", name)
			seen[name] = true
			continue
		}

		// Read file bytes
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			log.Printf("error reading %s: %v", name, err)
			lastErr = err
			continue
		}

		req2, err := http.NewRequest(http.MethodPut, targetURL, bytes.NewReader(data)) //nolint:noctx
		if err != nil {
			log.Printf("error building PUT for %s: %v", name, err)
			lastErr = err
			continue
		}
		req2.Header.Set("Content-Type", "application/octet-stream")
		resp2, err := client.Do(req2)
		if err != nil {
			log.Printf("error PUT %s: %v", name, err)
			lastErr = err
			continue
		}
		_ = resp2.Body.Close()
		if resp2.StatusCode != http.StatusOK && resp2.StatusCode != http.StatusCreated && resp2.StatusCode != http.StatusNoContent {
			log.Printf("error PUT %s: status %d", name, resp2.StatusCode)
			lastErr = err
			continue
		}
		log.Printf("uploaded %s", name)
		seen[name] = true
	}
	return lastErr
}

func main() {
	dir := os.Getenv("STREAMS_DIR")
	baseURL := os.Getenv("BLOCK_NODE_URL")
	if dir == "" {
		log.Fatal("STREAMS_DIR is required")
	}
	if baseURL == "" {
		log.Fatal("BLOCK_NODE_URL is required")
	}
	pollMS := defaultPollMS
	if v := os.Getenv("STREAM_POLL_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			log.Fatalf("invalid STREAM_POLL_MS %q: %v", v, err)
		}
		pollMS = n
	}
	client := &http.Client{Timeout: 5 * time.Second}
	seen := make(map[string]bool)
	var mu sync.Mutex

	ticker := time.NewTicker(time.Duration(pollMS) * time.Millisecond)
	defer ticker.Stop()
	log.Printf("block-relay polling %s -> %s every %dms", dir, baseURL, pollMS)
	for range ticker.C {
		mu.Lock()
		_ = pushOnce(dir, seen, client, baseURL)
		mu.Unlock()
	}
}
