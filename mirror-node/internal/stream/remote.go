package stream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrNotFound = errors.New("not found")

const (
	// maxListResponseBytes bounds a /v1/blocks listing body so a hostile
	// block node cannot exhaust memory through List.
	maxListResponseBytes = 1 << 20 // 1 MiB
	// maxBlockBytes bounds a single fetched block/stream file body so a
	// hostile block node cannot exhaust memory through Fetch.
	maxBlockBytes = 256 << 20 // 256 MiB
)

type RemoteSource struct {
	BaseURL    string
	HTTPClient *http.Client
}

func (r *RemoteSource) client() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

func (r *RemoteSource) baseURL() string {
	return strings.TrimRight(r.BaseURL, "/")
}

func validateName(name string) error {
	if name == "" {
		return fmt.Errorf("invalid block name %q: empty", name)
	}
	if strings.Contains(name, "/") {
		return fmt.Errorf("invalid block name %q: must not contain '/'", name)
	}
	if strings.Contains(name, "..") {
		return fmt.Errorf("invalid block name %q: must not contain '..'", name)
	}
	return nil
}

func (r *RemoteSource) List(ctx context.Context) ([]string, error) {
	url := r.baseURL() + "/v1/blocks"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: GET %s returned 404", ErrNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	body, err := readCapped(resp.Body, maxListResponseBytes)
	if err != nil {
		return nil, err
	}
	raw := strings.Split(string(body), "\n")
	out := make([]string, 0, len(raw))
	for _, line := range raw {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		out = append(out, trimmed)
	}
	return out, nil
}

func (r *RemoteSource) Fetch(ctx context.Context, name string) ([]byte, error) {
	if err := validateName(name); err != nil {
		return nil, err
	}
	url := r.baseURL() + "/v1/blocks/" + name
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: GET %s returned 404", ErrNotFound, url)
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("GET %s returned %d: %s", url, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	b, err := readCapped(resp.Body, maxBlockBytes)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// readCapped reads r in full, capping it at max bytes: it copies at most
// max+1 bytes so a body longer than max is detected and rejected instead of
// being buffered. Ordinary read errors are returned unchanged.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response exceeds maximum size of %d bytes", max)
	}
	return body, nil
}
