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
	body, err := io.ReadAll(resp.Body)
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
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return b, nil
}
