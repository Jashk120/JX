package stream

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestReadCapped(t *testing.T) {
	body, err := readCapped(strings.NewReader("ok"), 8)
	if err != nil || string(body) != "ok" {
		t.Fatalf("expected full small body, got %q, %v", body, err)
	}
	body, err = readCapped(strings.NewReader("exact-max"), 9)
	if err != nil || string(body) != "exact-max" {
		t.Fatalf("expected body exactly at the cap to be accepted, got %q, %v", body, err)
	}
	if _, err = readCapped(strings.NewReader("over-the-cap"), 9); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected cap exceeded error, got %v", err)
	}
	if _, err = readCapped(errReader{}, 8); err == nil || !strings.Contains(err.Error(), "read failed") {
		t.Fatalf("expected ordinary read error unchanged, got %v", err)
	}
}

func TestRemoteSourceRejectsOversizedListing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		line := []byte("round-0.rsf\n")
		_, _ = w.Write(bytes.Repeat(line, maxListResponseBytes/len(line)+2))
	}))
	defer srv.Close()
	rs := &RemoteSource{BaseURL: srv.URL}
	if _, err := rs.List(context.Background()); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized listing error, got %v", err)
	}
}

func TestRemoteSourceListTrimsAndDropsEmpties(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/blocks" {
			_, _ = w.Write([]byte("  round-0.rsf  \n\n  events-00000000.esf \n   \n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rs := &RemoteSource{BaseURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	names, err := rs.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(names) != 2 || names[0] != "round-0.rsf" || names[1] != "events-00000000.esf" {
		t.Fatalf("unexpected names %v", names)
	}
}

func TestRemoteSourceFetchValidation(t *testing.T) {
	rs := &RemoteSource{BaseURL: "http://example.com"}
	if _, err := rs.Fetch(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected empty validation, got %v", err)
	}
	if _, err := rs.Fetch(context.Background(), "a/b"); err == nil || !strings.Contains(err.Error(), "/") {
		t.Fatalf("expected slash validation, got %v", err)
	}
	if _, err := rs.Fetch(context.Background(), "a..b"); err == nil || !strings.Contains(err.Error(), "..") {
		t.Fatalf("expected .. validation, got %v", err)
	}
}

func TestRemoteSourceErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	rs := &RemoteSource{BaseURL: srv.URL}
	_, err := rs.Fetch(context.Background(), "round-0.rsf")
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	_, err = rs.List(context.Background())
	if err == nil || !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on list, got %v", err)
	}
}

func TestRemoteSourceNon200Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()
	rs := &RemoteSource{BaseURL: srv.URL}
	_, err := rs.List(context.Background())
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
	_, err = rs.Fetch(context.Background(), "round-0.rsf")
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected 500 error, got %v", err)
	}
}

func TestRemoteSourceHonorsContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	rs := &RemoteSource{BaseURL: srv.URL, HTTPClient: &http.Client{Timeout: 5 * time.Second}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := rs.List(ctx)
	if err == nil || !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}
