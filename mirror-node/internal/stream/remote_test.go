package stream

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

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
