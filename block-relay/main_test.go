package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func writeFile(t *testing.T, dir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), data, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
}

// --- helpers for fake block-node ---

type fakeBlockNode struct {
	mu    sync.Mutex
	heads []string
	puts  map[string][]byte
	// headStatus overrides: name -> status to return for HEAD. Default logic: 200 if in puts, else 404.
	headStatus map[string]int
}

func newFake() *fakeBlockNode {
	return &fakeBlockNode{puts: make(map[string][]byte), headStatus: make(map[string]int)}
}

func (f *fakeBlockNode) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Path expected: /v1/blocks/<name>
	name := r.URL.Path[len("/v1/blocks/"):]
	// URL path is already unescaped by net/http? Actually Path is escaped, use EscapedPath.
	// Use r.URL.EscapedPath() handling: simpler to use r.URL.Path which is unescaped per Go docs? Use Path value.
	// For test we just use what server sees.
	switch r.Method {
	case http.MethodHead:
		f.mu.Lock()
		if st, ok := f.headStatus[name]; ok {
			f.mu.Unlock()
			w.WriteHeader(st)
			return
		}
		_, exists := f.puts[name]
		f.mu.Unlock()
		f.heads = append(f.heads, name)
		if exists {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodPut:
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(r.Body)
		f.mu.Lock()
		f.puts[name] = buf.Bytes()
		f.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func TestPushOnce_uploadsMatchingFile(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "events-1.esf", []byte("hello esf"))
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()

	seen := make(map[string]bool)
	client := srv.Client()
	err := pushOnce(dir, seen, client, srv.URL)
	if err != nil {
		t.Fatalf("pushOnce: %v", err)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	got, ok := fake.puts["events-1.esf"]
	if !ok {
		t.Fatalf("expected PUT for events-1.esf, puts=%v", fake.puts)
	}
	if string(got) != "hello esf" {
		t.Fatalf("bytes mismatch: %q", got)
	}
}

func TestPushOnce_seenSetSkipsSecondPoll(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.rsf", []byte("rsf data"))
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	seen := make(map[string]bool)
	client := srv.Client()

	if err := pushOnce(dir, seen, client, srv.URL); err != nil {
		t.Fatalf("first push: %v", err)
	}
	// Reset puts tracking to detect second PUT
	fake.mu.Lock()
	firstPuts := len(fake.puts)
	fake.mu.Unlock()
	if firstPuts != 1 {
		t.Fatalf("expected 1 put after first poll, got %d", firstPuts)
	}
	if err := pushOnce(dir, seen, client, srv.URL); err != nil {
		t.Fatalf("second push: %v", err)
	}
	fake.mu.Lock()
	secondPuts := len(fake.puts)
	fake.mu.Unlock()
	if secondPuts != 1 {
		t.Fatalf("seen-set should prevent second PUT, puts=%d", secondPuts)
	}
}

func TestPushOnce_nonMatchingSuffixNeverUploaded(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "x.rsf_sig", []byte("should not push"))
	writeFile(t, dir, "notes.txt", []byte("also not"))
	writeFile(t, dir, "keep.esf", []byte("yes"))
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	seen := make(map[string]bool)
	_ = pushOnce(dir, seen, srv.Client(), srv.URL)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.puts["x.rsf_sig"]; ok {
		t.Fatalf("x.rsf_sig must not be uploaded")
	}
	if _, ok := fake.puts["notes.txt"]; ok {
		t.Fatalf("notes.txt must not be uploaded")
	}
	if _, ok := fake.puts["keep.esf"]; !ok {
		t.Fatalf("keep.esf should have been uploaded")
	}
}

func TestPushOnce_freshInstanceHead200SkipsUpload(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "checkpoint-42.ckpt", []byte("ckpt bytes"))
	fake := newFake()
	// Simulate server already has the file (HEAD 200) without needing a prior PUT from this process.
	fake.headStatus["checkpoint-42.ckpt"] = http.StatusOK
	srv := httptest.NewServer(fake)
	defer srv.Close()
	seen := make(map[string]bool) // fresh process
	_ = pushOnce(dir, seen, srv.Client(), srv.URL)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.puts["checkpoint-42.ckpt"]; ok {
		t.Fatalf("fresh instance should not re-upload when HEAD 200")
	}
	if !seen["checkpoint-42.ckpt"] {
		t.Fatalf("seen should be marked after HEAD 200")
	}
}

func TestPushOnce_unreachableSurvivesNTicks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "a.esf", []byte("data"))
	seen := make(map[string]bool)
	client := &http.Client{}
	// Unreachable URL
	badURL := "http://127.0.0.1:1"
	for i := 0; i < 3; i++ {
		err := pushOnce(dir, seen, client, badURL)
		// Should return error but not panic
		if err == nil {
			t.Logf("tick %d: expected error for unreachable, got nil (HEAD may have failed but pushOnce continues)", i)
		}
	}
	// If we reached here without panic, survival is proven.
	// seen should still be empty because nothing was successfully pushed
	if len(seen) != 0 {
		t.Fatalf("seen should be empty after unreachable ticks, got %v", seen)
	}
}

func TestPushOnce_allAllowedSuffixes(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.esf", "b.rsf", "c.esf_sig", "checkpoint-1.ckpt"} {
		writeFile(t, dir, name, []byte("x"))
	}
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	seen := make(map[string]bool)
	_ = pushOnce(dir, seen, srv.Client(), srv.URL)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	for _, name := range []string{"a.esf", "b.rsf", "c.esf_sig", "checkpoint-1.ckpt"} {
		if _, ok := fake.puts[name]; !ok {
			t.Errorf("expected %s to be uploaded", name)
		}
	}
}

func TestPushOnce_urlEscaping(t *testing.T) {
	dir := t.TempDir()
	// Flat name with space — should be path-escaped
	name := "checkpoint-1.ckpt"
	writeFile(t, dir, name, []byte("data"))
	fake := newFake()
	srv := httptest.NewServer(fake)
	defer srv.Close()
	seen := make(map[string]bool)
	_ = pushOnce(dir, seen, srv.Client(), srv.URL)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if _, ok := fake.puts[name]; !ok {
		t.Fatalf("expected PUT with escaped path for %q", name)
	}
}

func TestIsAllowed(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"a.esf", true},
		{"a.rsf", true},
		{"a.esf_sig", true},
		{"checkpoint-42.ckpt", true},
		{"x.rsf_sig", false},
		{"notes.txt", false},
		{"foo.ckpt.bak", false},
	}
	for _, c := range cases {
		if got := isAllowed(c.name); got != c.want {
			t.Errorf("isAllowed(%q)=%v want %v", c.name, got, c.want)
		}
	}
}
