package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestPutAndGetRoundtrip(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)

	body := []byte("hello block-node")
	req := httptest.NewRequest(http.MethodPut, "/v1/blocks/checkpoint-42.ckpt", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT got %d want 200", rec.Code)
	}
	// Bytes land on disk.
	data, err := os.ReadFile(filepath.Join(dir, "checkpoint-42.ckpt"))
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(data, body) {
		t.Fatalf("disk bytes mismatch: got %q want %q", data, body)
	}
	// GET roundtrip returns exact bytes.
	req2 := httptest.NewRequest(http.MethodGet, "/v1/blocks/checkpoint-42.ckpt", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("GET got %d want 200", rec2.Code)
	}
	got, _ := io.ReadAll(rec2.Body)
	if !bytes.Equal(got, body) {
		t.Fatalf("GET bytes mismatch: got %q want %q", got, body)
	}
}

func TestPutIdempotentNoRewrite(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)

	name := "foo.esf"
	first := []byte("first content")
	req1 := httptest.NewRequest(http.MethodPut, "/v1/blocks/"+name, bytes.NewReader(first))
	rec1 := httptest.NewRecorder()
	h.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first PUT got %d", rec1.Code)
	}
	path := filepath.Join(dir, name)
	fi1, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	mtime1 := fi1.ModTime()

	// Repeat PUT with different content — should be no-op.
	second := []byte("second content different")
	req2 := httptest.NewRequest(http.MethodPut, "/v1/blocks/"+name, bytes.NewReader(second))
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second PUT got %d want 200", rec2.Code)
	}
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat2: %v", err)
	}
	mtime2 := fi2.ModTime()
	if !mtime1.Equal(mtime2) {
		t.Fatalf("mtime changed on idempotent PUT: %v vs %v", mtime1, mtime2)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(data, first) {
		t.Fatalf("content rewritten on idempotent PUT: got %q want %q", data, first)
	}
	// GET still returns first content.
	req3 := httptest.NewRequest(http.MethodGet, "/v1/blocks/"+name, nil)
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	got, _ := io.ReadAll(rec3.Body)
	if !bytes.Equal(got, first) {
		t.Fatalf("GET after second PUT got %q want %q", got, first)
	}
}

func TestGetMissing404(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	req := httptest.NewRequest(http.MethodGet, "/v1/blocks/nope.esf", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("GET missing got %d want 404", rec.Code)
	}
}

func TestHead(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	body := []byte("head content 12345")
	// Put file.
	reqPut := httptest.NewRequest(http.MethodPut, "/v1/blocks/head.bin", bytes.NewReader(body))
	recPut := httptest.NewRecorder()
	h.ServeHTTP(recPut, reqPut)
	if recPut.Code != http.StatusOK {
		t.Fatalf("PUT got %d", recPut.Code)
	}

	// HEAD present -> 200 + Content-Length
	reqHead := httptest.NewRequest(http.MethodHead, "/v1/blocks/head.bin", nil)
	recHead := httptest.NewRecorder()
	h.ServeHTTP(recHead, reqHead)
	if recHead.Code != http.StatusOK {
		t.Fatalf("HEAD present got %d want 200", recHead.Code)
	}
	cl := recHead.Header().Get("Content-Length")
	if cl != fmt.Sprintf("%d", len(body)) {
		t.Fatalf("HEAD Content-Length got %q want %d", cl, len(body))
	}
	if recHead.Body.Len() != 0 {
		t.Fatalf("HEAD body not empty: %d bytes", recHead.Body.Len())
	}

	// HEAD absent -> 404
	reqHead2 := httptest.NewRequest(http.MethodHead, "/v1/blocks/missing.bin", nil)
	recHead2 := httptest.NewRecorder()
	h.ServeHTTP(recHead2, reqHead2)
	if recHead2.Code != http.StatusNotFound {
		t.Fatalf("HEAD absent got %d want 404", recHead2.Code)
	}
}

func TestListSorted(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	names := []string{"zebra.ckpt", "a.esf", "m.rsf", "checkpoint-10.ckpt"}
	for _, n := range names {
		req := httptest.NewRequest(http.MethodPut, "/v1/blocks/"+n, strings.NewReader("x"))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT %s got %d", n, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/blocks", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list got %d want 200", rec.Code)
	}
	body := rec.Body.String()
	lines := strings.Split(strings.TrimSpace(body), "\n")
	// Filter empties (in case body empty)
	got := make([]string, 0, len(lines))
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			got = append(got, strings.TrimSpace(l))
		}
	}
	expected := append([]string(nil), names...)
	sort.Strings(expected)
	if len(got) != len(expected) {
		t.Fatalf("list length got %d (%v) want %d (%v)", len(got), got, len(expected), expected)
	}
	for i := range expected {
		if got[i] != expected[i] {
			t.Fatalf("list sorted mismatch at %d: got %q want %q (got %v want %v)", i, got[i], expected[i], got, expected)
		}
	}
}

func TestTraversalRejected(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	cases := []string{
		"..",
		"a/b",
		"..%2Fescape",
		"%2e%2e%2Fescape",
		"a%2Fb",
		"a\\b",
		"a%5Cb",
		"..%2F..%2Fetc",
		"foo..bar",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPut, "/v1/blocks/"+name, strings.NewReader("evil"))
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("traversal PUT %q: got %d want 400", name, rec.Code)
			}
			req2 := httptest.NewRequest(http.MethodGet, "/v1/blocks/"+name, nil)
			rec2 := httptest.NewRecorder()
			h.ServeHTTP(rec2, req2)
			if rec2.Code != http.StatusBadRequest {
				t.Errorf("traversal GET %q: got %d want 400", name, rec2.Code)
			}
		})
	}
}

func TestTraversalDotDotSlashEscape(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	name := "..%2Fescape"
	req := httptest.NewRequest(http.MethodPut, "/v1/blocks/"+name, strings.NewReader("evil"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("traversal %q: got %d want 400", name, rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	dir := t.TempDir()
	h := newHandler(dir)
	// Seed a file.
	reqPut := httptest.NewRequest(http.MethodPut, "/v1/blocks/file.bin", strings.NewReader("data"))
	recPut := httptest.NewRecorder()
	h.ServeHTTP(recPut, reqPut)

	// POST on block route -> 405
	req := httptest.NewRequest(http.MethodPost, "/v1/blocks/file.bin", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST block got %d want 405", rec.Code)
	}
	// DELETE -> 405
	req2 := httptest.NewRequest(http.MethodDelete, "/v1/blocks/file.bin", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("DELETE block got %d want 405", rec2.Code)
	}
	// PUT on list route -> 405
	req3 := httptest.NewRequest(http.MethodPut, "/v1/blocks", strings.NewReader("x"))
	rec3 := httptest.NewRecorder()
	h.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT list got %d want 405", rec3.Code)
	}
	// POST on list -> 405
	req4 := httptest.NewRequest(http.MethodPost, "/v1/blocks", nil)
	rec4 := httptest.NewRecorder()
	h.ServeHTTP(rec4, req4)
	if rec4.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST list got %d want 405", rec4.Code)
	}
}

func TestValidNameUnit(t *testing.T) {
	if !validName("checkpoint-42.ckpt") {
		t.Error("validName rejected good name")
	}
	if validName("../escape") {
		t.Error("validName allowed ../escape")
	}
	if validName("a/b") {
		t.Error("validName allowed a/b")
	}
	if validName("..") {
		t.Error("validName allowed ..")
	}
	if validName("a\\b") {
		t.Error("validName allowed a\\b")
	}
	if validName("") {
		t.Error("validName allowed empty")
	}
}
