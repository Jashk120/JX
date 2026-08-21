package api

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/JKaIN/mirror-node/internal/store"
)

// Server exposes a minimal HTTP API over the mirror store.
type Server struct {
	store store.Store
	log   *slog.Logger
	mux   *http.ServeMux
}

func New(st store.Store, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{store: st, log: log, mux: http.NewServeMux()}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/rounds/latest", s.handleLatestRound)
	s.mux.HandleFunc("/api/v1/records", s.handleRecords)
	s.mux.HandleFunc("/api/v1/events", s.handleEvents)
}

func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) handleLatestRound(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"latestRound": s.store.LatestRound(),
	})
}

func (s *Server) handleRecords(w http.ResponseWriter, _ *http.Request) {
	recs := s.store.ListRecords()
	type summary struct {
		Round uint64 `json:"round"`
		Items int    `json:"items"`
	}
	out := make([]summary, 0, len(recs))
	for _, r := range recs {
		out = append(out, summary{Round: r.Round, Items: len(r.Items)})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

func (s *Server) handleEvents(w http.ResponseWriter, _ *http.Request) {
	evs := s.store.ListEvents()
	type summary struct {
		Creator uint64 `json:"creator"`
		Seq     uint64 `json:"seq"`
	}
	out := make([]summary, 0, len(evs))
	for _, e := range evs {
		out = append(out, summary{Creator: e.Creator, Seq: e.Seq})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
