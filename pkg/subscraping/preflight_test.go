package subscraping

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestPreflight(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	s := &Session{Client: &http.Client{}}

	// reachable host -> no error
	if err := s.Preflight(context.Background(), srv.URL); err != nil {
		t.Fatalf("Preflight(reachable) = %v, want nil", err)
	}

	// unreachable host (different URL) -> error (fast, no hang).
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	if err := s.Preflight(context.Background(), deadURL); err == nil {
		t.Fatal("Preflight(unreachable) = nil, want error")
	}

	// cached verdict is reused: closing the reachable server must not change its
	// answer, because the URL was already probed.
	srv.Close()
	if err := s.Preflight(context.Background(), srv.URL); err != nil {
		t.Fatalf("Preflight(cached reachable) = %v, want nil", err)
	}
}
