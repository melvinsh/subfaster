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

	// a verdict produced by a cancelled caller context must NOT be cached —
	// otherwise one cancelled domain would skip a healthy source for the rest
	// of a -dL run.
	live := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer live.Close()
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := s.Preflight(cancelled, live.URL); err == nil {
		t.Fatal("Preflight(cancelled) = nil, want error")
	}
	// re-probe with a good context: must succeed, proving the cancelled verdict
	// was not cached.
	if err := s.Preflight(context.Background(), live.URL); err != nil {
		t.Fatalf("Preflight(after cancelled) = %v, want nil — cancelled verdict was wrongly cached", err)
	}
}
