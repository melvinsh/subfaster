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

	// unreachable host -> error (fast, no hang). Close the server first so the
	// port refuses connections.
	dead := srv.URL
	srv.Close()
	if err := s.Preflight(context.Background(), dead); err == nil {
		t.Fatal("Preflight(unreachable) = nil, want error")
	}
}
