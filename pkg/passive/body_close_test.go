package passive

import (
	"context"
	"io"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// trackedBody records whether the consumer closed it.
type trackedBody struct {
	io.Reader
	mu     sync.Mutex
	closed bool
}

func (b *trackedBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *trackedBody) isClosed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.closed
}

// TestSourcesCloseResponseBodyOnErrorStatus runs every source against a 429 and
// a 403 and requires every body it was handed to be closed. httpRequestWrapper
// returns the response *and* an error for any non-200 status, so a source that
// returns on err before releasing the body leaks the connection instead of
// putting it back in the keep-alive pool. For keyed sources that is the common
// path: 429 once a quota is spent, 403 once a key is rejected.
func TestSourcesCloseResponseBodyOnErrorStatus(t *testing.T) {
	for _, registered := range AllSources {
		// chaos talks through its own client library, not the session.
		if registered.Name() == "chaos" {
			continue
		}
		t.Run(registered.Name(), func(t *testing.T) {
			for _, status := range []int{http.StatusTooManyRequests, http.StatusForbidden} {
				t.Run(http.StatusText(status), func(t *testing.T) {
					var mu sync.Mutex
					var bodies []*trackedBody
					transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
						body := &trackedBody{Reader: strings.NewReader(`{"error":"denied"}`)}
						mu.Lock()
						bodies = append(bodies, body)
						mu.Unlock()
						return &http.Response{
							StatusCode: status,
							Status:     http.StatusText(status),
							Body:       body,
							Header:     http.Header{"Content-Type": []string{"application/json"}},
							Request:    req,
						}, nil
					})

					// Fresh instance so the fake key doesn't leak into the shared registry.
					source := reflect.New(reflect.TypeOf(registered).Elem()).Interface().(subscraping.Source)
					source.AddApiKeys([]string{"test:key"})

					extractor, err := subscraping.NewSubdomainExtractor("example.com")
					if err != nil {
						t.Fatal(err)
					}
					session := &subscraping.Session{Client: &http.Client{Transport: transport}, Extractor: extractor, Timeout: 5}

					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					defer cancel()
					for range source.Run(ctx, "example.com", session) {
					}
					if ctx.Err() != nil {
						t.Fatal("source did not finish")
					}

					mu.Lock()
					defer mu.Unlock()
					for i, body := range bodies {
						if !body.isClosed() {
							t.Errorf("response body %d was never closed: the connection cannot be reused", i)
						}
					}
				})
			}
		})
	}
}
