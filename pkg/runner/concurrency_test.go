package runner

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/passive"
	"github.com/melvinsh/subfaster/v2/pkg/resolve"
	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

// slowSource answers after a per-domain delay and tracks how many runs overlap.
type slowSource struct {
	delays          map[string]time.Duration
	active, maximum *atomic.Int32
	results         int
}

func (s *slowSource) Run(ctx context.Context, domain string, _ *subscraping.Session) <-chan subscraping.Result {
	out := make(chan subscraping.Result)
	go func() {
		defer close(out)
		n := s.active.Add(1)
		defer s.active.Add(-1)
		for {
			m := s.maximum.Load()
			if n <= m || s.maximum.CompareAndSwap(m, n) {
				break
			}
		}
		select {
		case <-time.After(s.delays[domain]):
		case <-ctx.Done():
			return
		}
		for _, sub := range []string{"b." + domain, "a." + domain} {
			out <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: sub}
			s.results++
		}
	}()
	return out
}

func (s *slowSource) Name() string                               { return "slowtest" }
func (s *slowSource) IsDefault() bool                            { return false }
func (s *slowSource) HasRecursiveSupport() bool                  { return false }
func (s *slowSource) KeyRequirement() subscraping.KeyRequirement { return subscraping.NoKey }
func (s *slowSource) AddApiKeys([]string)                        {}
func (s *slowSource) Statistics() subscraping.Statistics {
	return subscraping.Statistics{Results: s.results}
}

func TestEnumerateMultipleDomainsConcurrentInOrder(t *testing.T) {
	// The first domain is the slowest, so a writer that didn't keep input order
	// would print it last.
	domains := []string{"one.test", "two.test", "three.test", "four.test", "five.test"}
	delays := map[string]time.Duration{}
	for i, d := range domains {
		delays[d] = time.Duration(len(domains)-i) * 60 * time.Millisecond
	}

	for _, threads := range []int{1, len(domains)} {
		source := &slowSource{delays: delays, active: new(atomic.Int32), maximum: new(atomic.Int32)}
		passive.NameSourceMap[source.Name()] = source
		t.Cleanup(func() { delete(passive.NameSourceMap, source.Name()) })

		var callbacks atomic.Int32
		r := &Runner{
			options: &Options{
				Threads: threads, Timeout: 5, MaxEnumerationTime: 1,
				ResultCallback: func(*resolve.HostEntry) { callbacks.Add(1) },
			},
			passiveAgent: passive.New([]string{source.Name()}, nil, false, false),
		}

		start := time.Now()
		if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(strings.Join(domains, "\n")), nil); err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)

		if got := int(source.maximum.Load()); got != threads {
			t.Errorf("threads=%d: peak concurrency %d", threads, got)
		}
		if threads > 1 && elapsed > delays[domains[0]]*2 {
			t.Errorf("threads=%d: took %s, domains did not overlap", threads, elapsed)
		}
		if got := int(callbacks.Load()); got != 2*len(domains) {
			t.Errorf("threads=%d: %d callbacks, want %d", threads, got, 2*len(domains))
		}
		if stats := r.GetStatistics()[source.Name()]; stats.Results != 2 {
			t.Errorf("threads=%d: per-domain stats not isolated: %+v", threads, stats)
		}
	}
}

func TestEnumerateMultipleDomainsWritesInInputOrder(t *testing.T) {
	domains := []string{"one.test", "two.test", "three.test"}
	delays := map[string]time.Duration{"one.test": 150 * time.Millisecond, "two.test": 75 * time.Millisecond}
	source := &slowSource{delays: delays, active: new(atomic.Int32), maximum: new(atomic.Int32)}
	passive.NameSourceMap[source.Name()] = source
	t.Cleanup(func() { delete(passive.NameSourceMap, source.Name()) })

	r := &Runner{
		options:      &Options{Threads: 3, Timeout: 5, MaxEnumerationTime: 1},
		passiveAgent: passive.New([]string{source.Name()}, nil, false, false),
	}
	var out bytes.Buffer
	if err := r.EnumerateMultipleDomainsWithCtx(context.Background(), strings.NewReader(strings.Join(domains, "\n")), []io.Writer{&out}); err != nil {
		t.Fatal(err)
	}
	want := "a.one.test\nb.one.test\na.two.test\nb.two.test\na.three.test\nb.three.test\n"
	if out.String() != want {
		t.Fatalf("output:\n%s\nwant:\n%s", out.String(), want)
	}
}
