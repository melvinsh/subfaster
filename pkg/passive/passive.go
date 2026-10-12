package passive

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

// EnumerateSubdomainsWithCtx enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomainsWithCtx(ctx context.Context, domain string, proxy string, timeout int, maxEnumTime time.Duration) chan subscraping.Result {
	results := make(chan subscraping.Result)

	go func() {
		defer close(results)

		session, err := subscraping.NewSession(domain, proxy, timeout)
		if err != nil {
			results <- subscraping.Result{
				Type: subscraping.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err),
			}
			return
		}
		defer session.Close()

		ctx, cancel := context.WithTimeout(ctx, maxEnumTime)

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for _, runner := range a.sources {
			wg.Add(1)
			go func(source subscraping.Source) {
				defer wg.Done()
				sourceResults := source.Run(ctx, domain, session)
				for resp := range sourceResults {
					select {
					case <-ctx.Done():
						// stop forwarding but keep draining so the source goroutine
						// is never blocked on a send and can exit instead of leaking
						for range sourceResults {
						}
						return
					case results <- resp:
					}
				}
			}(runner)
		}
		wg.Wait()
		cancel()
	}()
	return results
}

// Clone returns an agent with private copies of its sources, so enumerations
// running at the same time don't share per-run counters. A source holds only
// its API keys and those counters, so a shallow copy is enough.
func (a *Agent) Clone() *Agent {
	sources := make([]subscraping.Source, len(a.sources))
	for i, source := range a.sources {
		v := reflect.ValueOf(source)
		if v.Kind() != reflect.Pointer {
			sources[i] = source
			continue
		}
		cp := reflect.New(v.Elem().Type())
		cp.Elem().Set(v.Elem())
		sources[i] = cp.Interface().(subscraping.Source)
	}
	return &Agent{sources: sources}
}

func (a *Agent) GetStatistics() map[string]subscraping.Statistics {
	stats := make(map[string]subscraping.Statistics)
	sort.Slice(a.sources, func(i, j int) bool {
		return a.sources[i].Name() > a.sources[j].Name()
	})

	for _, source := range a.sources {
		stats[source.Name()] = source.Statistics()
	}
	return stats
}
