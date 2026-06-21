// Package hackertarget logic
package hackertarget

import (
	"bufio"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	s.requests = 0

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		// Cheap homepage probe first (no quota cost): bail fast if the host is
		// blocked/unreachable instead of waiting out the full request timeout.
		if err := session.Preflight(ctx, "https://hackertarget.com/"); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error,
				Error: fmt.Errorf("hackertarget preflight failed (blocked/unreachable): %w", err)}
			s.errors++
			return
		}

		htSearchUrl := fmt.Sprintf("https://api.hackertarget.com/hostsearch/?q=%s", domain)
		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey != "" {
			htSearchUrl = fmt.Sprintf("%s&apikey=%s", htSearchUrl, randomApiKey)
		}

		s.requests++
		resp, err := session.SimpleGet(ctx, htSearchUrl)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			select {
			case <-ctx.Done():
				return
			default:
			}
			line := scanner.Text()
			if line == "" {
				continue
			}
			// hackertarget answers HTTP 200 even when the daily quota is exhausted
			// or the query is rejected; the body is then a plaintext error sentence
			// (e.g. "API count exceeded - Increase Quota with Membership"). Surface it
			// as an error instead of silently reporting zero subdomains.
			if isQuotaError(line) {
				quota := resp.Header.Get("x-api-quota")
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error,
					Error: fmt.Errorf("hackertarget blocked (x-api-quota=%q): %s", quota, line)}
				s.errors++
				return
			}
			match := session.Extractor.Extract(line)
			for _, subdomain := range match {
				select {
				case <-ctx.Done():
					return
				case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
					s.results++
				}
			}
		}
	}()

	return results
}

// isQuotaError reports whether a hackertarget response line is a plaintext
// error returned with HTTP 200 (e.g. "API count exceeded - Increase Quota
// with Membership" when the daily quota is exhausted) rather than host data.
func isQuotaError(line string) bool {
	return strings.Contains(line, "API count exceeded") || strings.HasPrefix(line, "error ")
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hackertarget"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.OptionalKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
		Requests:  s.requests,
	}
}
