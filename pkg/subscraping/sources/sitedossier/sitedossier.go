// Package sitedossier logic
package sitedossier

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

// SleepRandIntn is the integer value to get the pseudo-random number
// to sleep before find the next match
const SleepRandIntn = 5

var reNext = regexp.MustCompile(`<a href="([A-Za-z0-9/.]+)"><b>`)

// Source is the passive scraping agent
type Source struct {
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
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

		// Cheap homepage probe first: if the IP is blocked, sitedossier drops
		// our SYNs and a real request would hang for the full timeout. Bail fast.
		if err := session.Preflight(ctx, "http://www.sitedossier.com/"); err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error,
				Error: fmt.Errorf("sitedossier preflight failed (blocked/unreachable): %w", err)}
			s.errors++
			return
		}

		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com/parentdomain/%s", domain), results)
	}()

	return results
}

func (s *Source) enumerate(ctx context.Context, session *subscraping.Session, baseURL string, results chan subscraping.Result) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	s.requests++
	resp, err := session.SimpleGet(ctx, baseURL)
	isnotfound := resp != nil && resp.StatusCode == http.StatusNotFound
	if err != nil && !isnotfound {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}
	session.DiscardHTTPResponse(resp)

	src := string(body)

	// When the IP is flagged, sitedossier 302-redirects to a captcha page
	// (followed automatically, landing on /audit) instead of returning data.
	// Detect it so it reports an error rather than a silent zero.
	finalPath := ""
	if resp.Request != nil {
		finalPath = resp.Request.URL.Path
	}
	if isBlockedResponse(finalPath, src) {
		results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Error,
			Error: fmt.Errorf("sitedossier blocked: captcha challenge (rate-limited)")}
		s.errors++
		return
	}
	for _, subdomain := range session.Extractor.Extract(src) {
		select {
		case <-ctx.Done():
			return
		case results <- subscraping.Result{Source: "sitedossier", Type: subscraping.Subdomain, Value: subdomain}:
			s.results++
		}
	}

	match := reNext.FindStringSubmatch(src)
	if len(match) > 0 {
		s.enumerate(ctx, session, fmt.Sprintf("http://www.sitedossier.com%s", match[1]), results)
	}
}

// isBlockedResponse reports whether a sitedossier response is the captcha
// challenge served when the client IP is rate-limited. The 302 to /audit is
// followed automatically, so we match the final path or the page text.
func isBlockedResponse(finalPath, body string) bool {
	return strings.Contains(finalPath, "/audit") || strings.Contains(body, "unusual or excessive requests")
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "sitedossier"
}

func (s *Source) IsDefault() bool {
	return false
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.NoKey
}

func (s *Source) AddApiKeys(_ []string) {
	// no key needed
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Requests:  s.requests,
	}
}
