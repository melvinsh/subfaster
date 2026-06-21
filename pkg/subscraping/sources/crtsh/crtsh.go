// Package crtsh logic
package crtsh

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encoding/json"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

type subdomain struct {
	NameValue string `json:"name_value"`
}

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

		s.getSubdomainsFromHTTP(ctx, domain, session, results)
	}()

	return results
}

func (s *Source) getSubdomainsFromHTTP(ctx context.Context, domain string, session *subscraping.Session, results chan subscraping.Result) {
	s.requests++
	resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain))
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	var subdomains []subdomain
	err = json.NewDecoder(resp.Body).Decode(&subdomains)
	if err != nil {
		results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
		s.errors++
		session.DiscardHTTPResponse(resp)
		return
	}

	session.DiscardHTTPResponse(resp)

	for _, subdomain := range subdomains {
		select {
		case <-ctx.Done():
			return
		default:
		}
		for sub := range strings.SplitSeq(subdomain.NameValue, "\n") {
			for _, value := range session.Extractor.Extract(sub) {
				if value != "" {
					select {
					case <-ctx.Done():
						return
					case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: value}:
						s.results++
					}
				}
			}
		}
	}
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "crtsh"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return true
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
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
	}
}
