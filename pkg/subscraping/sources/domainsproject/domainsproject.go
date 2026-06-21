// Package domainsproject logic
package domainsproject

import (
	"context"
	"fmt"
	"strings"
	"time"

	"encoding/json"

	"github.com/melvinsh/subfaster/v2/pkg/subscraping"
)

// Source is the passive scraping agent
type Source struct {
	apiKeys   []apiKey
	timeTaken time.Duration
	errors    int
	results   int
	requests  int
	skipped   bool
}

type apiKey struct {
	username string
	password string
}

type domainsProjectResponse struct {
	Domains []string `json:"domains"`
	Error   string   `json:"error"`
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

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey.username == "" || randomApiKey.password == "" {
			s.skipped = true
			return
		}

		searchURL := fmt.Sprintf("https://api.domainsproject.org/api/tld/search?domain=%s", domain)
		s.requests++
		resp, err := session.HTTPRequest(
			ctx,
			"GET",
			searchURL,
			"",
			nil,
			nil,
			subscraping.BasicAuth{Username: randomApiKey.username, Password: randomApiKey.password},
		)
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

		var response domainsProjectResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		if response.Error != "" {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%v", response.Error),
			}
			s.errors++
			return
		}

		for _, subdomain := range response.Domains {
			if !strings.HasPrefix(subdomain, ".") {
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

// Name returns the name of the source
func (s *Source) Name() string {
	return "domainsproject"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) KeyRequirement() subscraping.KeyRequirement {
	return subscraping.RequiredKey
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = subscraping.CreateApiKeys(keys, func(k, v string) apiKey {
		return apiKey{k, v}
	})
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		Requests:  s.requests,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
