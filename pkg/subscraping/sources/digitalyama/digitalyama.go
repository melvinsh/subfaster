package digitalyama

import (
	"context"
	"fmt"
	"time"

	"encoding/json"

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

type digitalYamaResponse struct {
	Query        string   `json:"query"`
	Count        int      `json:"count"`
	Subdomains   []string `json:"subdomains"`
	UsageSummary struct {
		QueryCost        float64 `json:"query_cost"`
		CreditsRemaining float64 `json:"credits_remaining"`
	} `json:"usage_summary"`
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
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		searchURL := fmt.Sprintf("https://api.digitalyama.com/subdomain_finder?domain=%s", domain)
		s.requests++
		resp, err := session.Get(ctx, searchURL, "", map[string]string{"x-api-key": randomApiKey})
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
				s.errors++
			}
		}()

		if resp.StatusCode != 200 {
			var errResponse struct {
				Detail []struct {
					Loc  []string `json:"loc"`
					Msg  string   `json:"msg"`
					Type string   `json:"type"`
				} `json:"detail"`
			}
			err = json.NewDecoder(resp.Body).Decode(&errResponse)
			if err != nil {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code %d", resp.StatusCode)}
				s.errors++
				return
			}
			if len(errResponse.Detail) > 0 {
				errMsg := errResponse.Detail[0].Msg
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s (code %d)", errMsg, resp.StatusCode)}
			} else {
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("unexpected status code %d", resp.StatusCode)}
			}
			s.errors++
			return
		}

		var response digitalYamaResponse
		err = json.NewDecoder(resp.Body).Decode(&response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}

		for _, subdomain := range response.Subdomains {
			select {
			case <-ctx.Done():
				return
			case results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}:
				s.results++
			}
		}
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "digitalyama"
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
	s.apiKeys = keys
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
