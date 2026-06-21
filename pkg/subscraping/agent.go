package subscraping

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/projectdiscovery/gologger"
)

// userAgent is the fixed User-Agent sent with every request.
const userAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

// NewSession creates a new session object for a domain
func NewSession(domain string, proxy string, timeout int) (*Session, error) {
	Transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 100,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		Dial: (&net.Dialer{
			Timeout: time.Duration(timeout) * time.Second,
		}).Dial,
	}

	// Add proxy
	if proxy != "" {
		proxyURL, _ := url.Parse(proxy)
		if proxyURL == nil {
			// Log warning but continue anyway
			gologger.Warning().Msgf("Invalid proxy provided: %s", proxy)
		} else {
			Transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	client := &http.Client{
		Transport: Transport,
		Timeout:   time.Duration(timeout) * time.Second,
	}

	session := &Session{Client: client, Timeout: timeout}

	// Create a new extractor object for the current domain
	extractor, err := NewSubdomainExtractor(domain)
	session.Extractor = extractor

	return session, err
}

// Get makes a GET request to a URL with extended parameters
func (s *Session) Get(ctx context.Context, getURL, cookies string, headers map[string]string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, cookies, headers, nil)
}

// SimpleGet makes a simple GET request to a URL
func (s *Session) SimpleGet(ctx context.Context, getURL string) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodGet, getURL, "", map[string]string{}, nil)
}

// preflightTimeout bounds the homepage probe used to detect connection-level
// blocks before spending a full request (or API quota) on the real endpoint.
const preflightTimeout = 3 * time.Second

// Preflight probes probeURL (a source's homepage, so it costs no API quota)
// with a short timeout. It returns an error if the host is unreachable within
// the probe window, letting a source bail out fast instead of hanging on a
// blocked endpoint for the full request timeout. It is not rate-limited.
func (s *Session) Preflight(ctx context.Context, probeURL string) error {
	ctx, cancel := context.WithTimeout(ctx, preflightTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, probeURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", userAgent)
	client := &http.Client{Timeout: preflightTimeout, Transport: s.Client.Transport}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

// Post makes a POST request to a URL with extended parameters
func (s *Session) Post(ctx context.Context, postURL, cookies string, headers map[string]string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, cookies, headers, body)
}

// SimplePost makes a simple POST request to a URL
func (s *Session) SimplePost(ctx context.Context, postURL, contentType string, body io.Reader) (*http.Response, error) {
	return s.HTTPRequest(ctx, http.MethodPost, postURL, "", map[string]string{"Content-Type": contentType}, body)
}

// HTTPRequest makes any HTTP request to a URL with extended parameters
func (s *Session) HTTPRequest(ctx context.Context, method, requestURL, cookies string, headers map[string]string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "en")
	// Keep connections alive so sources making many sequential requests to the
	// same host (e.g. thc paginates ~268x) reuse the TCP+TLS connection instead
	// of paying a fresh handshake (~70ms) per request. The Transport pools idle
	// conns (MaxIdleConnsPerHost) — "Connection: close" here would defeat that.
	req.Header.Set("Connection", "keep-alive")

	if cookies != "" {
		req.Header.Set("Cookie", cookies)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	return httpRequestWrapper(s.Client, req)
}

// DiscardHTTPResponse discards the response content by demand
func (s *Session) DiscardHTTPResponse(response *http.Response) {
	if response != nil {
		_, err := io.Copy(io.Discard, response.Body)
		if err != nil {
			gologger.Warning().Msgf("Could not discard response body: %s\n", err)
			return
		}
		if closeErr := response.Body.Close(); closeErr != nil {
			gologger.Warning().Msgf("Could not close response body: %s\n", closeErr)
		}
	}
}

// Close the session
func (s *Session) Close() {
	s.Client.CloseIdleConnections()
}

func httpRequestWrapper(client *http.Client, request *http.Request) (*http.Response, error) {
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}

	if response.StatusCode != http.StatusOK {
		requestURL, _ := url.QueryUnescape(request.URL.String())

		gologger.Debug().MsgFunc(func() string {
			buffer := new(bytes.Buffer)
			_, _ = buffer.ReadFrom(response.Body)
			return fmt.Sprintf("Response for failed request against %s:\n%s", requestURL, buffer.String())
		})
		return response, fmt.Errorf("unexpected status code %d received from %s", response.StatusCode, requestURL)
	}
	return response, nil
}
