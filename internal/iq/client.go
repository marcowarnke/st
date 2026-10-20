// Package iq is a minimal Sonatype IQ Server (Lifecycle) REST client.
package iq

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
	// MaxRetries is how often a request is retried after a 429, a 5xx or a
	// network error (see retryable).
	MaxRetries int
	// Debug, if set, receives one line per request and retry.
	Debug io.Writer
}

// sleep is swappable for tests.
var sleep = time.Sleep

func New(baseURL, user, password string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		User:     user,
		Password: password,
		HTTP:     &http.Client{Timeout: 60 * time.Second},

		MaxRetries: 3,
	}
}

type APIError struct {
	StatusCode int
	Method     string
	URL        string
	Message    string
	Attempts   int
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	s := fmt.Sprintf("HTTP %d: %s (%s %s)", e.StatusCode, msg, e.Method, e.URL)
	if e.Attempts > 1 {
		s += fmt.Sprintf(", gave up after %d attempts", e.Attempts)
	}
	return s
}

// IsNotFound reports whether err is an HTTP 404 from IQ Server.
func IsNotFound(err error) bool {
	var e *APIError
	return errors.As(err, &e) && e.StatusCode == http.StatusNotFound
}

// URL builds an absolute URL. Paths are relative to the base URL.
func (c *Client) URL(path string, query url.Values) string {
	u := c.BaseURL + "/" + strings.TrimLeft(path, "/")
	if len(query) > 0 {
		sep := "?"
		if strings.Contains(u, "?") {
			sep = "&"
		}
		u += sep + query.Encode()
	}
	return u
}

// Raw performs a request and returns the response; non-2xx statuses are
// returned as *APIError (with the body consumed). Rate limiting, server
// errors and network errors are retried with backoff (see retryable).
func (c *Client) Raw(method, path string, query url.Values, headers http.Header, body io.Reader) (*http.Response, error) {
	var data []byte
	if body != nil {
		var err error
		if data, err = io.ReadAll(body); err != nil {
			return nil, err
		}
	}
	u := c.URL(path, query)
	for attempt := 1; ; attempt++ {
		start := time.Now()
		resp, err := c.send(method, u, headers, body != nil, data)
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		c.debugf("%s %s -> %s (%s)", method, u, statusText(status, err), time.Since(start).Round(time.Millisecond))
		if attempt <= c.MaxRetries && retryable(method, status, err) {
			wait := backoff(attempt, resp)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			c.debugf("retrying in %s (attempt %d of %d)", wait.Round(time.Millisecond), attempt+1, c.MaxRetries+1)
			sleep(wait)
			continue
		}
		if err != nil {
			return nil, err
		}
		if resp.StatusCode >= 300 {
			defer resp.Body.Close()
			apiErr := parseError(resp)
			apiErr.Attempts = attempt
			return resp, apiErr
		}
		return resp, nil
	}
}

func (c *Client) send(method, u string, headers http.Header, hasBody bool, data []byte) (*http.Response, error) {
	var body io.Reader
	if hasBody {
		body = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, u, body)
	if err != nil {
		return nil, err
	}
	for k, vs := range headers {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if hasBody && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.User != "" || c.Password != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	return c.HTTP.Do(req)
}

// retryable reports whether a request should be sent again. 429 and 503
// mean the server did not handle it, so any method is retried. Other 5xx
// and network errors are retried only for idempotent methods: a POST may
// have taken effect (e.g. a waiver was created) before the error.
func retryable(method string, status int, err error) bool {
	switch {
	case status == http.StatusTooManyRequests || status == http.StatusServiceUnavailable:
		return true
	case method == http.MethodPost || method == http.MethodPatch:
		return false
	case err != nil:
		return true
	}
	return status == http.StatusInternalServerError || status == http.StatusBadGateway || status == http.StatusGatewayTimeout
}

// backoff honors Retry-After (in seconds, capped at 30s), else waits
// 0.5s, 1s, 2s, … with up to 50% jitter.
func backoff(attempt int, resp *http.Response) time.Duration {
	if resp != nil {
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 {
			return min(time.Duration(s)*time.Second, 30*time.Second)
		}
	}
	d := 500 * time.Millisecond << (attempt - 1)
	return d + rand.N(d/2+1)
}

func statusText(status int, err error) string {
	if err != nil {
		return err.Error()
	}
	return strconv.Itoa(status)
}

func (c *Client) debugf(format string, a ...any) {
	if c.Debug != nil {
		fmt.Fprintf(c.Debug, "st: "+format+"\n", a...)
	}
}

// parseError keeps short plain-text or JSON bodies; IQ Server mostly answers
// errors with a plain-text message.
func parseError(resp *http.Response) *APIError {
	e := &APIError{StatusCode: resp.StatusCode, Method: resp.Request.Method, URL: resp.Request.URL.String()}
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var payload struct {
		Message string `json:"message"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if json.Unmarshal(data, &payload) == nil {
		var msgs []string
		if payload.Message != "" {
			msgs = append(msgs, payload.Message)
		}
		for _, m := range payload.Errors {
			msgs = append(msgs, m.Message)
		}
		e.Message = strings.Join(msgs, "; ")
	}
	if e.Message == "" && len(data) > 0 && len(data) < 500 && !bytes.Contains(data, []byte("<html")) {
		e.Message = strings.TrimSpace(string(data))
	}
	return e
}

// Do sends body (JSON-encoded if non-nil) and decodes the response into out (if non-nil).
func (c *Client) Do(method, path string, query url.Values, body, out any) error {
	var r io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(data)
	}
	resp, err := c.Raw(method, path, query, nil, r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
