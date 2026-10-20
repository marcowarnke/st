// Package iq is a minimal Sonatype IQ Server (Lifecycle) REST client.
package iq

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
}

func New(baseURL, user, password string) *Client {
	return &Client{
		BaseURL:  strings.TrimRight(baseURL, "/"),
		User:     user,
		Password: password,
		HTTP:     &http.Client{Timeout: 60 * time.Second},
	}
}

type APIError struct {
	StatusCode int
	Method     string
	URL        string
	Message    string
}

func (e *APIError) Error() string {
	msg := e.Message
	if msg == "" {
		msg = http.StatusText(e.StatusCode)
	}
	return fmt.Sprintf("HTTP %d: %s (%s %s)", e.StatusCode, msg, e.Method, e.URL)
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
// returned as *APIError (with the body consumed).
func (c *Client) Raw(method, path string, query url.Values, headers http.Header, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, c.URL(path, query), body)
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
	if body != nil && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.User != "" || c.Password != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		defer resp.Body.Close()
		return resp, parseError(resp)
	}
	return resp, nil
}

// parseError keeps short plain-text or JSON bodies; IQ Server mostly answers
// errors with a plain-text message.
func parseError(resp *http.Response) error {
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
