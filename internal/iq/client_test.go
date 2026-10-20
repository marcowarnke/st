package iq

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flaky answers the first len(statuses) requests with those statuses, then 200.
func flaky(t *testing.T, retryAfter string, statuses ...int) (*Client, *atomic.Int32, *[]time.Duration) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		i := int(n.Add(1)) - 1
		if i < len(statuses) {
			if retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			w.WriteHeader(statuses[i])
			return
		}
		w.Write(append([]byte(`{"echo":`), append(orNull(body), '}')...))
	}))
	t.Cleanup(srv.Close)
	var waits []time.Duration
	old := sleep
	sleep = func(d time.Duration) { waits = append(waits, d) }
	t.Cleanup(func() { sleep = old })
	return New(srv.URL, "u", "p"), &n, &waits
}

func orNull(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}

func TestRetryThenSucceed(t *testing.T) {
	c, n, waits := flaky(t, "", 503, 502, 500)
	var out struct{ Echo any }
	if err := c.Do("GET", "api/v2/applications", nil, nil, &out); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 4 || len(*waits) != 3 {
		t.Fatalf("requests=%d waits=%v", n.Load(), *waits)
	}
	for i, w := range *waits {
		base := 500 * time.Millisecond << i
		if w < base || w > base+base/2 {
			t.Errorf("wait %d = %s, want %s..%s", i, w, base, base+base/2)
		}
	}
}

func TestRetryGivesUp(t *testing.T) {
	c, n, _ := flaky(t, "", 500, 500, 500, 500, 500)
	err := c.Do("GET", "api/v2/applications", nil, nil, nil)
	if n.Load() != 4 || err == nil || !strings.Contains(err.Error(), "HTTP 500") || !strings.Contains(err.Error(), "gave up after 4 attempts") {
		t.Fatalf("requests=%d err=%v", n.Load(), err)
	}
}

func TestRetryAfterAndBodyReplay(t *testing.T) {
	c, n, waits := flaky(t, "2", 429)
	var out struct{ Echo map[string]any }
	if err := c.Do("POST", "api/v2/components/remediation/application/a1", nil, map[string]any{"x": 1}, &out); err != nil {
		t.Fatal(err)
	}
	if n.Load() != 2 || len(*waits) != 1 || (*waits)[0] != 2*time.Second || out.Echo["x"] != float64(1) {
		t.Fatalf("requests=%d waits=%v echo=%v", n.Load(), *waits, out.Echo)
	}
}

func TestNoRetryForPostServerError(t *testing.T) {
	c, n, _ := flaky(t, "", 500)
	if err := c.Do("POST", "api/v2/policyWaivers/application/a1/v1", nil, map[string]any{}, nil); err == nil || n.Load() != 1 {
		t.Fatalf("requests=%d err=%v", n.Load(), err)
	}
}

func TestNoRetryForClientErrors(t *testing.T) {
	c, n, _ := flaky(t, "", 404)
	if err := c.Do("GET", "api/v2/x", nil, nil, nil); !IsNotFound(err) || n.Load() != 1 || strings.Contains(err.Error(), "attempts") {
		t.Fatalf("requests=%d err=%v", n.Load(), err)
	}
}

func TestDebug(t *testing.T) {
	c, _, _ := flaky(t, "", 503)
	var buf bytes.Buffer
	c.Debug = &buf
	if err := c.Do("GET", "api/v2/applications", nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"GET " + c.BaseURL + "/api/v2/applications -> 503", "retrying in", "-> 200"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %q", want, out)
		}
	}
}
