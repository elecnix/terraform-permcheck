package cloud

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

const widgetSchema = `{"typeName":"AWS::Thing::Widget","handlers":{"create":{"permissions":["thing:CreateWidget"]}}}`

// flakyRegistry serves a fake registry whose handler answers request n
// (counted from 0, per path) with respond(n, w). It returns the provider, a
// function that reports the request count per path, and the sleeps the
// provider asked for between attempts.
func flakyRegistry(t *testing.T, client *http.Client, respond func(n int, w http.ResponseWriter)) (*AWSProvider, func(path string) int, *[]time.Duration) {
	t.Helper()
	var mu sync.Mutex
	counts := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n := counts[r.URL.Path]
		counts[r.URL.Path]++
		mu.Unlock()
		respond(n, w)
	}))
	t.Cleanup(srv.Close)
	if client == nil {
		client = srv.Client()
	}
	var sleeps []time.Duration
	p := &AWSProvider{client: client, baseURL: srv.URL, sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}
	count := func(path string) int {
		mu.Lock()
		defer mu.Unlock()
		return counts[path]
	}
	return p, count, &sleeps
}

// TestAWSProvider_RetriesTransientStatus checks that a 5xx or a 429 is
// retried, so one bad answer from the registry does not fail the run.
func TestAWSProvider_RetriesTransientStatus(t *testing.T) {
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusTooManyRequests} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			p, count, _ := flakyRegistry(t, nil, func(n int, w http.ResponseWriter) {
				if n < 2 {
					w.WriteHeader(status)
					return
				}
				fmt.Fprint(w, widgetSchema)
			})
			if _, err := p.Resolve("aws_thing_widget"); err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got := count("/aws-thing-widget.json"); got != 3 {
				t.Errorf("requests = %d, want 3", got)
			}
		})
	}
}

// TestAWSProvider_RetriesAreBounded checks that a registry that keeps failing
// gets three attempts per key, then a failed lookup.
func TestAWSProvider_RetriesAreBounded(t *testing.T) {
	p, count, sleeps := flakyRegistry(t, nil, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusServiceUnavailable) })
	_, err := p.Resolve("aws_thing_widget")
	if !errors.Is(err, iam.ErrLookupFailed) {
		t.Fatalf("err = %v, want ErrLookupFailed", err)
	}
	for _, path := range []string{"/aws-thing-widget.json", "/aws-thing-thingwidget.json"} {
		if got := count(path); got != 3 {
			t.Errorf("%s: requests = %d, want 3", path, got)
		}
	}
	if len(*sleeps) != 4 {
		t.Errorf("sleeps = %v, want 2 per key", *sleeps)
	}
}

// TestAWSProvider_BackoffGrows checks that the wait doubles between attempts,
// with jitter that keeps each wait between half and all of its step.
func TestAWSProvider_BackoffGrows(t *testing.T) {
	p, _, sleeps := flakyRegistry(t, nil, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusBadGateway) })
	_, _ = p.Resolve("aws_lb")
	if len(*sleeps) != 2 {
		t.Fatalf("sleeps = %v, want 2", *sleeps)
	}
	for i, d := range *sleeps {
		step := retryBackoff << i
		if d < step/2 || d > step {
			t.Errorf("sleep %d = %v, want between %v and %v", i, d, step/2, step)
		}
	}
}

// TestAWSProvider_HonoursRetryAfter checks that a 429 waits as long as its
// Retry-After header asks, up to a cap.
func TestAWSProvider_HonoursRetryAfter(t *testing.T) {
	for _, tc := range []struct {
		header string
		want   time.Duration
	}{
		{"7", 7 * time.Second},
		{"3600", maxRetryAfter},
	} {
		t.Run(tc.header, func(t *testing.T) {
			p, _, sleeps := flakyRegistry(t, nil, func(n int, w http.ResponseWriter) {
				if n == 0 {
					w.Header().Set("Retry-After", tc.header)
					w.WriteHeader(http.StatusTooManyRequests)
					return
				}
				fmt.Fprint(w, widgetSchema)
			})
			if _, err := p.Resolve("aws_lb"); err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if len(*sleeps) != 1 || (*sleeps)[0] != tc.want {
				t.Errorf("sleeps = %v, want [%v]", *sleeps, tc.want)
			}
		})
	}
}

// TestAWSProvider_DoesNotRetryUnknownType checks that a 403 or 404, the
// registry's answer for a key it does not hold, is final.
func TestAWSProvider_DoesNotRetryUnknownType(t *testing.T) {
	p, count, sleeps := flakyRegistry(t, nil, func(_ int, w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) })
	if _, err := p.Resolve("aws_lb"); !errors.Is(err, iam.ErrUnknownType) {
		t.Fatalf("err = %v, want ErrUnknownType", err)
	}
	if got := count("/aws-elasticloadbalancingv2-loadbalancer.json"); got != 1 || len(*sleeps) != 0 {
		t.Errorf("requests = %d, sleeps = %v; want 1 request and no sleep", got, *sleeps)
	}
}

// TestAWSProvider_RetriesDroppedConnection checks that a connection the
// registry drops is retried.
func TestAWSProvider_RetriesDroppedConnection(t *testing.T) {
	p, count, _ := flakyRegistry(t, nil, func(n int, w http.ResponseWriter) {
		if n == 0 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		fmt.Fprint(w, widgetSchema)
	})
	if _, err := p.Resolve("aws_lb"); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got := count("/aws-elasticloadbalancingv2-loadbalancer.json"); got != 2 {
		t.Errorf("requests = %d, want 2", got)
	}
}

// TestAWSProvider_DoesNotRetryTimeout checks that a request that hits the
// client timeout is not retried: a stalled registry would otherwise cost
// three timeouts per key.
func TestAWSProvider_DoesNotRetryTimeout(t *testing.T) {
	release := make(chan struct{})
	p, count, _ := flakyRegistry(t, &http.Client{Timeout: 50 * time.Millisecond}, func(int, http.ResponseWriter) {
		select {
		case <-release:
		case <-time.After(5 * time.Second):
		}
	})
	// Registered after the server, so it runs first and srv.Close need not
	// wait for the stalled handler.
	t.Cleanup(func() { close(release) })
	if _, err := p.Resolve("aws_lb"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Fatalf("err = %v, want ErrLookupFailed", err)
	}
	if got := count("/aws-elasticloadbalancingv2-loadbalancer.json"); got != 1 {
		t.Errorf("requests = %d, want 1", got)
	}
}
