package cloud

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/elecnix/terraform-permcheck/internal/iam"
)

// registry serves a fake CloudFormation schema registry that answers every
// request with status, and returns a provider pointed at it.
func registry(t *testing.T, status int) *AWSProvider {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		if status == http.StatusOK {
			fmt.Fprint(w, `{"typeName":"AWS::Thing::Widget","handlers":{"create":{"permissions":["thing:CreateWidget"]}}}`)
		}
	}))
	t.Cleanup(srv.Close)
	return &AWSProvider{client: srv.Client(), baseURL: srv.URL, sleep: noSleep}
}

// noSleep skips the wait between registry attempts.
func noSleep(time.Duration) {}

// TestAWSProvider_ErrorKinds checks how the registry adapter marks each
// failure. The registry answers 403 for a key it does not hold (it sits on
// S3) and 404 is treated the same. Any other status, a network failure and a
// body that does not parse say nothing about the type, so they mark a failed
// lookup.
func TestAWSProvider_ErrorKinds(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{http.StatusForbidden, iam.ErrUnknownType},
		{http.StatusNotFound, iam.ErrUnknownType},
		{http.StatusInternalServerError, iam.ErrLookupFailed},
		{http.StatusServiceUnavailable, iam.ErrLookupFailed},
		{http.StatusTooManyRequests, iam.ErrLookupFailed},
	}
	for _, tc := range cases {
		t.Run(http.StatusText(tc.status), func(t *testing.T) {
			_, err := registry(t, tc.status).Resolve("aws_thing_widget")
			if !errors.Is(err, tc.want) {
				t.Errorf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAWSProvider_Resolves(t *testing.T) {
	s, err := registry(t, http.StatusOK).Resolve("aws_thing_widget")
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Actions("create"); len(got) != 1 || got[0] != "thing:CreateWidget" {
		t.Errorf("create = %v", got)
	}
}

func TestAWSProvider_NetworkFailureIsLookupFailure(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close() // nothing listens any more
	p := &AWSProvider{client: &http.Client{Timeout: time.Second}, baseURL: url, sleep: noSleep}
	if _, err := p.Resolve("aws_thing_widget"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Errorf("err = %v, want ErrLookupFailed", err)
	}
}

func TestAWSProvider_BadBodyIsLookupFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"typeName":`)
	}))
	t.Cleanup(srv.Close)
	p := &AWSProvider{client: srv.Client(), baseURL: srv.URL}
	if _, err := p.Resolve("aws_thing_widget"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Errorf("err = %v, want ErrLookupFailed", err)
	}
}

func TestAWSProvider_NoRegistryKeyIsUnknown(t *testing.T) {
	if _, err := NewAWSProvider().Resolve("google_storage_bucket"); !errors.Is(err, iam.ErrUnknownType) {
		t.Errorf("err = %v, want ErrUnknownType", err)
	}
}

func TestNewAWSProvider_HasTimeout(t *testing.T) {
	if NewAWSProvider().client.Timeout == 0 {
		t.Error("registry client has no timeout, so a stalled registry hangs the run")
	}
}

// failingProvider fails every lookup with err.
type failingProvider struct{ err error }

func (p failingProvider) Resolve(string) (*iam.Schema, error) { return nil, p.err }

func TestChainProvider_ErrorKinds(t *testing.T) {
	unknown := &mockProvider{schemas: map[string]*iam.Schema{}}
	down := failingProvider{fmt.Errorf("HTTP 503: %w", iam.ErrLookupFailed)}

	if _, err := NewChainProvider(unknown, unknown).Resolve("aws_x"); !errors.Is(err, iam.ErrUnknownType) {
		t.Errorf("every source says not found: err = %v, want ErrUnknownType", err)
	}
	if _, err := NewChainProvider(unknown, down).Resolve("aws_x"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Errorf("the fallback is down: err = %v, want ErrLookupFailed", err)
	}
	if _, err := NewChainProvider(down, unknown).Resolve("aws_x"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Errorf("the first source is down: err = %v, want ErrLookupFailed", err)
	}
}

// TestChainProvider_FillFailureIsAnError checks that a failed lookup while
// filling an incomplete operation is an error. Dropping it would report the
// operation as needing only what the first source found.
func TestChainProvider_FillFailureIsAnError(t *testing.T) {
	primary := &mockProvider{schemas: map[string]*iam.Schema{
		"aws_x": {TypeName: "aws_x", Ops: ungated(map[string][]string{"create": {"x:Tag"}}), Incomplete: map[string]bool{"create": true}},
	}}
	down := failingProvider{fmt.Errorf("HTTP 503: %w", iam.ErrLookupFailed)}
	if _, err := NewChainProvider(primary, down).Resolve("aws_x"); !errors.Is(err, iam.ErrLookupFailed) {
		t.Errorf("err = %v, want ErrLookupFailed", err)
	}
}
