package snyk

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestClient(srv *httptest.Server) *Client {
	return &Client{Token: "t", BaseURL: srv.URL, HTTP: srv.Client()}
}

// mustQuery builds a list query with the project scope filled in, failing
// the test when the options are not buildable.
func mustQuery(t *testing.T, o ListOptions) url.Values {
	t.Helper()
	q, err := BuildListQuery(o)
	if err != nil {
		t.Fatalf("BuildListQuery: %v", err)
	}
	return q
}

func TestListPaginationAcrossPages(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/rest/orgs/o/issues", func(w http.ResponseWriter, r *http.Request) {
		requests++
		q := r.URL.Query()
		if requests == 1 {
			if q.Get("version") != APIVersion {
				t.Errorf("version = %q", q.Get("version"))
			}
			if q.Get("limit") != "100" {
				t.Errorf("limit = %q", q.Get("limit"))
			}
			if r.Header.Get("Authorization") != "token t" {
				t.Errorf("authorization = %q", r.Header.Get("Authorization"))
			}
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		switch requests {
		case 1:
			fmt.Fprintf(w, `{"data":[{"id":"b"},{"id":"a"}],"links":{"next":"%s/rest/orgs/o/issues?starting_after=x"}}`, srv.URL)
		default:
			fmt.Fprint(w, `{"data":[{"id":"c"}],"links":{}}`)
		}
	})

	got, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
	if len(got) != 3 || got[0].ID != "b" || got[2].ID != "c" {
		t.Fatalf("got %d items, ids %v %v %v", len(got), got[0].ID, got[1].ID, got[2].ID)
	}
}

func TestListFollowsRelativeNextLink(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/rest/orgs/o/issues", func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if requests == 1 {
			fmt.Fprint(w, `{"data":[{"id":"a"},{"id":"b"}],"meta":{"links":{"next":"/rest/orgs/o/issues?starting_after=y"}}}`)
			return
		}
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	})

	got, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want 2 (relative next not followed)", requests)
	}
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
}

func TestGetRetriesOn429(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		fmt.Fprint(w, `{"data":{"id":"x","attributes":{"title":"T","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
	}))
	defer srv.Close()

	raw, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
	if raw.ID != "x" {
		t.Fatalf("id = %q", raw.ID)
	}
}

func TestGetRetriesOnTransient5xx(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `upstream temporarily unavailable`)
			return
		}
		fmt.Fprint(w, `{"data":{"id":"x","attributes":{"title":"T","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
	}))
	defer srv.Close()

	raw, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatalf("attempts = %d, want 3", attempts)
	}
	if raw.ID != "x" {
		t.Fatalf("id = %q", raw.ID)
	}
}

func TestGetFailsAfterExhaustedTransientRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil {
		t.Fatal("want error")
	}
	if !containsAll(err.Error(), "HTTP 502") {
		t.Fatalf("err = %v", err)
	}
	if attempts != MaxRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, MaxRetries+1)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	cases := []struct {
		header string
		want   time.Duration
	}{
		{"", time.Second},
		{"0", 0},
		{"2", 2 * time.Second},
		{"-3", time.Second},
		{"abc", time.Second},
		{"99999", maxRetryWait},
	}
	for _, c := range cases {
		h := http.Header{}
		if c.header != "" {
			h.Set("Retry-After", c.header)
		}
		if got := retryAfter(h); got != c.want {
			t.Errorf("retryAfter(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestTransientBackoffCap(t *testing.T) {
	if got := transientBackoff(50); got != 2*time.Second {
		t.Errorf("transientBackoff(50) = %v, want cap 2s", got)
	}
	if got := transientBackoff(0); got != 250*time.Millisecond {
		t.Errorf("transientBackoff(0) = %v, want 250ms", got)
	}
}

func TestBodySnippetTruncates(t *testing.T) {
	long := strings.Repeat("x", 400)
	got := bodySnippet([]byte(long))
	if len(got) != 300 {
		t.Fatalf("len = %d, want 300", len(got))
	}
	if got := bodySnippet([]byte("short")); got != "short" {
		t.Errorf("got %q", got)
	}
}

func TestListDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{invalid json`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err == nil || !containsAll(err.Error(), "decode list response") {
		t.Fatalf("err = %v", err)
	}
}

func TestGetDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[1,2]}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil || !containsAll(err.Error(), "decode issue response") {
		t.Fatalf("err = %v", err)
	}
}

func TestListMaxPagesGuard(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintf(w, `{"data":[{"id":"i%d"}],"links":{"next":"/rest/orgs/o/issues?p=%d"}}`, requests, requests)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err == nil || !containsAll(err.Error(), fmt.Sprintf("pagination exceeded %d pages", MaxPages)) {
		t.Fatalf("err = %v", err)
	}
	if requests != MaxPages {
		t.Fatalf("requests = %d, want %d", requests, MaxPages)
	}
}

func TestNewClientBaseURLFromEnv(t *testing.T) {
	t.Setenv("SNYK_API_URL", "")
	c := NewClient("tok")
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("base = %q", c.BaseURL)
	}
	if c.HTTP.Timeout != httpTimeout {
		t.Errorf("http timeout = %v, want bounded %v", c.HTTP.Timeout, httpTimeout)
	}
	t.Setenv("SNYK_API_URL", "http://localhost:1234/")
	c = NewClient("tok")
	if c.BaseURL != "http://localhost:1234" {
		t.Errorf("trailing slash not trimmed: %q", c.BaseURL)
	}
}

func TestGetReturnsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","detail":"bad token"}]}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil {
		t.Fatal("want error")
	}
	if !containsAll(err.Error(), "HTTP 401", "bad token") {
		t.Fatalf("err = %v", err)
	}
}

func TestGet429ExhaustsRetries(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil || !containsAll(err.Error(), "HTTP 429") {
		t.Fatalf("err = %v", err)
	}
	if attempts != MaxRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, MaxRetries+1)
	}
}

func TestListContextCanceledFailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		_, err := newTestClient(srv).List(ctx, "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !stringContains(err.Error(), "context canceled") {
			t.Fatalf("err = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("List did not honor canceled context")
	}
}

func TestBuildListQuery(t *testing.T) {
	t.Run("empty project ID is rejected", func(t *testing.T) {
		_, err := BuildListQuery(ListOptions{})
		if err == nil || !containsAll(err.Error(), "project ID") {
			t.Fatalf("err = %v, want project ID required", err)
		}
	})
	t.Run("defaults filter open and not ignored", func(t *testing.T) {
		q := mustQuery(t, ListOptions{ProjectID: "p1"})
		assertParam(t, q, "status", "open")
		assertParam(t, q, "ignored", "false")
		assertParam(t, q, "scan_item.id", "p1")
		assertParam(t, q, "scan_item.type", "project")
		if q.Has("effective_severity_level") {
			t.Error("unexpected effective_severity_level")
		}
	})
	t.Run("explicit status overrides default", func(t *testing.T) {
		q := mustQuery(t, ListOptions{Status: "open,resolved", ProjectID: "p1"})
		assertParam(t, q, "status", "open,resolved")
		assertParam(t, q, "ignored", "false")
	})
	t.Run("include ignored drops the filter", func(t *testing.T) {
		q := mustQuery(t, ListOptions{IncludeIgnored: true, ProjectID: "p1"})
		if q.Has("ignored") {
			t.Error("ignored should be absent")
		}
		assertParam(t, q, "status", "open")
	})
	t.Run("type=code is always sent", func(t *testing.T) {
		q := mustQuery(t, ListOptions{
			Severity:  "high,critical",
			ProjectID: "p1",
		})
		assertParam(t, q, "type", "code")
		assertParam(t, q, "effective_severity_level", "high,critical")
		assertParam(t, q, "scan_item.id", "p1")
		assertParam(t, q, "scan_item.type", "project")
	})
	t.Run("code flows are explicit", func(t *testing.T) {
		q := mustQuery(t, ListOptions{ProjectID: "p1"})
		assertParam(t, q, "include_code_flows", "false")
		q = mustQuery(t, ListOptions{IncludeCodeFlows: true, ProjectID: "p1"})
		assertParam(t, q, "include_code_flows", "true")
	})
}

func assertParam(t *testing.T, q url.Values, key, want string) {
	t.Helper()
	if got := q.Get(key); got != want {
		t.Errorf("%s = %q, want %q", key, got, want)
	}
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		if !stringContains(s, sub) {
			return false
		}
	}
	return true
}

func stringContains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
