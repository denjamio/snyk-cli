package snyk

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func newTestClient(srv *httptest.Server) *Client {
	return &Client{Token: "t", BaseURL: srv.URL, HTTP: srv.Client(), UserAgent: defaultUserAgent}
}

// kindOf asserts err is the typed *Error and returns its kind.
func kindOf(t *testing.T, err error) Kind {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) {
		t.Fatalf("err = %v, want a typed *Error", err)
	}
	return e.Kind
}

// Unwrap exposes the wrapped cause, so errors.Is and errors.As keep
// working through the typed error.
func TestErrorUnwrap(t *testing.T) {
	cause := errors.New("boom")
	wrapped := &Error{Kind: KindNetwork, err: cause}
	if !errors.Is(wrapped, cause) {
		t.Fatal("errors.Is(wrapped, cause) = false; Unwrap broken")
	}
	if wrapped.Error() != "boom" {
		t.Fatalf("Error() = %q, want the wrapped message unchanged", wrapped.Error())
	}
	var e *Error
	if !errors.As(wrapped, &e) || e.Kind != KindNetwork {
		t.Fatal("errors.As failed on the typed error")
	}
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

	got, truncated, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err != nil {
		t.Fatal(err)
	}
	if truncated {
		t.Fatal("a two-page listing must not report truncation")
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

	got, _, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
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

func TestListReportsPaginationProgress(t *testing.T) {
	requests := 0
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	defer srv.Close()

	mux.HandleFunc("/rest/orgs/o/issues", func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if requests == 1 {
			fmt.Fprintf(w, `{"data":[{"id":"a"},{"id":"b"}],"links":{"next":"%s/rest/orgs/o/issues?p=2"}}`, srv.URL)
			return
		}
		fmt.Fprint(w, `{"data":[{"id":"c"}],"links":{}}`)
	})

	var events []string
	c := newTestClient(srv)
	c.Progress = func(event string) { events = append(events, event) }
	if _, _, err := c.List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"})); err != nil {
		t.Fatal(err)
	}
	want := []string{"page 1: 2 issues", "page 2: 1 issue"}
	if len(events) != len(want) {
		t.Fatalf("events = %v, want %v", events, want)
	}
	for i := range want {
		if events[i] != want[i] {
			t.Errorf("event %d = %q, want %q", i, events[i], want[i])
		}
	}
}

func TestGetReportsRetryProgress(t *testing.T) {
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

	var events []string
	c := newTestClient(srv)
	c.Progress = func(event string) { events = append(events, event) }
	if _, err := c.Get(context.Background(), "o", "x"); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %v, want one retry event", events)
	}
	if !strings.Contains(events[0], "HTTP 429") || !strings.Contains(events[0], fmt.Sprintf("attempt 1/%d", MaxRetries)) {
		t.Errorf("event = %q", events[0])
	}
}

func TestClientWithoutProgressIsSilent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()

	if _, _, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"})); err != nil {
		t.Fatal(err)
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
	if !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("err = %v", err)
	}
	if got := kindOf(t, err); got != KindTransient {
		t.Fatalf("kind = %q, want %q", got, KindTransient)
	}
	if attempts != MaxRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, MaxRetries+1)
	}
}

func TestRetryAfterParsing(t *testing.T) {
	// An HTTP-date far enough in the future is capped at maxRetryWait.
	farFuture := time.Now().Add(time.Hour).UTC().Format(http.TimeFormat)
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
		// HTTP-date form (RFC 9110 §10.2.1): past dates fall back to the
		// 1s default, far-future dates are capped.
		{farFuture, maxRetryWait},
		{"Mon, 02 Jan 2006 15:04:05 GMT", time.Second},
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

// A near-future HTTP-date inside the cap is honored (up to 1s of slack so
// the test stays deterministic).
func TestRetryAfterHTTPDateInsideCap(t *testing.T) {
	header := time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat)
	h := http.Header{}
	h.Set("Retry-After", header)
	if got := retryAfter(h); got < 2*time.Second || got > maxRetryWait {
		t.Errorf("retryAfter(%q) = %v, want a wait in (2s, %v]", header, got, maxRetryWait)
	}
}

// Full-jitter exponential backoff: only the [0, cap) window is pinned,
// since the point of jitter is that the wait is random.
func TestTransientRetryDelay(t *testing.T) {
	cases := []struct {
		attempt int
		cap     time.Duration
	}{
		{0, 250 * time.Millisecond},
		{1, 500 * time.Millisecond},
		{2, time.Second},
		{3, 2 * time.Second},
		{50, 2 * time.Second},
	}
	for _, c := range cases {
		got := transientRetryDelay(c.attempt)
		if got < 0 || got >= c.cap {
			t.Errorf("transientRetryDelay(%d) = %v, want a wait in [0, %v)", c.attempt, got, c.cap)
		}
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

// The 300-byte cut can split a UTF-8 sequence; the snippet must stay valid.
func TestBodySnippetIsUTF8Safe(t *testing.T) {
	// 299 ASCII bytes + é (2 bytes): the cut at 300 leaves a dangling byte.
	got := bodySnippet([]byte(strings.Repeat("x", 299) + "é"))
	if !utf8.ValidString(got) {
		t.Fatalf("snippet is not valid UTF-8: %q", got)
	}
	if len(got) != 299 {
		t.Fatalf("len = %d, want 299 (dangling byte dropped)", len(got))
	}
}

func TestListDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{invalid json`)
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err == nil || !strings.Contains(err.Error(), "decode list response") {
		t.Fatalf("err = %v", err)
	}
	if got := kindOf(t, err); got != KindDecode {
		t.Fatalf("kind = %q, want %q", got, KindDecode)
	}
}

func TestGetDecodeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[1,2]}`)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil || !strings.Contains(err.Error(), "decode issue response") {
		t.Fatalf("err = %v", err)
	}
	if got := kindOf(t, err); got != KindDecode {
		t.Fatalf("kind = %q, want %q", got, KindDecode)
	}
}

// The MaxPages cap is a safety valve, not a failure: when more pages
// remain, the issues fetched so far come back with truncated=true.
func TestListStopsAtMaxPagesAndReportsTruncation(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		fmt.Fprintf(w, `{"data":[{"id":"i%d"}],"links":{"next":"/rest/orgs/o/issues?p=%d"}}`, requests, requests)
	}))
	defer srv.Close()

	got, truncated, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err != nil {
		t.Fatalf("cap must not fail the run: %v", err)
	}
	if !truncated {
		t.Fatal("truncated = false, want true when more pages remain")
	}
	if requests != MaxPages {
		t.Fatalf("requests = %d, want %d", requests, MaxPages)
	}
	if len(got) != MaxPages {
		t.Fatalf("issues = %d, want the %d fetched before the cap", len(got), MaxPages)
	}
}

func TestNewClientBaseURL(t *testing.T) {
	c := NewClient("tok", "")
	if c.BaseURL != DefaultBaseURL {
		t.Errorf("empty base = %q, want default %q", c.BaseURL, DefaultBaseURL)
	}
	if c.HTTP.Timeout != httpTimeout {
		t.Errorf("http timeout = %v, want bounded %v", c.HTTP.Timeout, httpTimeout)
	}
	c = NewClient("tok", "http://localhost:1234/")
	if c.BaseURL != "http://localhost:1234" {
		t.Errorf("trailing slash not trimmed: %q", c.BaseURL)
	}
	if c.UserAgent == "" {
		t.Error("NewClient must set a default User-Agent")
	}
}

// cursor resolves the pagination link: relative cursors anchor at the
// base URL, same-origin absolute ones pass through, and anything pointing
// outside the base URL is refused — following it would send the
// Authorization token to another host.
func TestCursorResolvesAndRejectsLinks(t *testing.T) {
	cl := &Client{BaseURL: "https://api.eu.snyk.io"}
	cases := []struct {
		name string
		in   []string
		want string
		err  bool
	}{
		{"no link", []string{"", ""}, "", false},
		{"relative", []string{"/rest/orgs/o/issues?starting_after=x"}, "https://api.eu.snyk.io/rest/orgs/o/issues?starting_after=x", false},
		{"relative without slash", []string{"rest/orgs/o/issues"}, "https://api.eu.snyk.io/rest/orgs/o/issues", false},
		{"same origin absolute", []string{"https://api.eu.snyk.io/rest?n=2"}, "https://api.eu.snyk.io/rest?n=2", false},
		{"meta fallback", []string{"", "/rest?n=2"}, "https://api.eu.snyk.io/rest?n=2", false},
		{"top-level wins", []string{"/rest?n=1", "/rest?n=2"}, "https://api.eu.snyk.io/rest?n=1", false},
		{"cross origin host", []string{"https://evil.example/rest"}, "", true},
		{"cross origin scheme", []string{"http://api.eu.snyk.io/rest"}, "", true},
		{"protocol relative", []string{"//evil.example/rest"}, "", true},
		{"unparseable", []string{"/x%zz"}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cl.cursor(tc.in...)
			if tc.err {
				if err == nil {
					t.Fatalf("cursor(%v) = %q, want an error", tc.in, got)
				}
				if got := kindOf(t, err); got != KindAPI {
					t.Fatalf("kind = %q, want %q", got, KindAPI)
				}
				return
			}
			if err != nil {
				t.Fatalf("cursor(%v): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("cursor(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// A compromised or misbehaving API must not be able to redirect the
// pagination cursor to another host: the client refuses to follow the
// cursor instead of sending it the Authorization token, and the failure
// is a typed api error.
func TestListRefusesCrossOriginCursor(t *testing.T) {
	attackerHits := 0
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer attacker.Close()

	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, `{"data":[{"id":"a"}],"links":{"next":"%s/rest/orgs/o/issues?steal=1"}}`, attacker.URL)
	}))
	defer srv.Close()

	_, _, err := newTestClient(srv).List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
	if err == nil {
		t.Fatal("want an error for a cross-origin cursor")
	}
	if got := kindOf(t, err); got != KindAPI {
		t.Fatalf("kind = %q, want %q", got, KindAPI)
	}
	if !strings.Contains(err.Error(), "refusing to follow") {
		t.Errorf("err = %v, want the refusal reason", err)
	}
	if attackerHits != 0 {
		t.Fatalf("the cursor host received %d requests; the token must never leave the origin", attackerHits)
	}
	if requests != 1 {
		t.Errorf("api requests = %d, want 1", requests)
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
	if !strings.Contains(err.Error(), "HTTP 401") || !strings.Contains(err.Error(), "bad token") {
		t.Fatalf("err = %v", err)
	}
	if got := kindOf(t, err); got != KindAuth {
		t.Fatalf("kind = %q, want %q", got, KindAuth)
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
	if err == nil || !strings.Contains(err.Error(), "HTTP 429") {
		t.Fatalf("err = %v", err)
	}
	if got := kindOf(t, err); got != KindRateLimit {
		t.Fatalf("kind = %q, want %q", got, KindRateLimit)
	}
	if attempts != MaxRetries+1 {
		t.Fatalf("attempts = %d, want %d", attempts, MaxRetries+1)
	}
}

// The retry budget caps the cumulative wait: a hostile Retry-After that
// would exceed it fails fast with the typed rate_limit error instead of
// stalling the request — and without ever sleeping, since the check runs
// before the wait.
func TestRetryBudgetExhaustsOnHostileRetryAfter(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.RetryBudget = 500 * time.Millisecond
	_, err := c.Get(context.Background(), "o", "x")
	if err == nil || !strings.Contains(err.Error(), "retry budget exhausted") {
		t.Fatalf("err = %v, want the budget error", err)
	}
	if got := kindOf(t, err); got != KindRateLimit {
		t.Fatalf("kind = %q, want %q", got, KindRateLimit)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (budget trips before the first wait)", attempts)
	}
}

// A budget within reach lets retries proceed normally: waits that fit do
// not trip it, and the run succeeds.
func TestRetryBudgetAccommodatesSmallWaits(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		if attempts == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, `{"data":{"id":"x","attributes":{"title":"T","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	c.RetryBudget = 30 * time.Second
	raw, err := c.Get(context.Background(), "o", "x")
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || raw.ID != "x" {
		t.Fatalf("attempts = %d, id = %q", attempts, raw.ID)
	}
}

func TestGetContextCanceledDuringRetrySleep(t *testing.T) {
	attempts := 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(http.StatusTooManyRequests)
		if attempts == 1 {
			cancel() // abort while the client sits in the retry wait
		}
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(ctx, "o", "x")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v, want context canceled", err)
	}
	if attempts != 1 {
		t.Fatalf("attempts = %d, want 1 (retry wait must abort on cancel)", attempts)
	}
}

func TestResponseBodyOverLimitIsRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(bytes.Repeat([]byte("x"), maxBodyBytes+1))
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil || !strings.Contains(err.Error(), "response body exceeds") {
		t.Fatalf("err = %v, want over-limit rejection", err)
	}
}

func TestResponseBodyReadErrorIsPropagated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "partial")
		w.(http.Flusher).Flush() // headers + first chunk reach the client
		panic(http.ErrAbortHandler)
	}))
	defer srv.Close()

	_, err := newTestClient(srv).Get(context.Background(), "o", "x")
	if err == nil || !strings.Contains(err.Error(), "read response body") {
		t.Fatalf("err = %v, want read error propagated", err)
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
		_, _, err := newTestClient(srv).List(ctx, "o", mustQuery(t, ListOptions{ProjectID: "p1"}))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Fatalf("err = %v, want context canceled", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("List did not honor canceled context")
	}
}

// TestListDoesNotMutateCallerQuery pins that List adds its pagination
// params to a private copy: the caller's url.Values must come back exactly
// as it was passed in.
func TestListDoesNotMutateCallerQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()

	q := mustQuery(t, ListOptions{ProjectID: "p1"})
	if _, _, err := newTestClient(srv).List(context.Background(), "o", q); err != nil {
		t.Fatal(err)
	}
	if _, ok := q["version"]; ok {
		t.Error("List added version to the caller's query")
	}
	if _, ok := q["limit"]; ok {
		t.Error("List added limit to the caller's query")
	}
}

func TestBuildListQuery(t *testing.T) {
	t.Run("empty project ID is rejected", func(t *testing.T) {
		_, err := BuildListQuery(ListOptions{})
		if err == nil || !strings.Contains(err.Error(), "project ID") {
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

// flakyTransport fails the first `failures` requests with a transport
// error, then delegates to base — a stand-in for connection refused/reset.
type flakyTransport struct {
	failures int
	calls    int
	base     http.RoundTripper
}

func (t *flakyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	t.calls++
	if t.calls <= t.failures {
		return nil, errors.New("connection reset by peer")
	}
	return t.base.RoundTrip(r)
}

func newFlakyClient(srv *httptest.Server, failures int) (*Client, *flakyTransport) {
	tr := &flakyTransport{failures: failures, base: http.DefaultTransport}
	c := newTestClient(srv)
	c.HTTP.Transport = tr
	return c, tr
}

// GET never mutates state, so a transport failure retries like a
// transient status; a later attempt goes through and the wait is
// reported as progress.
func TestGetRetriesOnNetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, `{"data":{"id":"x","attributes":{"title":"T","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
	}))
	defer srv.Close()

	var events []string
	c, tr := newFlakyClient(srv, 1)
	c.Progress = func(event string) { events = append(events, event) }
	raw, err := c.Get(context.Background(), "o", "x")
	if err != nil {
		t.Fatal(err)
	}
	if tr.calls != 2 {
		t.Fatalf("calls = %d, want 2 (one retry)", tr.calls)
	}
	if raw.ID != "x" {
		t.Fatalf("id = %q", raw.ID)
	}
	if len(events) != 1 || !strings.Contains(events[0], "network error") || !strings.Contains(events[0], "attempt 1/"+fmt.Sprint(MaxRetries)) {
		t.Errorf("events = %v, want one network retry event", events)
	}
}

func TestNetworkErrorExhaustsRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c, tr := newFlakyClient(srv, 1<<30) // always fail
	_, err := c.Get(context.Background(), "o", "x")
	if err == nil || !strings.Contains(err.Error(), "connection reset by peer") {
		t.Fatalf("err = %v, want the wrapped transport error", err)
	}
	if got := kindOf(t, err); got != KindNetwork {
		t.Fatalf("kind = %q, want %q", got, KindNetwork)
	}
	if tr.calls != MaxRetries+1 {
		t.Fatalf("calls = %d, want %d", tr.calls, MaxRetries+1)
	}
}

// A caller-canceled context ends the run on the first transport failure —
// no retries, no waits.
func TestNetworkErrorCanceledContextFailsFast(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c, tr := newFlakyClient(srv, 1<<30)
	_, err := c.Get(ctx, "o", "x")
	if err == nil || !strings.Contains(err.Error(), "context canceled") {
		t.Fatalf("err = %v, want context canceled", err)
	}
	if tr.calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retries after cancel)", tr.calls)
	}
}

func TestUserAgentHeaderIsSent(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if strings.HasSuffix(r.URL.Path, "/issues/x") {
			fmt.Fprint(w, `{"data":{"id":"x","attributes":{"title":"T","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()

	c := newTestClient(srv)
	if _, _, err := c.List(context.Background(), "o", mustQuery(t, ListOptions{ProjectID: "p1"})); err != nil {
		t.Fatal(err)
	}
	if got != "snyk-cli" {
		t.Errorf("default User-Agent = %q, want snyk-cli", got)
	}

	c.UserAgent = "snyk-cli/v9.9.9"
	if _, err := c.Get(context.Background(), "o", "x"); err != nil {
		t.Fatal(err)
	}
	if got != "snyk-cli/v9.9.9" {
		t.Errorf("overridden User-Agent = %q, want snyk-cli/v9.9.9", got)
	}
}
