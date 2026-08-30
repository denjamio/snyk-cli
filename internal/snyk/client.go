package snyk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultBaseURL = "https://api.eu.snyk.io"
	APIVersion     = "2026-03-25"
	PageLimit      = 100
	MaxPages       = 100
	MaxRetries     = 5
	httpTimeout    = 60 * time.Second
	maxRetryWait   = 120 * time.Second
	maxBodyBytes   = 10 << 20
)

type Client struct {
	Token   string
	BaseURL string
	HTTP    *http.Client
}

// NewClient returns a client for baseURL. An empty baseURL falls back to
// DefaultBaseURL; the caller resolves SNYK_API_URL (flag-over-env config
// lives in the CLI layer, the client takes no environment dependencies).
func NewClient(token, baseURL string) *Client {
	if baseURL == "" {
		baseURL = DefaultBaseURL
	}
	return &Client{Token: token, BaseURL: strings.TrimRight(baseURL, "/"), HTTP: &http.Client{Timeout: httpTimeout}}
}

// ListOptions describes one issues-list query. Severity/Status are
// pre-validated comma-separated lists; the tool is code-only and
// project-scoped by design, so ProjectID is required.
type ListOptions struct {
	Severity         string
	Status           string
	IncludeIgnored   bool
	ProjectID        string
	CreatedAfter     string
	IncludeCodeFlows bool
}

// BuildListQuery builds the REST query for list. The tool is code-only and
// project-scoped by design: ProjectID is required, and the query always
// carries type=code plus scan_item.id/scan_item.type=project.
func BuildListQuery(o ListOptions) (url.Values, error) {
	if o.ProjectID == "" {
		return nil, errors.New("list requires a project ID")
	}
	v := url.Values{}
	if o.Severity != "" {
		v.Set("effective_severity_level", o.Severity)
	}
	if o.Status != "" {
		v.Set("status", o.Status)
	} else {
		v.Set("status", "open")
	}
	if !o.IncludeIgnored {
		v.Set("ignored", "false")
	}
	v.Set("type", "code")
	v.Set("scan_item.id", o.ProjectID)
	v.Set("scan_item.type", "project")
	if o.CreatedAfter != "" {
		v.Set("created_after", o.CreatedAfter)
	}
	v.Set("include_code_flows", strconv.FormatBool(o.IncludeCodeFlows))
	return v, nil
}

type pageResponse struct {
	Data  []RawIssue `json:"data"`
	Links struct {
		Next string `json:"next"`
	} `json:"links"`
	Meta struct {
		Links struct {
			Next string `json:"next"`
		} `json:"links"`
	} `json:"meta"`
}

// List retrieves every page of issues for orgID under query, following the
// cursor links until exhausted (bounded by MaxPages). The query is copied
// before pagination params are added, so the caller's value is untouched.
func (c *Client) List(ctx context.Context, orgID string, query url.Values) ([]RawIssue, error) {
	q := cloneValues(query)
	q.Set("version", APIVersion)
	q.Set("limit", strconv.Itoa(PageLimit))
	next := c.BaseURL + "/rest/orgs/" + url.PathEscape(orgID) + "/issues?" + q.Encode()
	var out []RawIssue
	for page := 0; next != ""; page++ {
		if page >= MaxPages {
			return nil, fmt.Errorf("pagination exceeded %d pages", MaxPages)
		}
		body, err := c.get(ctx, next)
		if err != nil {
			return nil, err
		}
		var p pageResponse
		if err := json.Unmarshal(body, &p); err != nil {
			return nil, fmt.Errorf("decode list response: %w", err)
		}
		out = append(out, p.Data...)
		next = c.absoluteURL(p.Links.Next)
		if n := c.absoluteURL(p.Meta.Links.Next); next == "" {
			next = n
		}
	}
	return out, nil
}

// Get retrieves a single issue with code flows always included.
func (c *Client) Get(ctx context.Context, orgID, issueID string) (*RawIssue, error) {
	u := c.BaseURL + "/rest/orgs/" + url.PathEscape(orgID) + "/issues/" +
		url.PathEscape(issueID) + "?version=" + APIVersion + "&include_code_flows=true"
	body, err := c.get(ctx, u)
	if err != nil {
		return nil, err
	}
	var p struct {
		Data RawIssue `json:"data"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return nil, fmt.Errorf("decode issue response: %w", err)
	}
	return &p.Data, nil
}

// absoluteURL resolves a pagination cursor to an absolute URL: absolute
// links pass through, relative ones are anchored at the base URL.
func (c *Client) absoluteURL(next string) string {
	switch {
	case next == "":
		return ""
	case strings.HasPrefix(next, "http://"), strings.HasPrefix(next, "https://"):
		return next
	default:
		return c.BaseURL + next
	}
}

// cloneValues copies a url.Values so List can add pagination params
// without mutating the caller's query.
func cloneValues(v url.Values) url.Values {
	out := make(url.Values, len(v))
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	return out
}

func (c *Client) get(ctx context.Context, u string) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "token "+c.Token)
		req.Header.Set("Accept", "application/vnd.api+json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		body, err := readBody(resp)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		switch {
		case resp.StatusCode == http.StatusTooManyRequests && attempt < MaxRetries:
			lastErr = fmt.Errorf("snyk api: HTTP 429 rate limited")
			if err := sleepCtx(ctx, retryAfter(resp.Header)); err != nil {
				return nil, err
			}
		case isTransientStatus(resp.StatusCode) && attempt < MaxRetries:
			lastErr = fmt.Errorf("snyk api: HTTP %d transient failure", resp.StatusCode)
			if err := sleepCtx(ctx, transientRetryDelay(attempt)); err != nil {
				return nil, err
			}
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("snyk api %s: HTTP %d: %s", u, resp.StatusCode, bodySnippet(body))
		default:
			return body, nil
		}
	}
	return nil, lastErr
}

// readBody reads the response body capped at maxBodyBytes. The reader is
// given one byte more than the cap so an over-long body is detected and
// rejected instead of silently truncating to malformed JSON.
func readBody(resp *http.Response) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	if len(body) > maxBodyBytes {
		return nil, fmt.Errorf("response body exceeds %d byte limit", maxBodyBytes)
	}
	return body, nil
}

// sleepCtx waits d, returning early with the context error when ctx is done
// (e.g. SIGINT), so retry waits never outlive the caller's intent.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func isTransientStatus(code int) bool {
	return code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

// transientRetryDelay returns the linear backoff (capped at 2s) applied
// between retries of a transient 5xx failure.
func transientRetryDelay(attempt int) time.Duration {
	d := time.Duration(attempt+1) * 250 * time.Millisecond
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

func retryAfter(h http.Header) time.Duration {
	d := time.Second
	if n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After"))); err == nil && n >= 0 {
		d = time.Duration(n) * time.Second
	}
	if d > maxRetryWait {
		d = maxRetryWait
	}
	return d
}

func bodySnippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 300 {
		s = s[:300]
	}
	return s
}
