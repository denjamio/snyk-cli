package snyk

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
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

func NewClient(token string) *Client {
	base := os.Getenv("SNYK_API_URL")
	if base == "" {
		base = DefaultBaseURL
	}
	return &Client{Token: token, BaseURL: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: httpTimeout}}
}

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

func (c *Client) List(ctx context.Context, orgID string, query url.Values) ([]RawIssue, error) {
	query.Set("version", APIVersion)
	query.Set("limit", strconv.Itoa(PageLimit))
	next := c.BaseURL + "/rest/orgs/" + url.PathEscape(orgID) + "/issues?" + query.Encode()
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
		next = c.abs(p.Links.Next)
		if n := c.abs(p.Meta.Links.Next); next == "" {
			next = n
		}
	}
	return out, nil
}

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

func (c *Client) abs(next string) string {
	switch {
	case next == "":
		return ""
	case strings.HasPrefix(next, "http://"), strings.HasPrefix(next, "https://"):
		return next
	default:
		return c.BaseURL + next
	}
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
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
		_ = resp.Body.Close()
		switch {
		case resp.StatusCode == http.StatusTooManyRequests && attempt < MaxRetries:
			lastErr = fmt.Errorf("snyk api: HTTP 429 rate limited")
			time.Sleep(retryAfter(resp.Header))
		case isTransientStatus(resp.StatusCode) && attempt < MaxRetries:
			lastErr = fmt.Errorf("snyk api: HTTP %d transient failure", resp.StatusCode)
			time.Sleep(transientBackoff(attempt))
		case resp.StatusCode != http.StatusOK:
			return nil, fmt.Errorf("snyk api %s: HTTP %d: %s", u, resp.StatusCode, bodySnippet(body))
		default:
			return body, nil
		}
	}
	return nil, lastErr
}

func isTransientStatus(code int) bool {
	return code == http.StatusBadGateway ||
		code == http.StatusServiceUnavailable ||
		code == http.StatusGatewayTimeout
}

func transientBackoff(attempt int) time.Duration {
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
