package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/denjamio/snyk-cli/internal/snyk"
)

// envLookup abstracts environment access: os.Getenv in production,
// injected in tests that should not touch the process environment.
type envLookup func(string) string

// resolveSetting applies CLI-over-env precedence: the flag value wins when
// set, otherwise the named environment variable is used ("" if unset).
func resolveSetting(flagValue, envKey string, getenv envLookup) string {
	if flagValue != "" {
		return flagValue
	}
	return getenv(envKey)
}

// snykClient builds the API client from the environment — the one place
// where token and tuning env vars are resolved. SNYK_TOKEN is required
// (config failure, exit 1); SNYK_HTTP_TIMEOUT optionally bounds each HTTP
// request and must be a positive Go duration (invalid values are usage
// errors, exit 2). Failures come back as a pre-classified *runError.
func snykClient(s Streams, getenv envLookup) (*snyk.Client, error) {
	token := getenv("SNYK_TOKEN")
	if token == "" {
		return nil, &runError{kind: kindConfig, exit: 1, msg: "SNYK_TOKEN not set"}
	}
	client := snyk.NewClient(token, getenv("SNYK_API_URL"))
	client.UserAgent = "snyk-cli/" + Version
	client.Progress = progressLogger(s)
	if v := getenv("SNYK_HTTP_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, &runError{kind: kindUsage, exit: 2, msg: "invalid SNYK_HTTP_TIMEOUT: must be a positive duration like 90s or 2m"}
		}
		client.HTTP.Timeout = d
	}
	return client, nil
}

// withRunTimeout optionally bounds the whole run with SNYK_TIMEOUT: a
// positive Go duration becomes a context deadline, so in-flight requests,
// pagination and retry waits all abort with a canceled-kind error when it
// fires — a coarse cap over the per-request SNYK_HTTP_TIMEOUT and the
// retry budget. Unset leaves the context untouched; the returned cancel
// is always callable. An invalid value is a pre-classified *runError the
// caller reports as a usage failure. Environment access is injected, so
// tests need not touch the process environment.
func withRunTimeout(ctx context.Context, getenv envLookup) (context.Context, context.CancelFunc, error) {
	v := getenv("SNYK_TIMEOUT")
	if v == "" {
		return ctx, func() {}, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return ctx, nil, &runError{kind: kindUsage, exit: 2, msg: "invalid SNYK_TIMEOUT: must be a positive duration like 90s or 2m"}
	}
	cctx, cancel := context.WithTimeout(ctx, d)
	return cctx, cancel, nil
}

// progressLogger renders client operational events (pagination, retries)
// on stderr, and only when stderr is a terminal: humans see progress,
// while piped consumers — scripts and agents — get nothing extra, so
// their stdout payload stays the whole story.
func progressLogger(s Streams) func(string) {
	if !s.ErrIsTTY {
		return nil
	}
	return func(event string) {
		fmt.Fprintln(s.Err, "snyk:", event)
	}
}
