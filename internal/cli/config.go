package cli

import (
	"context"
	"fmt"
	"os"
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
// (runtime error); SNYK_HTTP_TIMEOUT optionally bounds each HTTP request
// and must be a positive Go duration (invalid values are usage errors).
// When ok is false the second result is the exit code to return.
func snykClient(s Streams, args []string, command string, getenv envLookup) (*snyk.Client, int, bool) {
	token := getenv("SNYK_TOKEN")
	if token == "" {
		return nil, runtimeError(s, args, command, kindConfig, "SNYK_TOKEN not set"), false
	}
	client := snyk.NewClient(token, getenv("SNYK_API_URL"))
	client.UserAgent = "snyk-cli/" + Version
	client.Progress = progressLogger(s)
	if v := getenv("SNYK_HTTP_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, usageError(s, args, command, "invalid SNYK_HTTP_TIMEOUT: must be a positive duration like 90s or 2m"), false
		}
		client.HTTP.Timeout = d
	}
	return client, 0, true
}

// withRunTimeout optionally bounds the whole run with SNYK_TIMEOUT: a
// positive Go duration becomes a context deadline, so in-flight requests,
// pagination and retry waits all abort with a canceled-kind error when it
// fires — a coarse cap over the per-request SNYK_HTTP_TIMEOUT and the
// retry budget. Unset leaves the context untouched; the returned cancel
// is always callable. An invalid value is a configuration error the
// caller reports as a usage failure.
func withRunTimeout(ctx context.Context) (context.Context, context.CancelFunc, error) {
	v := os.Getenv("SNYK_TIMEOUT")
	if v == "" {
		return ctx, func() {}, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil || d <= 0 {
		return ctx, nil, fmt.Errorf("invalid SNYK_TIMEOUT: must be a positive duration like 90s or 2m")
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
