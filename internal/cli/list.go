package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
)

var (
	severities = []string{"info", "low", "medium", "high", "critical"}
	statuses   = []string{"open", "resolved"}
)

func runList(ctx context.Context, args []string, s Streams) int {
	cmd, code := parseCommand(issuesListSpec, args, s)
	if cmd == nil {
		return code
	}
	if code := cmd.rejectPositional(s); code != 0 {
		return code
	}
	f := cmd.flags
	org := resolveSetting(f.getString("org"), "SNYK_ORG_ID", os.Getenv)
	if org == "" {
		return usageError(s, args, issuesListSpec.Name, "--org is required (or set SNYK_ORG_ID)")
	}
	project := resolveSetting(f.getString("project"), "SNYK_PROJECT_ID", os.Getenv)
	if project == "" {
		return usageError(s, args, issuesListSpec.Name, "--project is required (or set SNYK_PROJECT_ID)")
	}
	createdAfter := f.getString("created-after")
	if createdAfter != "" {
		if _, err := time.Parse(time.RFC3339, createdAfter); err != nil {
			return usageError(s, args, issuesListSpec.Name, "invalid --created-after: must be an RFC3339 date-time like 2026-08-01T00:00:00Z")
		}
	}
	sevToks, err := normalizeList(f.getString("severity"), severities, "severity")
	if err != nil {
		return usageError(s, args, issuesListSpec.Name, err.Error())
	}
	statusToks, err := normalizeList(f.getString("status"), statuses, "status")
	if err != nil {
		return usageError(s, args, issuesListSpec.Name, err.Error())
	}
	client, code, ok := snykClient(s, args, issuesListSpec.Name, os.Getenv)
	if !ok {
		return code
	}
	query, err := snyk.BuildListQuery(snyk.ListOptions{Severity: strings.Join(sevToks, ","),
		Status:           strings.Join(statusToks, ","),
		IncludeIgnored:   f.getBool("include-ignored"),
		ProjectID:        project,
		CreatedAfter:     createdAfter,
		IncludeCodeFlows: f.getBool("include-code-flows"),
	})
	if err != nil {
		return runtimeError(s, args, "issues list", errorKind(err), err.Error())
	}
	raw, truncated, err := client.List(ctx, org, query)
	if err != nil {
		return runtimeError(s, args, "issues list", errorKind(err), err.Error())
	}
	if truncated {
		// Truncation is an anomaly, not progress: unlike the progress
		// events this warning reaches stderr even on piped runs, where
		// progress stays silent, so no consumer mistakes a capped
		// listing for the full set.
		fmt.Fprintf(s.Err, "snyk: listing truncated at the %d-issue page cap; narrow with --severity or --created-after to see the rest\n", snyk.MaxPages*snyk.PageLimit)
	}
	items := snyk.NormalizeAll(raw)
	groups := snyk.GroupByType(items)
	mode := output.ResolveMode(f.getBool("json"), f.getBool("quiet"))
	var data any = snyk.ListData{TotalIssues: len(items), Groups: groups, Truncated: truncated}
	if mode == output.ModeQuiet {
		data = groups
	}
	summary := summarize(len(items), strings.Join(statusToks, ","), f.getBool("include-ignored"), strings.Join(sevToks, ","), createdAfter, truncated)
	return emit(s, mode, "issues list", summary, data, func(w io.Writer) {
		output.RenderGroupsTable(w, tableGroups(groups), summary)
	})
}

// normalizeList validates a comma-separated flag against its allowed values:
// tokens are trimmed and lowercased, duplicates dropped, order preserved. An
// empty value means "no filter". Unknown or empty tokens are rejected so
// invalid input fails fast with a usage error instead of an API round-trip.
func normalizeList(value string, allowed []string, name string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Split(value, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			return nil, fmt.Errorf("empty value in --%s", name)
		}
		if !slices.Contains(allowed, tok) {
			return nil, fmt.Errorf("invalid --%s value %q; allowed: %s", name, tok, strings.Join(allowed, ","))
		}
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out, nil
}

// summarize renders the envelope summary line from the effective filters;
// the truncated hint appears only when the page cap actually tripped.
func summarize(n int, statusFlag string, includeIgnored bool, severity, createdAfter string, truncated bool) string {
	status := statusFlag
	if status == "" {
		status = snyk.DefaultStatus
	}
	ignored := "ignored=false"
	if includeIgnored {
		ignored = "ignored=any"
	}
	parts := []string{
		fmt.Sprintf("%d issues", n),
		"status=" + status,
		ignored,
		"type=code",
	}
	if severity != "" {
		parts = append(parts, "severity="+severity)
	}
	if createdAfter != "" {
		parts = append(parts, "created_after="+createdAfter)
	}
	if truncated {
		parts = append(parts, "truncated=true")
	}
	return strings.Join(parts, " · ")
}
