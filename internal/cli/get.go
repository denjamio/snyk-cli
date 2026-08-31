package cli

import (
	"context"
	"io"
	"os"

	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
)

func runGet(ctx context.Context, args []string, s Streams) int {
	cmd, code := parseCommand(issuesGetSpec, args, s)
	if cmd == nil {
		return code
	}
	if len(cmd.positional) != 1 {
		return usageError(s, cmd.args, issuesGetSpec.Name, "exactly one ISSUE_ID argument is required")
	}
	f := cmd.flags
	org := resolveSetting(f.getString("org"), "SNYK_ORG_ID", os.Getenv)
	if org == "" {
		return usageError(s, cmd.args, issuesGetSpec.Name, "--org is required (or set SNYK_ORG_ID)")
	}
	client, code, ok := snykClient(s, cmd.args, issuesGetSpec.Name, os.Getenv)
	if !ok {
		return code
	}
	raw, err := client.Get(ctx, org, cmd.positional[0])
	if err != nil {
		return runtimeError(s, cmd.args, "issues get", errorKind(err), failureMessage(err))
	}
	item := snyk.Normalize(*raw)
	mode := output.ResolveMode(f.getBool("json"), f.getBool("quiet"))
	return emit(s, mode, f.getBool("compact"), "issues get", "1 issue", item, func(w io.Writer) error {
		return output.RenderIssuesTable(w, []output.Row{tableRow(item)}, "1 issue")
	})
}
