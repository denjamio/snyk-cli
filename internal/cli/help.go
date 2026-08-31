package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/denjamio/snyk-cli/internal/output"
)

func runHelp(_ context.Context, args []string, s Streams) int {
	cmd, code := parseCommand(helpSpec, args, s)
	if cmd == nil {
		return code
	}
	if code := cmd.rejectPositional(s); code != 0 {
		return code
	}
	if !cmd.flags.getBool("json") {
		printUsage(s.Out)
		return 0
	}
	return writeEnvelope(s, output.Envelope{
		OK:      true,
		Command: "help",
		Data:    map[string]any{"commands": catalog()},
	})
}

// printUsage renders the human usage text. Flag blocks are generated from
// the catalog, the same source as `help --json`, so the two help surfaces
// cannot drift apart; only the conceptual sections (scope, grouping,
// environment, exit codes) are written by hand.
func printUsage(w io.Writer) {
	var sb strings.Builder
	sb.WriteString(`snyk <resource> [action] [flags]

Resources:
  issues    Snyk Code issues (actions: list, get)
  skill     Install or print the embedded agent skill
  help      Print usage (--json for structured catalog)
  version   Print version

Run "snyk help --json" for the machine-readable command catalog.
`)
	for _, c := range catalog() {
		writeFlagsSection(&sb, c)
	}
	sb.WriteString(`
Scope:
  issues list always queries Snyk Code issues (type=code) of a single
  project (scan_item.id); there is no --type flag and no cross-project
  listing. The payload carries only fields the code payload provides.

Grouping:
  issues list groups issues by vulnerability type. Groups are ordered
  alphabetically by type name; issues inside each group by severity, then
  most recent created_at, with the stable id as final tie-break.

Output modes:
  terminal             Human-readable table
  piped / --json       {"ok":true,"command":...,"summary":...,"data":...}
  --quiet              Raw data only
  --compact            JSON without indentation (piped, --json or --quiet)

Environment:
  SNYK_TOKEN           Required API token
  SNYK_ORG_ID          Default for --org on issues list and issues get (flag wins)
  SNYK_PROJECT_ID      Default for --project on issues list (flag wins)
  SNYK_API_URL         Optional API base URL (default https://api.eu.snyk.io)
  SNYK_HTTP_TIMEOUT    Optional per-request timeout, Go duration (default 60s)
  SNYK_TIMEOUT         Optional whole-run deadline, Go duration (default none)

Exit codes: 0 success · 1 runtime error · 2 usage error
Piped failures carry {"ok":false,...,"error":{"kind":...,"message":...}}
with kind one of: usage, config, auth, not_found, rate_limit, transient,
network, canceled, api, decode, internal.
`)
	fmt.Fprint(w, sb.String())
}

// writeFlagsSection renders one command's flag table: name column padded to
// the widest entry, description appended with its default when present.
func writeFlagsSection(sb *strings.Builder, c commandSpec) {
	if len(c.Flags) == 0 {
		return
	}
	fmt.Fprintf(sb, "\n%s flags:\n", c.Name)
	width := 0
	for _, f := range c.Flags {
		if l := len(f.Name); l > width {
			width = l
		}
	}
	for _, f := range c.Flags {
		fmt.Fprintf(sb, "  %-*s  %s\n", width, f.Name, f.usage())
	}
}
