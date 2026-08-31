package cli

import (
	"fmt"
	"io"
	"strings"
)

// flagSpec declares one command flag (or a documented positional argument,
// marked Positional). It is the single source behind three surfaces that
// must not drift: the flag.FlagSet binding, the human usage text and the
// machine-readable catalog of `help --json`.
type flagSpec struct {
	Name        string `json:"name"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
	// Bool marks flags that never take a value (--flag, --flag=true), so
	// the argument pre-parser does not swallow the next token. Hidden from
	// the catalog payload.
	Bool bool `json:"-"`
	// Positional marks documented positional arguments: displayed by both
	// help surfaces, never bound as flags. Hidden from the catalog payload.
	Positional bool `json:"-"`
}

// usage renders the flag description, appending the documented default when
// present — the exact string shown by `-h`, `help` and the catalog.
func (f flagSpec) usage() string {
	if f.Default == "" {
		return f.Description
	}
	return fmt.Sprintf("%s (default: %s)", f.Description, f.Default)
}

// commandSpec declares one command of the catalog.
type commandSpec struct {
	Name     string     `json:"name"`
	Summary  string     `json:"summary"`
	Flags    []flagSpec `json:"flags,omitempty"`
	Examples []string   `json:"examples,omitempty"`
}

// outputFlags are the output-mode flags shared by every command that emits
// a payload.
func outputFlags() []flagSpec {
	return []flagSpec{
		{Name: "--json", Bool: true, Description: "force JSON envelope output"},
		{Name: "--quiet", Bool: true, Description: "print data only, no envelope"},
	}
}

var (
	issuesListSpec = commandSpec{
		Name:    "issues list",
		Summary: "List issues of a project, grouped by vulnerability type",
		Flags: append([]flagSpec{
			{Name: "--org", Description: "Snyk organization ID (required; or env SNYK_ORG_ID)"},
			{Name: "--project", Description: "Project ID (required; or env SNYK_PROJECT_ID)"},
			{Name: "--severity", Default: "all", Description: "comma-separated: info,low,medium,high,critical"},
			{Name: "--status", Default: "open", Description: "comma-separated: open,resolved"},
			{Name: "--created-after", Description: "RFC3339 date-time, e.g. 2026-08-01T00:00:00Z (only issues created after)"},
			{Name: "--include-ignored", Default: "false", Bool: true, Description: "include ignored issues"},
			{Name: "--include-code-flows", Default: "false", Bool: true, Description: "include data flows (source to sink) for code issues; heavier payload"},
		}, outputFlags()...),
		Examples: []string{
			"snyk issues list --org ORG_ID",
			"snyk issues list --org ORG_ID --severity high,critical --json",
		},
	}
	issuesGetSpec = commandSpec{
		Name:    "issues get",
		Summary: "Get a single issue with full detail",
		Flags: append([]flagSpec{
			{Name: "--org", Description: "Snyk organization ID (required; or env SNYK_ORG_ID)"},
			{Name: "ISSUE_ID", Description: "Snyk issue UUID (positional argument, order-independent)", Positional: true},
		}, outputFlags()...),
		Examples: []string{"snyk issues get ISSUE_ID --org ORG_ID --json"},
	}
	skillSpec = commandSpec{
		Name:    "skill",
		Summary: "Install or print the embedded agent skill (SKILL.md)",
		Flags: []flagSpec{
			{Name: "install", Description: "optional positional action; bare `skill` also installs", Positional: true},
			{Name: "--global", Bool: true, Description: "install to ~/.agents/skills (default: ./.agents/skills in the current directory)"},
			{Name: "--dir", Description: "install into the given directory instead"},
			{Name: "--print", Bool: true, Description: "print the embedded SKILL.md to stdout"},
			{Name: "--json", Bool: true, Description: "force JSON envelope output"},
		},
		Examples: []string{
			"snyk skill install --global",
			"snyk skill install",
			"snyk skill --print",
		},
	}
	helpSpec = commandSpec{
		Name:    "help",
		Summary: "Print usage; --json for the machine-readable command catalog",
		Flags: []flagSpec{
			{Name: "--json", Bool: true, Description: "print the machine-readable command catalog"},
		},
		Examples: []string{"snyk help", "snyk help --json"},
	}
	versionSpec = commandSpec{
		Name:     "version",
		Summary:  "Print version",
		Examples: []string{"snyk version"},
	}
)

// catalog is the authoritative command catalog: `help --json` marshals it
// verbatim, the human usage text renders it and flag binding reads from it.
func catalog() []commandSpec {
	return []commandSpec{issuesListSpec, issuesGetSpec, skillSpec, helpSpec, versionSpec}
}

// booleanFlags drives the argument pre-parser: boolean flags never swallow
// the following token. Derived from the catalog — plus the implicit
// -h/--help accepted on every command — so pre-parsing cannot drift from
// the real flag definitions.
var booleanFlags = func() map[string]bool {
	m := map[string]bool{"help": true}
	for _, c := range catalog() {
		for _, f := range c.Flags {
			if f.Bool {
				m[strings.TrimLeft(f.Name, "-")] = true
			}
		}
	}
	return m
}()

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

Environment:
  SNYK_TOKEN           Required API token
  SNYK_ORG_ID          Default for --org on issues list and issues get (flag wins)
  SNYK_PROJECT_ID      Default for --project on issues list (flag wins)
  SNYK_API_URL         Optional API base URL (default https://api.eu.snyk.io)
  SNYK_HTTP_TIMEOUT    Optional per-request timeout, Go duration (default 60s)

Exit codes: 0 success · 1 runtime error · 2 usage error
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
