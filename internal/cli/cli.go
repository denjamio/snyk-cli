package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	embedded "github.com/denjamio/snyk-cli"
	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
)

var (
	severities = []string{"info", "low", "medium", "high", "critical"}
	statuses   = []string{"open", "resolved"}
)

// Version is injected at build time via -ldflags "-X ...cli.Version=vX.Y.Z".
// Falls back to "dev" for untagged local builds.
var Version = "dev"

type Streams struct {
	Out      io.Writer
	Err      io.Writer
	OutIsTTY bool
}

func NewOSStreams() Streams {
	return Streams{Out: os.Stdout, Err: os.Stderr, OutIsTTY: output.IsTTY(os.Stdout)}
}

type flagDoc struct {
	Name        string `json:"name"`
	Default     string `json:"default,omitempty"`
	Description string `json:"description"`
}

type commandDoc struct {
	Name     string    `json:"name"`
	Summary  string    `json:"summary"`
	Flags    []flagDoc `json:"flags,omitempty"`
	Examples []string  `json:"examples,omitempty"`
}

func catalog() []commandDoc {
	return []commandDoc{
		{
			Name:    "issues list",
			Summary: "List issues of a project, grouped by vulnerability type",
			Flags: []flagDoc{
				{Name: "--org", Description: "Snyk organization ID (required; or env SNYK_ORG_ID)"},
				{Name: "--project", Description: "Project ID (required; or env SNYK_PROJECT_ID)"},
				{Name: "--severity", Default: "all", Description: "comma-separated: info,low,medium,high,critical"},
				{Name: "--status", Default: "open", Description: "comma-separated: open,resolved"},
				{Name: "--created-after", Description: "RFC3339 date-time, e.g. 2026-08-01T00:00:00Z (only issues created after)"},
				{Name: "--include-ignored", Default: "false", Description: "include ignored issues"},
				{Name: "--include-code-flows", Default: "false", Description: "include data flows (source to sink) for code issues"},
				{Name: "--json", Description: "force JSON envelope output"},
				{Name: "--quiet", Description: "print data only, no envelope"},
			},
			Examples: []string{
				"snyk issues list --org ORG_ID",
				"snyk issues list --org ORG_ID --severity high,critical --json",
			},
		},
		{
			Name:    "issues get",
			Summary: "Get a single issue with full detail",
			Flags: []flagDoc{
				{Name: "--org", Description: "Snyk organization ID (required; or env SNYK_ORG_ID)"},
				{Name: "ISSUE_ID", Description: "Snyk issue UUID (positional argument, order-independent)"},
				{Name: "--json", Description: "force JSON envelope output"},
				{Name: "--quiet", Description: "print data only, no envelope"},
			},
			Examples: []string{"snyk issues get ISSUE_ID --org ORG_ID --json"},
		},
		{
			Name:    "skill",
			Summary: "Install or print the embedded agent skill (SKILL.md)",
			Flags: []flagDoc{
				{Name: "install", Description: "optional positional action; bare `skill` also installs"},
				{Name: "--global", Description: "install to ~/.agents/skills (default: ./.agents/skills in the current directory)"},
				{Name: "--dir PATH", Description: "install into the given directory instead"},
				{Name: "--print", Description: "print the embedded SKILL.md to stdout"},
				{Name: "--json", Description: "force JSON envelope output"},
			},
			Examples: []string{
				"snyk skill install --global",
				"snyk skill install",
				"snyk skill --print",
			},
		},
		{
			Name:     "version",
			Summary:  "Print version",
			Examples: []string{"snyk version"},
		},
	}
}

var booleanFlags = map[string]bool{
	"json":               true,
	"quiet":              true,
	"include-ignored":    true,
	"include-code-flows": true,
	"help":               true,
	"global":             true,
	"print":              true,
}

func flagsFirst(args []string) ([]string, []string) {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if len(a) > 1 && a[0] == '-' {
			flags = append(flags, a)
			name := strings.TrimLeft(a, "-")
			hasValue := strings.Contains(a, "=")
			if !hasValue && !booleanFlags[name] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
			continue
		}
		positional = append(positional, a)
	}
	return flags, positional
}

func Run(args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, "missing command")
	}
	switch args[0] {
	case "issues":
		return runIssues(args[1:], s)
	case "skill":
		return runSkill(args[1:], s)
	case "help":
		return runHelp(args[1:], s)
	case "version", "--version", "-v":
		fmt.Fprintln(s.Out, "snyk "+Version)
		return 0
	default:
		return usageError(s, "unknown command: "+args[0])
	}
}

// runIssues dispatches the issues resource. Future API surfaces (projects,
// dependencies, ...) plug in as sibling resource dispatchers in Run.
func runIssues(args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, "missing issues command (available: list, get)")
	}
	switch args[0] {
	case "list":
		return runList(args[1:], s)
	case "get":
		return runGet(args[1:], s)
	default:
		return usageError(s, "unknown issues command: "+args[0])
	}
}

func runHelp(args []string, s Streams) int {
	for _, a := range args {
		if a == "--json" {
			if err := output.WriteJSON(s.Out, output.Envelope{
				OK:      true,
				Command: "help",
				Data:    map[string]any{"commands": catalog()},
			}); err != nil {
				fmt.Fprintln(s.Err, "error:", err)
				return 1
			}
			return 0
		}
	}
	printUsage(s.Out)
	return 0
}

// resolveSetting applies CLI-over-env precedence: the flag value wins when
// set, otherwise the named environment variable is used ("" if unset).
func resolveSetting(flagValue, envKey string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envKey)
}

func runList(args []string, s Streams) int {
	fs := newFlagSet("issues list")
	orgFlag := fs.String("org", "", "Snyk organization ID (required; or env SNYK_ORG_ID)")
	projectFlag := fs.String("project", "", "Project ID (required; or env SNYK_PROJECT_ID)")
	severity := fs.String("severity", "", "comma-separated: info,low,medium,high,critical (default: all)")
	status := fs.String("status", "", "comma-separated: open,resolved (default: open)")
	createdAfter := fs.String("created-after", "", "RFC3339 date-time, e.g. 2026-08-01T00:00:00Z (only issues created after)")
	includeIgnored := fs.Bool("include-ignored", false, "include ignored issues")
	includeCodeFlows := fs.Bool("include-code-flows", false, "include data flows (source to sink) for code issues; heavier payload")
	jsonFlag := fs.Bool("json", false, "force JSON envelope output")
	quietFlag := fs.Bool("quiet", false, "print data only, no envelope")
	if code, ok := parse(fs, args, s); !ok {
		return code
	}
	org := resolveSetting(*orgFlag, "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, "--org is required (or set SNYK_ORG_ID)")
	}
	project := resolveSetting(*projectFlag, "SNYK_PROJECT_ID")
	if project == "" {
		return usageError(s, "--project is required (or set SNYK_PROJECT_ID)")
	}
	if *createdAfter != "" {
		if _, err := time.Parse(time.RFC3339, *createdAfter); err != nil {
			return usageError(s, "invalid --created-after: must be an RFC3339 date-time like 2026-08-01T00:00:00Z")
		}
	}
	sevToks, err := normalizeList(*severity, severities, "severity")
	if err != nil {
		return usageError(s, err.Error())
	}
	statusToks, err := normalizeList(*status, statuses, "status")
	if err != nil {
		return usageError(s, err.Error())
	}
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return runtimeError(s, "issues list", "SNYK_TOKEN not set")
	}
	client := snyk.NewClient(token)
	query, err := snyk.BuildListQuery(snyk.ListOptions{
		Severity:         strings.Join(sevToks, ","),
		Status:           strings.Join(statusToks, ","),
		IncludeIgnored:   *includeIgnored,
		ProjectID:        project,
		CreatedAfter:     *createdAfter,
		IncludeCodeFlows: *includeCodeFlows,
	})
	if err != nil {
		return runtimeError(s, "issues list", err.Error())
	}
	raw, err := client.List(context.Background(), org, query)
	if err != nil {
		return runtimeError(s, "issues list", err.Error())
	}
	items := snyk.NormalizeAll(raw)
	groups := snyk.GroupByType(items)
	mode := output.ResolveMode(*jsonFlag, *quietFlag)
	var data any = snyk.ListData{TotalIssues: len(items), Groups: groups}
	if mode == output.ModeQuiet {
		data = groups
	}
	summary := summarize(len(items), strings.Join(statusToks, ","), *includeIgnored, strings.Join(sevToks, ","), *createdAfter)
	return emit(s, mode, "issues list", summary, data, func(w io.Writer) {
		output.RenderGroupsTable(w, groups, summary)
	})
}

// normalizeList validates a comma-separated flag against its allowed values:
// tokens are trimmed and lowercased, duplicates dropped, order preserved. An
// empty value means "no filter". Unknown or empty tokens are rejected so
// invalid input fails fast with a usage error instead of an API round-trip.
func normalizeList(value string, allowed []string, flag string) ([]string, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range strings.Split(value, ",") {
		tok = strings.ToLower(strings.TrimSpace(tok))
		if tok == "" {
			return nil, fmt.Errorf("empty value in --%s", flag)
		}
		if !slices.Contains(allowed, tok) {
			return nil, fmt.Errorf("invalid --%s value %q; allowed: %s", flag, tok, strings.Join(allowed, ","))
		}
		if !seen[tok] {
			seen[tok] = true
			out = append(out, tok)
		}
	}
	return out, nil
}

func runGet(args []string, s Streams) int {
	fs := newFlagSet("issues get")
	orgFlag := fs.String("org", "", "Snyk organization ID (required; or env SNYK_ORG_ID)")
	jsonFlag := fs.Bool("json", false, "force JSON envelope output")
	quietFlag := fs.Bool("quiet", false, "print data only, no envelope")
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	if len(positional) != 1 {
		return usageError(s, "exactly one ISSUE_ID argument is required")
	}
	org := resolveSetting(*orgFlag, "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, "--org is required (or set SNYK_ORG_ID)")
	}
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return runtimeError(s, "issues get", "SNYK_TOKEN not set")
	}
	client := snyk.NewClient(token)
	raw, err := client.Get(context.Background(), org, positional[0])
	if err != nil {
		return runtimeError(s, "issues get", err.Error())
	}
	item := snyk.Normalize(*raw)
	mode := output.ResolveMode(*jsonFlag, *quietFlag)
	return emit(s, mode, "issues get", "1 issue", item, func(w io.Writer) {
		output.RenderIssuesTable(w, []snyk.Issue{item}, "1 issue")
	})
}

// runSkill installs (or prints) the SKILL.md embedded in the binary, so the
// skill always travels version-matched with the CLI. Default destination is
// ./.agents/skills in the current project; --global targets ~/.agents and
// --dir overrides both. --print emits the raw markdown instead.
func runSkill(args []string, s Streams) int {
	fs := newFlagSet("skill")
	jsonFlag := fs.Bool("json", false, "force JSON envelope output")
	global := fs.Bool("global", false, "install to ~/.agents/skills (default: ./.agents/skills in the current directory)")
	dir := fs.String("dir", "", "install into the given directory instead")
	printFlag := fs.Bool("print", false, "print the embedded SKILL.md to stdout")
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	for _, p := range positional {
		if p != "install" {
			return usageError(s, fmt.Sprintf("unexpected argument %q; only the optional action install is accepted", p))
		}
	}
	if *printFlag {
		if *global || *dir != "" {
			return usageError(s, "--print cannot be combined with a destination")
		}
		fmt.Fprint(s.Out, embedded.SkillMD)
		return 0
	}
	base := ""
	switch {
	case *dir != "":
		base = *dir
	case *global:
		home, err := os.UserHomeDir()
		if err != nil {
			return runtimeError(s, "skill", err.Error())
		}
		base = home
	default:
		cwd, err := os.Getwd()
		if err != nil {
			return runtimeError(s, "skill", err.Error())
		}
		base = cwd
	}
	target := filepath.Join(base, ".agents", "skills", "snyk", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return runtimeError(s, "skill", err.Error())
	}
	action := "installed"
	if prev, err := os.ReadFile(target); err == nil && string(prev) == embedded.SkillMD {
		action = "already up to date"
	} else if err := os.WriteFile(target, []byte(embedded.SkillMD), 0o644); err != nil {
		return runtimeError(s, "skill", err.Error())
	}
	summary := fmt.Sprintf("skill %s at %s", action, target)
	mode := output.ResolveMode(*jsonFlag, false)
	return emit(s, mode, "skill", summary, map[string]any{"path": target}, func(w io.Writer) {
		fmt.Fprintln(w, summary)
	})
}

func parse(fs *flag.FlagSet, args []string, s Streams) (int, bool) {
	flagArgs, _ := flagsFirst(args)
	return parseFS(fs, flagArgs, s)
}

func parseFS(fs *flag.FlagSet, args []string, s Streams) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0, false
		}
		return usageError(s, err.Error()), false
	}
	return 0, true
}

func emit(s Streams, mode output.Mode, command, summary string, data any, renderHuman func(io.Writer)) int {
	useHuman := mode == output.ModeAuto && s.OutIsTTY
	if !useHuman {
		var err error
		if mode == output.ModeQuiet {
			err = output.WriteJSON(s.Out, data)
		} else {
			err = output.WriteEnvelope(s.Out, command, summary, data)
		}
		if err != nil {
			fmt.Fprintln(s.Err, "error:", err)
			return 1
		}
		return 0
	}
	renderHuman(s.Out)
	return 0
}

func summarize(n int, statusFlag string, includeIgnored bool, severity, createdAfter string) string {
	status := statusFlag
	if status == "" {
		status = "open"
	}
	ignored := "ignored=false"
	if includeIgnored {
		ignored = "ignored=any"
	}
	out := fmt.Sprintf("%d issues · status=%s · %s · type=code", n, status, ignored)
	if severity != "" {
		out += fmt.Sprintf(" · severity=%s", severity)
	}
	if createdAfter != "" {
		out += fmt.Sprintf(" · created_after=%s", createdAfter)
	}
	return out
}

func runtimeError(s Streams, command, msg string) int {
	if s.OutIsTTY {
		fmt.Fprintln(s.Err, "error:", msg)
		return 1
	}
	if err := output.WriteJSON(s.Out, output.Envelope{OK: false, Command: command, Error: msg}); err != nil {
		fmt.Fprintln(s.Err, "error:", err)
	}
	return 1
}

func usageError(s Streams, msg string) int {
	fmt.Fprintln(s.Err, "error:", msg)
	printUsage(s.Err)
	return 2
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}

func printUsage(w io.Writer) {
	fmt.Fprint(w, `snyk <resource> [action] [flags]

Resources:
  issues    Snyk Code issues (actions: list, get)
  skill     Install or print the embedded agent skill
  help      Print usage (--json for structured catalog)
  version   Print version

Run "snyk help --json" for the machine-readable command catalog.

issues list flags:
  --org ID             Snyk organization ID (required; or env SNYK_ORG_ID)
  --project ID         Project ID (required; or env SNYK_PROJECT_ID);
                       the query is always scoped to it (scan_item.id +
                       scan_item.type=project)
  --severity LIST      info,low,medium,high,critical (default: all severities)
  --status LIST        open,resolved (comma-separated; default: open)
  --created-after TS   RFC3339 date-time, e.g. 2026-08-01T00:00:00Z (only issues created after)
  --include-ignored    Include ignored issues (default filters them out)
  --include-code-flows Include data flows (source to sink) for code issues;
                       heavier payload. 'issues get' always includes them.
  --json               Force JSON envelope output (default when piped)
  --quiet              Print data only, no envelope

Scope:
  issues list always queries Snyk Code issues (type=code) of a single
  project (scan_item.id); there is no --type flag and no cross-project
  listing. The payload carries only fields the code payload provides.

Grouping:
  issues list groups issues by vulnerability type. Groups are ordered
  alphabetically by type name; issues inside each group by severity, then
  most recent created_at, with the stable id as final tie-break.

issues get flags:
  --org ID             Snyk organization ID (required; or env SNYK_ORG_ID)
  ISSUE_ID             Snyk issue UUID (positional argument)
  --json / --quiet

skill flags:
  install              Optional action (bare skill also installs)
  --global             Install to ~/.agents/skills (default: ./.agents/skills
                       in the current directory)
  --dir PATH           Install into the given directory instead
  --print              Print the embedded SKILL.md to stdout
  --json               Force JSON envelope output

Output modes:
  terminal             Human-readable table
  piped / --json       {"ok":true,"command":...,"summary":...,"data":...}
  --quiet              Raw data only

Environment:
  SNYK_TOKEN           Required API token
  SNYK_ORG_ID          Default for --org on issues list and issues get (flag wins)
  SNYK_PROJECT_ID      Default for --project on issues list (flag wins)
  SNYK_API_URL         Optional API base URL (default https://api.eu.snyk.io)

Exit codes: 0 success · 1 runtime error · 2 usage error
`)
}
