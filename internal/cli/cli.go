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

// boundFlags gives typed access to the flags bound from a command spec.
type boundFlags struct {
	strFlags  map[string]*string
	boolFlags map[string]*bool
}

// bind registers every non-positional entry of specs on fs. Value flags
// default to "" (unset) and boolean flags to false; the spec's Default is
// documentation, applied by the command logic afterwards. Lookups for
// unknown names return zero values so a spec/handler mismatch can never
// crash the CLI.
func bind(fs *flag.FlagSet, specs []flagSpec) *boundFlags {
	b := &boundFlags{strFlags: map[string]*string{}, boolFlags: map[string]*bool{}}
	for _, sp := range specs {
		if sp.Positional {
			continue
		}
		name := strings.TrimLeft(sp.Name, "-")
		if sp.Bool {
			b.boolFlags[name] = fs.Bool(name, false, sp.usage())
		} else {
			b.strFlags[name] = fs.String(name, "", sp.usage())
		}
	}
	return b
}

// str returns the value of a bound string flag ("" when unset or unknown).
func (b *boundFlags) str(name string) string {
	if p, ok := b.strFlags[name]; ok {
		return *p
	}
	return ""
}

// boolean returns the value of a bound bool flag (false when unset or unknown).
func (b *boundFlags) boolean(name string) bool {
	if p, ok := b.boolFlags[name]; ok {
		return *p
	}
	return false
}

func Run(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, "missing command")
	}
	switch args[0] {
	case "issues":
		return runIssues(ctx, args[1:], s)
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
func runIssues(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, "missing issues command (available: list, get)")
	}
	switch args[0] {
	case "list":
		return runList(ctx, args[1:], s)
	case "get":
		return runGet(ctx, args[1:], s)
	default:
		return usageError(s, "unknown issues command: "+args[0])
	}
}

func runHelp(args []string, s Streams) int {
	fs := newFlagSet(helpSpec.Name)
	f := bind(fs, helpSpec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError(s, fmt.Sprintf("unexpected argument %q; help takes no positional arguments", positional[0]))
	}
	if !f.boolean("json") {
		printUsage(s.Out)
		return 0
	}
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

// resolveSetting applies CLI-over-env precedence: the flag value wins when
// set, otherwise the named environment variable is used ("" if unset).
func resolveSetting(flagValue, envKey string) string {
	if flagValue != "" {
		return flagValue
	}
	return os.Getenv(envKey)
}

func runList(ctx context.Context, args []string, s Streams) int {
	fs := newFlagSet(issuesListSpec.Name)
	f := bind(fs, issuesListSpec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError(s, fmt.Sprintf("unexpected argument %q; issues list takes no positional arguments", positional[0]))
	}
	org := resolveSetting(f.str("org"), "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, "--org is required (or set SNYK_ORG_ID)")
	}
	project := resolveSetting(f.str("project"), "SNYK_PROJECT_ID")
	if project == "" {
		return usageError(s, "--project is required (or set SNYK_PROJECT_ID)")
	}
	createdAfter := f.str("created-after")
	if createdAfter != "" {
		if _, err := time.Parse(time.RFC3339, createdAfter); err != nil {
			return usageError(s, "invalid --created-after: must be an RFC3339 date-time like 2026-08-01T00:00:00Z")
		}
	}
	sevToks, err := normalizeList(f.str("severity"), severities, "severity")
	if err != nil {
		return usageError(s, err.Error())
	}
	statusToks, err := normalizeList(f.str("status"), statuses, "status")
	if err != nil {
		return usageError(s, err.Error())
	}
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return runtimeError(s, "issues list", "SNYK_TOKEN not set")
	}
	client := snyk.NewClient(token, os.Getenv("SNYK_API_URL"))
	query, err := snyk.BuildListQuery(snyk.ListOptions{
		Severity:         strings.Join(sevToks, ","),
		Status:           strings.Join(statusToks, ","),
		IncludeIgnored:   f.boolean("include-ignored"),
		ProjectID:        project,
		CreatedAfter:     createdAfter,
		IncludeCodeFlows: f.boolean("include-code-flows"),
	})
	if err != nil {
		return runtimeError(s, "issues list", err.Error())
	}
	raw, err := client.List(ctx, org, query)
	if err != nil {
		return runtimeError(s, "issues list", err.Error())
	}
	items := snyk.NormalizeAll(raw)
	groups := snyk.GroupByType(items)
	mode := output.ResolveMode(f.boolean("json"), f.boolean("quiet"))
	var data any = snyk.ListData{TotalIssues: len(items), Groups: groups}
	if mode == output.ModeQuiet {
		data = groups
	}
	summary := summarize(len(items), strings.Join(statusToks, ","), f.boolean("include-ignored"), strings.Join(sevToks, ","), createdAfter)
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

func runGet(ctx context.Context, args []string, s Streams) int {
	fs := newFlagSet(issuesGetSpec.Name)
	f := bind(fs, issuesGetSpec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	if len(positional) != 1 {
		return usageError(s, "exactly one ISSUE_ID argument is required")
	}
	org := resolveSetting(f.str("org"), "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, "--org is required (or set SNYK_ORG_ID)")
	}
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return runtimeError(s, "issues get", "SNYK_TOKEN not set")
	}
	client := snyk.NewClient(token, os.Getenv("SNYK_API_URL"))
	raw, err := client.Get(ctx, org, positional[0])
	if err != nil {
		return runtimeError(s, "issues get", err.Error())
	}
	item := snyk.Normalize(*raw)
	mode := output.ResolveMode(f.boolean("json"), f.boolean("quiet"))
	return emit(s, mode, "issues get", "1 issue", item, func(w io.Writer) {
		output.RenderIssuesTable(w, []snyk.Issue{item}, "1 issue")
	})
}

// runSkill installs (or prints) the SKILL.md embedded in the binary, so the
// skill always travels version-matched with the CLI. Default destination is
// ./.agents/skills in the current project; --global targets ~/.agents and
// --dir overrides both. --print emits the raw markdown instead.
func runSkill(args []string, s Streams) int {
	fs := newFlagSet(skillSpec.Name)
	f := bind(fs, skillSpec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	for _, p := range positional {
		if p != "install" {
			return usageError(s, fmt.Sprintf("unexpected argument %q; only the optional action install is accepted", p))
		}
	}
	dir := f.str("dir")
	global := f.boolean("global")
	if f.boolean("print") {
		if global || dir != "" {
			return usageError(s, "--print cannot be combined with a destination")
		}
		fmt.Fprint(s.Out, embedded.SkillMD)
		return 0
	}
	base := ""
	switch {
	case dir != "":
		base = dir
	case global:
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
	} else if err := writeFileAtomic(target, []byte(embedded.SkillMD), 0o644); err != nil {
		return runtimeError(s, "skill", err.Error())
	}
	summary := fmt.Sprintf("skill %s at %s", action, target)
	mode := output.ResolveMode(f.boolean("json"), false)
	return emit(s, mode, "skill", summary, map[string]any{"path": target}, func(w io.Writer) {
		fmt.Fprintln(w, summary)
	})
}

// writeFileAtomic writes data to a temp file inside the target directory
// and renames it into place, so an interrupted install can never leave a
// truncated SKILL.md behind; the temp file is cleaned up on any failure.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(name, perm); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// parseFS parses pre-split flag args, mapping flag package errors to exit
// codes: --help exits cleanly (0, false), anything else is a usage error.
func parseFS(fs *flag.FlagSet, args []string, s Streams) (code int, ok bool) {
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

// summarize renders the envelope summary line from the effective filters.
func summarize(n int, statusFlag string, includeIgnored bool, severity, createdAfter string) string {
	status := statusFlag
	if status == "" {
		status = "open"
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
	return strings.Join(parts, " · ")
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
