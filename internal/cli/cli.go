package cli

import (
	"context"
	"errors"
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

// Failure kinds the CLI layer adds on top of the client's own (auth,
// not_found, rate_limit, transient, network, api, decode): together they
// form the closed set the envelope's error.kind may carry.
const (
	kindUsage    = "usage"    // invalid invocation (exit 2)
	kindConfig   = "config"   // environment misconfiguration (e.g. SNYK_TOKEN missing)
	kindCanceled = "canceled" // caller canceled: SIGINT/SIGTERM or deadline
	kindInternal = "internal" // unexpected failures: guards, local I/O
)

// Version is injected at build time via -ldflags "-X ...cli.Version=vX.Y.Z".
// Falls back to "dev" for untagged local builds.
var Version = "dev"

type Streams struct {
	Out      io.Writer
	Err      io.Writer
	OutIsTTY bool
	ErrIsTTY bool
}

func NewOSStreams() Streams {
	return Streams{
		Out:      os.Stdout,
		Err:      os.Stderr,
		OutIsTTY: output.IsTTY(os.Stdout),
		ErrIsTTY: output.IsTTY(os.Stderr),
	}
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
		return usageError(s, "", "missing command", args)
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
		return usageError(s, args[0], "unknown command: "+args[0], args)
	}
}

// runIssues dispatches the issues resource. Future API surfaces (projects,
// dependencies, ...) plug in as sibling resource dispatchers in Run.
func runIssues(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, "issues", "missing issues command (available: list, get)", args)
	}
	switch args[0] {
	case "list":
		return runList(ctx, args[1:], s)
	case "get":
		return runGet(ctx, args[1:], s)
	default:
		return usageError(s, "issues "+args[0], "unknown issues command: "+args[0], args)
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
		return usageError(s, helpSpec.Name, fmt.Sprintf("unexpected argument %q; help takes no positional arguments", positional[0]), args)
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

// errorKind classifies any error surfaced through the envelope, so machine
// consumers branch on error.kind instead of matching message strings.
func errorKind(err error) string {
	var apiErr *snyk.Error
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return kindCanceled
	case errors.As(err, &apiErr):
		return string(apiErr.Kind)
	default:
		return kindInternal
	}
}

// snykClient builds the API client from the environment — the one place
// where token and tuning env vars are resolved. SNYK_TOKEN is required
// (runtime error); SNYK_HTTP_TIMEOUT optionally bounds each HTTP request
// and must be a positive Go duration (invalid values are usage errors).
// When ok is false the second result is the exit code to return.
func snykClient(s Streams, command string) (*snyk.Client, int, bool) {
	token := os.Getenv("SNYK_TOKEN")
	if token == "" {
		return nil, runtimeError(s, command, kindConfig, "SNYK_TOKEN not set"), false
	}
	client := snyk.NewClient(token, os.Getenv("SNYK_API_URL"))
	client.UserAgent = "snyk-cli/" + Version
	client.Progress = progressLogger(s)
	if v := os.Getenv("SNYK_HTTP_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 {
			return nil, usageError(s, command, "invalid SNYK_HTTP_TIMEOUT: must be a positive duration like 90s or 2m", nil), false
		}
		client.HTTP.Timeout = d
	}
	return client, 0, true
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

func runList(ctx context.Context, args []string, s Streams) int {
	fs := newFlagSet(issuesListSpec.Name)
	f := bind(fs, issuesListSpec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return code
	}
	if len(positional) > 0 {
		return usageError(s, issuesListSpec.Name, fmt.Sprintf("unexpected argument %q; issues list takes no positional arguments", positional[0]), args)
	}
	org := resolveSetting(f.str("org"), "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, issuesListSpec.Name, "--org is required (or set SNYK_ORG_ID)", args)
	}
	project := resolveSetting(f.str("project"), "SNYK_PROJECT_ID")
	if project == "" {
		return usageError(s, issuesListSpec.Name, "--project is required (or set SNYK_PROJECT_ID)", args)
	}
	createdAfter := f.str("created-after")
	if createdAfter != "" {
		if _, err := time.Parse(time.RFC3339, createdAfter); err != nil {
			return usageError(s, issuesListSpec.Name, "invalid --created-after: must be an RFC3339 date-time like 2026-08-01T00:00:00Z", args)
		}
	}
	sevToks, err := normalizeList(f.str("severity"), severities, "severity")
	if err != nil {
		return usageError(s, issuesListSpec.Name, err.Error(), args)
	}
	statusToks, err := normalizeList(f.str("status"), statuses, "status")
	if err != nil {
		return usageError(s, issuesListSpec.Name, err.Error(), args)
	}
	client, code, ok := snykClient(s, issuesListSpec.Name)
	if !ok {
		return code
	}
	query, err := snyk.BuildListQuery(snyk.ListOptions{Severity: strings.Join(sevToks, ","),
		Status:           strings.Join(statusToks, ","),
		IncludeIgnored:   f.boolean("include-ignored"),
		ProjectID:        project,
		CreatedAfter:     createdAfter,
		IncludeCodeFlows: f.boolean("include-code-flows"),
	})
	if err != nil {
		return runtimeError(s, "issues list", errorKind(err), err.Error())
	}
	raw, truncated, err := client.List(ctx, org, query)
	if err != nil {
		return runtimeError(s, "issues list", errorKind(err), err.Error())
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
	mode := output.ResolveMode(f.boolean("json"), f.boolean("quiet"))
	var data any = snyk.ListData{TotalIssues: len(items), Groups: groups, Truncated: truncated}
	if mode == output.ModeQuiet {
		data = groups
	}
	summary := summarize(len(items), strings.Join(statusToks, ","), f.boolean("include-ignored"), strings.Join(sevToks, ","), createdAfter, truncated)
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
		return usageError(s, issuesGetSpec.Name, "exactly one ISSUE_ID argument is required", args)
	}
	org := resolveSetting(f.str("org"), "SNYK_ORG_ID")
	if org == "" {
		return usageError(s, issuesGetSpec.Name, "--org is required (or set SNYK_ORG_ID)", args)
	}
	client, code, ok := snykClient(s, issuesGetSpec.Name)
	if !ok {
		return code
	}
	raw, err := client.Get(ctx, org, positional[0])
	if err != nil {
		return runtimeError(s, "issues get", errorKind(err), err.Error())
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
	switch {
	case len(positional) > 1:
		return usageError(s, skillSpec.Name, "skill takes at most one positional argument: install", args)
	case len(positional) == 1 && positional[0] != "install":
		return usageError(s, skillSpec.Name, fmt.Sprintf("unexpected argument %q; only the optional action install is accepted", positional[0]), args)
	}
	if f.boolean("print") {
		if f.boolean("global") || f.str("dir") != "" {
			return usageError(s, skillSpec.Name, "--print cannot be combined with a destination", args)
		}
		fmt.Fprint(s.Out, embedded.SkillMD)
		return 0
	}
	dir := f.str("dir")
	base := ""
	switch {
	case dir != "":
		base = dir
	case f.boolean("global"):
		home, err := os.UserHomeDir()
		if err != nil {
			return runtimeError(s, "skill", kindInternal, err.Error())
		}
		base = home
	default:
		cwd, err := os.Getwd()
		if err != nil {
			return runtimeError(s, "skill", kindInternal, err.Error())
		}
		base = cwd
	}
	target := filepath.Join(base, ".agents", "skills", "snyk", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return runtimeError(s, "skill", kindInternal, err.Error())
	}
	action := "installed"
	if prev, err := os.ReadFile(target); err == nil && string(prev) == embedded.SkillMD {
		action = "already up to date"
	} else if err := writeFileAtomic(target, []byte(embedded.SkillMD), 0o644); err != nil {
		return runtimeError(s, "skill", kindInternal, err.Error())
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
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
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
		return usageError(s, fs.Name(), err.Error(), args), false
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

// summarize renders the envelope summary line from the effective filters;
// the truncated hint appears only when the page cap actually tripped.
func summarize(n int, statusFlag string, includeIgnored bool, severity, createdAfter string, truncated bool) string {
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
	if truncated {
		parts = append(parts, "truncated=true")
	}
	return strings.Join(parts, " · ")
}

func runtimeError(s Streams, command, kind, msg string) int {
	if s.OutIsTTY {
		fmt.Fprintln(s.Err, "error:", msg)
		return 1
	}
	if err := output.WriteJSON(s.Out, output.Envelope{
		OK:      false,
		Command: command,
		Error:   &output.ErrorPayload{Kind: kind, Message: msg},
	}); err != nil {
		fmt.Fprintln(s.Err, "error:", err)
	}
	return 1
}

// usageError reports an invalid invocation (exit 2). Like runtime errors,
// the failure is also emitted as a structured envelope when the consumer is
// not a TTY or explicitly asked for machine output, so agents and scripts
// can parse any failure uniformly; the plain message and the usage text
// always go to stderr.
func usageError(s Streams, command, msg string, args []string) int {
	if !s.OutIsTTY || jsonRequested(args) {
		if err := output.WriteJSON(s.Out, output.Envelope{
			OK:      false,
			Command: command,
			Error:   &output.ErrorPayload{Kind: kindUsage, Message: msg},
		}); err != nil {
			fmt.Fprintln(s.Err, "error:", err)
		}
	}
	fmt.Fprintln(s.Err, "error:", msg)
	printUsage(s.Err)
	return 2
}

// jsonRequested reports whether the raw args explicitly ask for
// machine-readable output (--json/--quiet), even when flag parsing never
// got that far — usage errors then reach agents as structured envelopes
// too. The flag package accepts single-dash spellings, so those count as
// well; an explicit =false value opts out.
func jsonRequested(args []string) bool {
	for _, a := range args {
		if a == "--" {
			return false
		}
		if !strings.HasPrefix(a, "-") {
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimLeft(a, "-"), "=")
		if name != "json" && name != "quiet" {
			continue
		}
		if hasValue && value == "false" {
			continue
		}
		return true
	}
	return false
}

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
