package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/denjamio/snyk-cli/internal/output"
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

// getString returns the value of a bound string flag ("" when unset or unknown).
func (b *boundFlags) getString(name string) string {
	if p, ok := b.strFlags[name]; ok {
		return *p
	}
	return ""
}

// getBool returns the value of a bound bool flag (false when unset or unknown).
func (b *boundFlags) getBool(name string) bool {
	if p, ok := b.boolFlags[name]; ok {
		return *p
	}
	return false
}

// command is one parsed invocation: the spec it resolved to, the raw args
// as given, the bound flags and the positional arguments.
type command struct {
	spec       commandSpec
	args       []string
	flags      *boundFlags
	positional []string
}

// parseCommand binds the spec's flags to a fresh FlagSet, pre-splits flags
// from positionals and parses them. On a parse failure it reports the
// usage error and returns nil together with its exit code.
func parseCommand(spec commandSpec, args []string, s Streams) (*command, int) {
	fs := newFlagSet(spec.Name)
	f := bind(fs, spec.Flags)
	flagArgs, positional := flagsFirst(args)
	if code, ok := parseFS(fs, flagArgs, s); !ok {
		return nil, code
	}
	return &command{spec: spec, args: args, flags: f, positional: positional}, 0
}

// rejectPositional reports a usage error naming the first offender when a
// command that takes no positional arguments is given one; 0 otherwise.
func (c *command) rejectPositional(s Streams) int {
	if len(c.positional) == 0 {
		return 0
	}
	return usageError(s, c.args, c.spec.Name, fmt.Sprintf("unexpected argument %q; %s takes no positional arguments", c.positional[0], c.spec.Name))
}

func Run(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, args, "", "missing command")
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
		return usageError(s, args, args[0], "unknown command: "+args[0])
	}
}

// runIssues dispatches the issues resource. Future API surfaces (projects,
// dependencies, ...) plug in as sibling resource dispatchers in Run.
func runIssues(ctx context.Context, args []string, s Streams) int {
	if len(args) == 0 {
		return usageError(s, args, "issues", "missing issues command (available: list, get)")
	}
	switch args[0] {
	case "list":
		return runList(ctx, args[1:], s)
	case "get":
		return runGet(ctx, args[1:], s)
	default:
		return usageError(s, args, "issues "+args[0], "unknown issues command: "+args[0])
	}
}

// parseFS parses pre-split flag args, mapping flag package errors to exit
// codes: --help exits cleanly (0, false), anything else is a usage error.
func parseFS(fs *flag.FlagSet, args []string, s Streams) (code int, ok bool) {
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0, false
		}
		return usageError(s, args, fs.Name(), err.Error()), false
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

func newFlagSet(name string) *flag.FlagSet {
	return flag.NewFlagSet(name, flag.ContinueOnError)
}
