package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
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

// failureMessage renders a client error for the envelope, appending a
// region hint to auth failures: a valid-looking token rejected with
// 401/403 usually means the org lives behind another regional endpoint
// than the default (EU) base URL.
func failureMessage(err error) string {
	msg := err.Error()
	var apiErr *snyk.Error
	if errors.As(err, &apiErr) && apiErr.Kind == snyk.KindAuth {
		return msg + "; check SNYK_TOKEN and, for orgs outside the EU region, set SNYK_API_URL (default: " + snyk.DefaultBaseURL + ")"
	}
	return msg
}

// fail is the single path every failure takes to the user. The structured
// envelope goes to stdout whenever the consumer is not a TTY or explicitly
// asked for machine output (--json/--quiet), so agents and scripts parse
// any failure uniformly. Humans on a terminal always get the plain message
// on stderr; usage errors (exit 2) additionally print it there on piped
// runs, together with the usage text.
func fail(s Streams, args []string, command, kind, msg string, exit int) int {
	structured := !s.OutIsTTY || jsonRequested(args)
	if structured {
		if err := output.WriteJSON(s.Out, output.Envelope{
			OK:      false,
			Command: command,
			Error:   &output.ErrorPayload{Kind: kind, Message: msg},
		}); err != nil {
			fmt.Fprintln(s.Err, "error:", err)
		}
	}
	if s.OutIsTTY || exit == 2 {
		fmt.Fprintln(s.Err, "error:", msg)
	}
	if exit == 2 {
		printUsage(s.Err)
	}
	return exit
}

// runtimeError reports a failed run (exit 1): config, API, network and
// alike. A human terminal sees the plain message on stderr; piped runs,
// and TTY runs that asked for --json/--quiet, get the envelope on stdout.
func runtimeError(s Streams, args []string, command, kind, msg string) int {
	return fail(s, args, command, kind, msg, 1)
}

// usageError reports an invalid invocation (exit 2).
func usageError(s Streams, args []string, command, msg string) int {
	return fail(s, args, command, kindUsage, msg, 2)
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
