package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
)

type Mode uint8

const (
	ModeAuto Mode = iota
	ModeJSON
	ModeQuiet
)

// ErrorPayload is the structured failure inside the envelope: kind lets
// machine consumers branch (auth, not_found, rate_limit, ...) without
// matching message strings, message is the human-readable detail.
type ErrorPayload struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type Envelope struct {
	OK      bool          `json:"ok"`
	Command string        `json:"command"`
	Summary string        `json:"summary,omitempty"`
	Error   *ErrorPayload `json:"error,omitempty"`
	Data    any           `json:"data,omitempty"`
}

func ResolveMode(jsonFlag, quietFlag bool) Mode {
	switch {
	case quietFlag:
		return ModeQuiet
	case jsonFlag:
		return ModeJSON
	default:
		return ModeAuto
	}
}

// IsTTY reports whether f is attached to a terminal. The probe is
// platform-implemented (isatty_*.go): a real terminal query — not just a
// ModeCharDevice check — so character devices like /dev/null are not
// mistaken for terminals in auto output mode.
func IsTTY(f *os.File) bool {
	return isTerminal(f)
}

func WriteJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func WriteEnvelope(w io.Writer, command, summary string, data any) error {
	return WriteJSON(w, Envelope{OK: true, Command: command, Summary: summary, Data: data})
}

// Row is one issue as the tables render it: a presentation-only
// projection the caller (cli) builds from its domain model, so this
// package carries no dependency on it.
type Row struct {
	Severity string // as returned by the API; rendered uppercase
	Type     string
	Title    string
	Where    string // "file:line", already width-truncated by the caller
	Project  string // short id
	ID       string // short id
}

// Group is one vulnerability-type cluster for the groups table.
type Group struct {
	Title    string
	Severity string
	Rows     []Row
}

func RenderIssuesTable(w io.Writer, rows []Row, summary string) {
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tTYPE\tTITLE\tWHERE\tPROJECT")
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			severityLabel(r.Severity), r.Type, truncateRight(r.Title, 40), r.Where, r.Project)
	}
	_ = tw.Flush()
}

func RenderGroupsTable(w io.Writer, groups []Group, summary string) {
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)
	for _, g := range groups {
		fmt.Fprintf(w, "== %s · %d issues · %s\n", g.Title, len(g.Rows), severityLabel(g.Severity))
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tWHERE\tPROJECT\tID")
		for _, r := range g.Rows {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
				severityLabel(r.Severity), r.Where, r.Project, r.ID)
		}
		_ = tw.Flush()
		fmt.Fprintln(w)
	}
}

func severityLabel(severity string) string {
	if severity == "" {
		return "-"
	}
	return strings.ToUpper(severity)
}

// truncateRight keeps the head of s (the first max runes, ending in an
// ellipsis).
func truncateRight(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}
