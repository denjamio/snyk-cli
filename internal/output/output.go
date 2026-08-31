package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/denjamio/snyk-cli/internal/snyk"
)

type Mode uint8

const (
	ModeAuto Mode = iota
	ModeJSON
	ModeQuiet
)

type Envelope struct {
	OK      bool   `json:"ok"`
	Command string `json:"command"`
	Summary string `json:"summary,omitempty"`
	Error   string `json:"error,omitempty"`
	Data    any    `json:"data,omitempty"`
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

func RenderIssuesTable(w io.Writer, items []snyk.Issue, summary string) {
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SEVERITY\tTYPE\tTITLE\tWHERE\tPROJECT")
	for _, it := range items {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			strings.ToUpper(it.Severity), it.IssueType, truncateRight(it.Title, 40),
			where(it), shortID(it.ProjectID))
	}
	_ = tw.Flush()
}

func RenderGroupsTable(w io.Writer, groups []snyk.IssueGroup, summary string) {
	fmt.Fprintln(w, summary)
	fmt.Fprintln(w)
	for _, g := range groups {
		fmt.Fprintf(w, "== %s · %d issues · %s\n", g.Type, len(g.Issues), severityLabel(g.Severity))
		tw := tabwriter.NewWriter(w, 2, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tWHERE\tPROJECT\tID")
		for _, it := range g.Issues {
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n",
				severityLabel(it.Severity), where(it), shortID(it.ProjectID), shortID(it.ID))
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

func where(it snyk.Issue) string {
	if it.Location != nil && it.Location.File != "" {
		return truncateLeft(fmt.Sprintf("%s:%d", it.Location.File, it.Location.StartLine), whereWidth)
	}
	return "-"
}

const whereWidth = 28

// truncateLeft keeps the tail of s (the last width runes, including an
// ellipsis), so long paths still show the file name next to the line.
func truncateLeft(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return "…" + string(r[len(r)-width+1:])
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

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
