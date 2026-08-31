package cli

import (
	"fmt"

	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
)

const whereWidth = 28

// where renders the issue's primary location as "file:line", left-
// truncated so long paths still show the file name next to the line.
func where(it snyk.Issue) string {
	if it.Location != nil && it.Location.File != "" {
		return truncateLeft(fmt.Sprintf("%s:%d", it.Location.File, it.Location.StartLine), whereWidth)
	}
	return "-"
}

// truncateLeft keeps the tail of s (the last width runes, including an
// ellipsis), so long paths still show the file name next to the line.
func truncateLeft(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	return "…" + string(r[len(r)-width+1:])
}

// shortID trims an id to the leading 8 characters tables display.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

// tableRow projects an issue onto the presentation row the output package
// renders — output stays decoupled from the domain model.
func tableRow(it snyk.Issue) output.Row {
	return output.Row{
		Severity: it.Severity,
		Type:     it.IssueType,
		Title:    it.Title,
		Where:    where(it),
		Project:  shortID(it.ProjectID),
		ID:       shortID(it.ID),
	}
}

// tableGroups projects grouped issues onto their presentation form.
func tableGroups(groups []snyk.IssueGroup) []output.Group {
	out := make([]output.Group, 0, len(groups))
	for _, g := range groups {
		rows := make([]output.Row, 0, len(g.Issues))
		for _, it := range g.Issues {
			rows = append(rows, tableRow(it))
		}
		out = append(out, output.Group{Title: g.Title, Severity: g.Severity, Rows: rows})
	}
	return out
}
