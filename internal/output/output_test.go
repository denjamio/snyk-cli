package output

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/denjamio/snyk-cli/internal/snyk"
)

func TestResolveModePrecedence(t *testing.T) {
	cases := []struct {
		jsonFlag, quietFlag bool
		want                Mode
	}{
		{false, false, ModeAuto},
		{true, false, ModeJSON},
		{false, true, ModeQuiet},
		{true, true, ModeQuiet},
	}
	for _, c := range cases {
		if got := ResolveMode(c.jsonFlag, c.quietFlag); got != c.want {
			t.Errorf("ResolveMode(%v,%v) = %v, want %v", c.jsonFlag, c.quietFlag, got, c.want)
		}
	}
}

func TestIsTTYPipeIsNotTTY(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	defer func() { _ = w.Close() }()
	if IsTTY(r) {
		t.Error("pipe detected as TTY")
	}
}

// Character devices like /dev/null must not pass as terminals: a redirect
// to /dev/null would otherwise flip auto mode to the human table.
func TestIsTTYNullDeviceIsNotTTY(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no null device available: %v", err)
	}
	defer func() { _ = f.Close() }()
	if IsTTY(f) {
		t.Error("null device detected as TTY")
	}
}

func TestRenderIssuesTable(t *testing.T) {
	items := []snyk.Issue{
		{ID: "2", Severity: "low", IssueType: "code", Title: "Insecure hash", ProjectID: "abc12345-def0",
			Location: &snyk.Location{File: "src/services/payments/gateway/adapters/stripe/refund.js", StartLine: 99}},
		{ID: "1", Severity: "critical", IssueType: "code", Title: "RCE via unsafe deserialization", ProjectID: "abc12345-def0",
			Location: &snyk.Location{File: "src/auth.js", StartLine: 7}},
	}
	var buf bytes.Buffer
	RenderIssuesTable(&buf, items, "2 issues · status=open · ignored=false")

	out := buf.String()
	for _, want := range []string{
		"2 issues · status=open · ignored=false",
		"SEVERITY",
		"WHERE",
		"CRITICAL",
		"RCE via unsafe deserialization",
		"src/auth.js:7",
		"LOW",
		"Insecure hash",
		"refund.js:99",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if !strings.Contains(out, "…") {
		t.Error("long path should be left-truncated with ellipsis")
	}
	if strings.Index(out, "CRITICAL") < strings.Index(out, "LOW") {
		t.Error("rows must render in the order they are given (sorting is upstream)")
	}
}

func TestRenderGroupsTable(t *testing.T) {
	groups := []snyk.IssueGroup{
		{
			ID: "sql-injection", Title: "SQL Injection", Severity: "critical",
			Issues: []snyk.Issue{
				{ID: "b22", Severity: "critical", ProjectID: "abc12345-def0",
					Location: &snyk.Location{File: "src/db.js", StartLine: 10}},
				{ID: "a11", Severity: "high", ProjectID: "abc12345-def0",
					Location: &snyk.Location{File: "src/api.js", StartLine: 3}},
			},
		},
		{
			ID: "weak-hash", Title: "Weak Hash", Severity: "medium",
			Issues: []snyk.Issue{
				{ID: "c33", Severity: "medium", ProjectID: "abc12345-def0",
					Location: &snyk.Location{File: "src/hash.js", StartLine: 22}},
			},
		},
	}
	var buf bytes.Buffer
	RenderGroupsTable(&buf, groups, "3 issues · status=open · ignored=false · type=code")

	out := buf.String()
	for _, want := range []string{
		"3 issues · status=open · ignored=false · type=code",
		"== SQL Injection · 2 issues · CRITICAL",
		"== Weak Hash · 1 issues · MEDIUM",
		"SEVERITY",
		"src/db.js:10",
		"src/hash.js:22",
		"b22",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if strings.Index(out, "== SQL Injection") > strings.Index(out, "== Weak Hash") {
		t.Error("groups must render in the order they are given")
	}
	if strings.Index(out, "b22") > strings.Index(out, "a11") {
		t.Error("issues must render in the order they are given")
	}
}

func TestWriteEnvelopeShape(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteEnvelope(&buf, "list", "3 issues", snyk.ListData{TotalIssues: 3, Groups: []snyk.IssueGroup{}}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{`"ok": true`, `"command": "list"`, `"summary": "3 issues"`, `"total_issues"`} {
		if !strings.Contains(out, want) {
			t.Errorf("envelope missing %q:\n%s", want, out)
		}
	}
}

func TestTruncateRight(t *testing.T) {
	cases := []struct {
		in   string
		max  int
		want string
	}{
		{"short", 60, "short"},
		{strings.Repeat("a", 60), 60, strings.Repeat("a", 60)},
		{strings.Repeat("a", 61), 60, strings.Repeat("a", 59) + "…"},
		{strings.Repeat("ñ", 80), 60, strings.Repeat("ñ", 59) + "…"},
	}
	for _, c := range cases {
		if got := truncateRight(c.in, c.max); got != c.want {
			t.Errorf("truncateRight(%q chars, %d) wrong: got %d chars", []rune(c.in), c.max, len([]rune(got)))
		}
	}
}

func TestTruncateLeftKeepsTheTail(t *testing.T) {
	cases := []struct {
		in    string
		width int
		want  string
	}{
		{"short.js", 28, "short.js"},
		{"src/a/very/deeply/nested/path/to/module/gateway.js:99", 28, "…ath/to/module/gateway.js:99"},
	}
	for _, c := range cases {
		if got := truncateLeft(c.in, c.width); got != c.want {
			t.Errorf("truncateLeft(%q, %d) = %q, want %q", c.in, c.width, got, c.want)
		}
	}
}

func TestShortID(t *testing.T) {
	if got := shortID("abcdefghij"); got != "abcdefgh" {
		t.Errorf("shortID long = %q", got)
	}
	if got := shortID("abc"); got != "abc" {
		t.Errorf("shortID short = %q", got)
	}
	if got := shortID(""); got != "" {
		t.Errorf("shortID empty = %q", got)
	}
}

func TestQuietModeWritesRawDataWithoutEnvelope(t *testing.T) {
	var buf bytes.Buffer
	data := []snyk.Issue{{ID: "a"}}
	if err := WriteJSON(&buf, data); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.HasPrefix(strings.TrimSpace(out), "[") {
		t.Errorf("expected bare array, got:\n%s", out)
	}
	if strings.Contains(out, `"ok"`) {
		t.Error("raw data must not contain envelope")
	}
}
