package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	embedded "github.com/denjamio/snyk-cli"
	"github.com/denjamio/snyk-cli/internal/output"
	"github.com/denjamio/snyk-cli/internal/snyk"
)

func newStreams() (Streams, *bytes.Buffer, *bytes.Buffer) {
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	return Streams{Out: out, Err: errOut, OutIsTTY: false}, out, errOut
}

var updateGolden = flag.Bool("update", false, "rewrite the golden files")

// TestListEnvelopeGolden pins the JSON envelope contract byte for byte:
// the sorted, closed payload that pipelines and agents rely on. Intentional
// contract changes are applied with `go test ./internal/cli -update` and
// land in review as the diff they are.
func TestListEnvelopeGolden(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	golden := filepath.Join("testdata", "issues_list_envelope.json")
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("golden file missing; run with -update: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("envelope drifted from the golden contract\n--- golden ---\n%s\n--- got ---\n%s", want, out.Bytes())
	}
}

func decodeEnvelope(t *testing.T, data []byte) output.Envelope {
	t.Helper()
	var env output.Envelope
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("invalid envelope JSON: %v\n%s", err, data)
	}
	return env
}

func TestVersion(t *testing.T) {
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"version"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := strings.TrimSpace(out.String()); got != "snyk "+Version {
		t.Errorf("out = %q", got)
	}
}

func TestHelpText(t *testing.T) {
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"help"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	for _, want := range []string{"list", "get", "version", "--org"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage missing %q", want)
		}
	}
}

func TestHelpJSONCatalog(t *testing.T) {
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"help", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || env.Command != "help" {
		t.Fatalf("envelope = %+v", env)
	}
	data, err := json.Marshal(env.Data)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Commands []commandSpec `json:"commands"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Commands) != 5 {
		t.Fatalf("commands = %d, want 5", len(parsed.Commands))
	}
	var listDoc commandSpec
	for _, c := range parsed.Commands {
		if c.Name == "issues list" {
			listDoc = c
		}
	}
	if len(listDoc.Flags) < 8 {
		t.Errorf("list flags = %d, want >= 8", len(listDoc.Flags))
	}
}

// TestUsageCoversCatalog pins the human usage text to the machine-readable
// catalog: every flag documented there must appear in `help` output, so the
// two help surfaces cannot drift apart.
func TestUsageCoversCatalog(t *testing.T) {
	var buf bytes.Buffer
	printUsage(&buf)
	usage := buf.String()
	for _, cmd := range catalog() {
		for _, f := range cmd.Flags {
			if !strings.Contains(usage, f.Name) {
				t.Errorf("usage missing %q (command %s)", f.Name, cmd.Name)
			}
		}
	}
}

// The documented default for --status comes from the same constant the
// query builder and the envelope summary apply, so the three surfaces
// cannot drift apart.
func TestStatusDefaultIsShared(t *testing.T) {
	for _, c := range catalog() {
		if c.Name != "issues list" {
			continue
		}
		for _, f := range c.Flags {
			if f.Name == "--status" && f.Default != snyk.DefaultStatus {
				t.Errorf("--status documented default = %q, want the shared %q", f.Default, snyk.DefaultStatus)
			}
		}
	}
}

func TestUnknownCommandExit2(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"bogus"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// Usage errors must reach non-human consumers as structured envelopes too,
// mirroring runtime errors: piped always, or on a TTY when --json/--quiet
// was explicitly requested.
func TestUsageErrorEnvelopeWhenPiped(t *testing.T) {
	s, out, errOut := newStreams()
	if rc := Run(context.Background(), []string{"bogus"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindUsage || !strings.Contains(env.Error.Message, "unknown command") {
		t.Fatalf("envelope = %+v", env)
	}
	if !strings.Contains(errOut.String(), "unknown command") {
		t.Errorf("stderr = %q, want the plain message as well", errOut.String())
	}
}

func TestUsageErrorEnvelopeWithJSONOnTTY(t *testing.T) {
	clearScopeEnv(t)
	s, out, _ := newStreams()
	s.OutIsTTY = true
	if rc := Run(context.Background(), []string{"issues", "list", "--json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindUsage || !strings.Contains(env.Error.Message, "--org is required") {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestUsageErrorEnvelopeWithQuietWhenPiped(t *testing.T) {
	clearScopeEnv(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "--quiet"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindUsage || !strings.Contains(env.Error.Message, "ISSUE_ID") {
		t.Fatalf("envelope = %+v", env)
	}
}

func TestUsageErrorPlainOnTTYWithoutJSON(t *testing.T) {
	s, out, _ := newStreams()
	s.OutIsTTY = true
	if rc := Run(context.Background(), []string{"bogus"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should stay clean for humans, got %q", out.String())
	}
}

// clearScopeEnv empties the org/project env vars so host shells exporting
// them cannot leak into tests that assert flag-validation behavior.
func clearScopeEnv(t *testing.T) {
	t.Helper()
	t.Setenv("SNYK_ORG_ID", "")
	t.Setenv("SNYK_PROJECT_ID", "")
}

func TestListRequiresOrg(t *testing.T) {
	clearScopeEnv(t)
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "--org is required") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestListRequiresProject(t *testing.T) {
	clearScopeEnv(t)
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "--project is required") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestListNoTokenStructuredErrorWhenPiped(t *testing.T) {
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "")
	s, out, _ := newStreams()
	rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--json"}, s)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindConfig || !strings.Contains(env.Error.Message, "SNYK_TOKEN not set") {
		t.Fatalf("envelope = %+v", env)
	}
}

// On a human terminal, without machine-output flags, a runtime error is
// the plain message on stderr and stdout stays untouched.
func TestListNoTokenPlainErrorOnTTY(t *testing.T) {
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "")
	s, out, errOut := newStreams()
	s.OutIsTTY = true
	rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p"}, s)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should be empty on TTY error path, got %q", out.String())
	}
	if !strings.HasPrefix(errOut.String(), "error:") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// Runtime errors mirror usage errors: on a TTY, an explicit --json/--quiet
// still routes the structured envelope to stdout, so consumers that asked
// for machine output get it whatever the stream is attached to.
func TestRuntimeErrorEnvelopeWithJSONOnTTY(t *testing.T) {
	for _, flag := range []string{"--json", "--quiet", "-json"} {
		t.Run(flag, func(t *testing.T) {
			clearScopeEnv(t)
			t.Setenv("SNYK_TOKEN", "")
			s, out, errOut := newStreams()
			s.OutIsTTY = true
			rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", flag}, s)
			if rc != 1 {
				t.Fatalf("rc = %d, want 1", rc)
			}
			env := decodeEnvelope(t, out.Bytes())
			if env.Error == nil || env.Error.Kind != kindConfig || !strings.Contains(env.Error.Message, "SNYK_TOKEN not set") {
				t.Fatalf("envelope = %+v, want kind %q", env, kindConfig)
			}
			if !strings.HasPrefix(errOut.String(), "error:") {
				t.Errorf("stderr = %q, want the plain message as well", errOut.String())
			}
		})
	}
}

// The envelope's error.kind classifies the failure so machine consumers
// branch on it instead of matching message strings: auth, not_found, api
// and rate_limit map from HTTP statuses; canceled comes from the context.
func TestErrorKindInEnvelope(t *testing.T) {
	cases := []struct {
		name   string
		status int
		kind   string
	}{
		{"unauthorized", http.StatusUnauthorized, "auth"},
		{"forbidden", http.StatusForbidden, "auth"},
		{"missing issue", http.StatusNotFound, "not_found"},
		{"other api status", http.StatusInternalServerError, "api"},
		{"rate limit exhausted", http.StatusTooManyRequests, "rate_limit"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/vnd.api+json")
				w.Header().Set("Retry-After", "0")
				w.WriteHeader(c.status)
				fmt.Fprint(w, `{"errors":[{"detail":"boom"}]}`)
			}))
			defer srv.Close()
			clearScopeEnv(t)
			t.Setenv("SNYK_TOKEN", "t")
			t.Setenv("SNYK_API_URL", srv.URL)

			s, out, _ := newStreams()
			if rc := Run(context.Background(), []string{"issues", "get", "x", "--org", "o", "--json"}, s); rc != 1 {
				t.Fatalf("rc = %d, want 1", rc)
			}
			env := decodeEnvelope(t, out.Bytes())
			if env.Error == nil || env.Error.Kind != c.kind || !strings.Contains(env.Error.Message, "boom") {
				t.Fatalf("envelope = %+v, want kind %q", env, c.kind)
			}
		})
	}
}

func TestGetParsesFlagsAfterPositional(t *testing.T) {
	t.Setenv("SNYK_TOKEN", "")
	s, out, _ := newStreams()
	rc := Run(context.Background(), []string{"issues", "get", "c", "--org", "o", "--json"}, s)
	if rc != 1 {
		t.Fatalf("rc = %d, want 1 (token error, not usage error)", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || !strings.Contains(env.Error.Message, "SNYK_TOKEN not set") {
		t.Fatalf("expected runtime token error proving --org parsed, got %+v", env)
	}
}

func TestGetRequiresExactlyOnePositional(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "--org", "o"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "exactly one ISSUE_ID") {
		t.Errorf("stderr = %q", errOut.String())
	}
	s2, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "a", "b", "--org", "o"}, s2); rc != 2 {
		t.Fatalf("rc = %d, want 2 for two positionals", rc)
	}
}

func TestFlagsFirst(t *testing.T) {
	cases := []struct {
		name  string
		args  []string
		flags string
		pos   string
	}{
		{"flags after positional", []string{"c", "--org", "o", "--json"}, "--org o --json", "c"},
		{"inline value", []string{"--status=open,resolved", "id1"}, "--status=open,resolved", "id1"},
		{"booleans do not consume", []string{"--include-ignored", "--quiet", "x", "y"}, "--include-ignored --quiet", "x,y"},
		{"terminator", []string{"a", "--", "b", "--json"}, "", "a,b,--json"},
		{"value consumed", []string{"--org", "o", "c"}, "--org o", "c"},
		{"bare dash stays a value", []string{"--dir", "-", "c"}, "--dir -", "c"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			flags, pos, err := flagsFirst(tc.args)
			if err != nil {
				t.Fatalf("flagsFirst(%v): %v", tc.args, err)
			}
			if got := strings.Join(flags, " "); got != tc.flags {
				t.Errorf("flags = %q, want %q", got, tc.flags)
			}
			if got := strings.Join(pos, ","); got != tc.pos {
				t.Errorf("pos = %q, want %q", got, tc.pos)
			}
		})
	}
}

// A known value flag followed by a flag-shaped token is a missing value:
// rejected here instead of letting the flag package silently bind the
// token as the value (`--org --json` would otherwise reach the API as
// org "--json").
func TestFlagsFirstRejectsMissingValue(t *testing.T) {
	for _, args := range [][]string{
		{"--org", "--json"},
		{"--severity", "--quiet", "x"},
		{"issues", "get", "--org", "--", "id"},
	} {
		_, _, err := flagsFirst(args)
		if err == nil {
			t.Errorf("flagsFirst(%v) = nil error, want the missing-value rejection", args)
			continue
		}
		if !strings.Contains(err.Error(), "needs a value") {
			t.Errorf("flagsFirst(%v) err = %v, want the missing-value message", args, err)
		}
	}
}

// End to end: a value flag whose value looks like another flag is a usage
// error (exit 2) — not a runtime error from an API call carrying the
// token as a value.
func TestMissingFlagValueIsUsageErrorBeforeAPICall(t *testing.T) {
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "")
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "x", "--org", "--json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "flag --org needs a value") {
		t.Errorf("stderr = %q", errOut.String())
	}

	s, _, errOut = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--project", "p", "--severity", "--json"}, s); rc != 2 {
		t.Fatalf("severity rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "flag --severity needs a value") {
		t.Errorf("severity stderr = %q", errOut.String())
	}
}

func startMockSnyk(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	requests := 0
	mux := http.NewServeMux()

	page1 := func() string {
		return `{"data":[
			{"id":"b","attributes":{"key":"k2","title":"B issue","type":"code","effective_severity_level":"high","status":"open","ignored":false,"created_at":"2024-01-01T00:00:00Z","updated_at":"2024-01-01T00:00:00Z","description":"desc-b"},"relationships":{"organization":{"data":{"id":"o1"}},"scan_item":{"data":{"id":"p1","type":"project"}}}},
			{"id":"a","attributes":{"key":"k1","title":"A issue","type":"package_vulnerability","effective_severity_level":"critical","status":"open","ignored":false},"relationships":{"organization":{"data":{"id":"o1"}},"scan_item":{"data":{"id":"p1","type":"project"}}}}
		],"links":{"next":"` + srv.URL + `/rest/orgs/o/issues?starting_after=1"}}`
	}
	page2 := `{"data":[
		{"id":"c","attributes":{"key":"k3","title":"C issue","type":"cloud","effective_severity_level":"medium","status":"open","ignored":false,"description":"desc-c","coordinates":[{"remedies":[{"type":"manual","description":"Fix it"}]}]},"relationships":{"organization":{"data":{"id":"o1"}},"scan_item":{"data":{"id":"e1","type":"environment"}}}}
	],"links":{}}`
	detailC := `{"data":{"id":"c","attributes":{"key":"k3","title":"C detail","type":"cloud","effective_severity_level":"medium","status":"open","ignored":false,"coordinates":[{"remedies":[{"type":"manual","description":"Fix it"}]}]},"relationships":{"organization":{"data":{"id":"o1"}},"scan_item":{"data":{"id":"e1","type":"environment"}}}}}`

	mux.HandleFunc("/rest/orgs/o/issues", func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		if requests == 1 {
			fmt.Fprint(w, page1())
			return
		}
		fmt.Fprint(w, page2)
	})
	mux.HandleFunc("/rest/orgs/o/issues/c", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, detailC)
	})

	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "test-token")
	t.Setenv("SNYK_API_URL", srv.URL)
	return srv
}

func TestListQuietOutputsBareGroupsArray(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	body := out.String()
	if !strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Errorf("quiet output is not a bare array:\n%s", body)
	}
	if strings.Contains(body, `"ok"`) {
		t.Error("quiet output must not contain envelope")
	}
	ia := strings.Index(body, `"id": "a-issue"`)
	ib := strings.Index(body, `"id": "b-issue"`)
	ic := strings.Index(body, `"id": "c-issue"`)
	if ia == -1 || ib == -1 || ic == -1 || ia >= ib || ib >= ic {
		t.Errorf("groups not ordered by name:\n%s", body)
	}
}

func TestListEnvelopePipedByDefault(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || env.Command != "issues list" {
		t.Fatalf("envelope = %+v", env)
	}
	if !strings.Contains(env.Summary, "3 issues · status=open · ignored=false") {
		t.Errorf("summary = %q", env.Summary)
	}
	data, _ := json.Marshal(env.Data)
	var ld struct {
		TotalIssues int `json:"total_issues"`
		Groups      []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
			Issues   []struct {
				ID        string `json:"id"`
				IssueType string `json:"issue_type"`
			} `json:"issues"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(data, &ld); err != nil {
		t.Fatal(err)
	}
	if ld.TotalIssues != 3 || len(ld.Groups) != 3 {
		t.Errorf("data = %s", data)
	}
	first := ld.Groups[0]
	if first.ID != "a-issue" || first.Severity != "critical" || len(first.Issues) != 1 {
		t.Errorf("first group = %s", data)
	}
	if first.Issues[0].ID != "a" || first.Issues[0].IssueType != "package_vulnerability" {
		t.Errorf("normalization lost: %s", data)
	}
}

func TestListHumanTableOnTTY(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	s.OutIsTTY = true
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	body := out.String()
	for _, want := range []string{"== A issue", "== B issue", "SEVERITY", "CRITICAL", "HIGH"} {
		if !strings.Contains(body, want) {
			t.Errorf("table missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, `"ok"`) {
		t.Error("TTY mode must not emit JSON")
	}
}

func TestGetSuccessReturnsNormalizedDetail(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "c", "--org", "o", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || env.Command != "issues get" || env.Summary != "1 issue" {
		t.Fatalf("envelope = %+v", env)
	}
	data, _ := json.Marshal(env.Data)
	var item struct {
		ID          string `json:"id"`
		Title       string `json:"title"`
		IssueType   string `json:"issue_type"`
		Remediation *struct {
			ManualSteps string `json:"manual_steps"`
		} `json:"remediation"`
		ProjectID string `json:"project_id"`
	}
	if err := json.Unmarshal(data, &item); err != nil {
		t.Fatal(err)
	}
	if item.ID != "c" || item.Title != "C detail" || item.IssueType != "cloud" {
		t.Errorf("item = %s", data)
	}
	if item.Remediation == nil || item.Remediation.ManualSteps != "Fix it" {
		t.Errorf("remediation = %+v", item.Remediation)
	}
	if item.ProjectID != "" {
		t.Errorf("environment scan item should not map to project_id, got %q", item.ProjectID)
	}
}

// A listing that hits the page cap still succeeds: the payload flags the
// truncation and the warning reaches stderr even on piped runs — the only
// stderr output a piped consumer ever gets.
func TestListTruncationFlagsPayloadAndWarnsOnStderr(t *testing.T) {
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprintf(w, `{"data":[{"id":"i%d"}],"links":{"next":"/rest/orgs/o/issues?p=%d"}}`, requests, requests)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	s, out, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d, want 0 (the cap must not fail the run)", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || !strings.Contains(env.Summary, "truncated=true") {
		t.Fatalf("envelope = %+v, want truncated=true in the summary", env)
	}
	data, _ := json.Marshal(env.Data)
	var ld struct {
		TotalIssues int  `json:"total_issues"`
		Truncated   bool `json:"truncated"`
	}
	if err := json.Unmarshal(data, &ld); err != nil {
		t.Fatal(err)
	}
	if ld.TotalIssues != snyk.MaxPages || !ld.Truncated {
		t.Errorf("data = %s, want total %d (one issue per page, capped) and truncated true", data, snyk.MaxPages)
	}
	if !strings.Contains(errOut.String(), "listing truncated") || !strings.Contains(errOut.String(), "--severity") {
		t.Errorf("stderr = %q, want the truncation warning with a narrowing hint", errOut.String())
	}
}

func TestListTruncationNotFlaggedOnNormalRuns(t *testing.T) {
	startMockSnyk(t)
	s, out, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if strings.Contains(out.String(), `"truncated": true`) || strings.Contains(errOut.String(), "truncated") {
		t.Errorf("normal run must not flag truncation:\nstdout: %s\nstderr: %s", out.String(), errOut.String())
	}
}

func TestFlagHelpExitsCleanly(t *testing.T) {
	for _, args := range [][]string{
		{"issues", "list", "-h"},
		{"issues", "get", "--help"},
		// -h is boolean for the pre-parser: the following flag must
		// survive instead of being swallowed as a value.
		{"issues", "list", "-h", "--json"},
	} {
		s, _, _ := newStreams()
		if rc := Run(context.Background(), args, s); rc != 0 {
			t.Errorf("Run(%v) rc = %d, want 0", args, rc)
		}
	}
}

func TestGetEnvelopeGolden(t *testing.T) {
	startMockSnyk(t)
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "c", "--org", "o", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	golden := filepath.Join("testdata", "issues_get_envelope.json")
	if *updateGolden {
		if err := os.WriteFile(golden, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("golden file missing; run with -update: %v", err)
	}
	if !bytes.Equal(out.Bytes(), want) {
		t.Errorf("envelope drifted from the golden contract\n--- golden ---\n%s\n--- got ---\n%s", want, out.Bytes())
	}
}

// Auth failures carry a region hint: the default base URL serves the EU
// region, so a valid-shaped token rejected with 401 usually means the
// org lives behind another regional endpoint.
func TestAuthErrorCarriesRegionHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"errors":[{"code":"UNAUTHORIZED","detail":"bad token"}]}`)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "x", "--org", "o", "--json"}, s); rc != 1 {
		t.Fatalf("rc = %d, want 1", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != "auth" {
		t.Fatalf("envelope = %+v, want kind auth", env)
	}
	for _, want := range []string{"SNYK_TOKEN", "SNYK_API_URL", snyk.DefaultBaseURL} {
		if !strings.Contains(env.Error.Message, want) {
			t.Errorf("message = %q, want the region hint mentioning %q", env.Error.Message, want)
		}
	}
}

// --compact drops the indentation from both JSON output paths (envelope
// and bare quiet data) without changing their contents.
func TestCompactDropsIndentation(t *testing.T) {
	startMockSnyk(t)

	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--json", "--compact"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	body := out.String()
	if !strings.HasPrefix(body, `{"ok":true`) {
		t.Errorf("compact envelope = %.80s, want an unindented single line", body)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || env.Command != "issues list" {
		t.Fatalf("envelope = %+v", env)
	}

	s, out, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--quiet", "--compact"}, s); rc != 0 {
		t.Fatalf("quiet compact rc = %d", rc)
	}
	body = out.String()
	if !strings.HasPrefix(body, "[") || strings.Count(body, "\n") != 1 {
		t.Errorf("quiet compact output = %.80s, want a bare single-line array", body)
	}
}

func TestSkillPrintOutputsEmbeddedDoc(t *testing.T) {
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"skill", "--print"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	body := out.String()
	if !strings.HasPrefix(body, "---\nname: snyk") || !strings.Contains(body, "# snyk") {
		t.Errorf("print output is not the embedded SKILL.md:\n%.200s", body)
	}
}

func TestSkillPrintRejectsDestination(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"skill", "--print", "--global"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2 for --print with destination", rc)
	}
	if !strings.Contains(errOut.String(), "--print cannot be combined") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestSkillRejectsUnknownPositional(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"skill", "uninstall"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "only the optional action") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestSkillRejectsRepeatedInstall(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"skill", "install", "install"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2 for repeated install positional", rc)
	}
	if !strings.Contains(errOut.String(), "at most one positional") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// The flag package accepts single-dash spellings, so `-json` is a real
// JSON request: usage errors must reach the caller as structured
// envelopes for it too — on a TTY, where plain output is the default —
// while an explicit =false opts back out.
func TestUsageErrorEnvelopeSpellingAndOptOut(t *testing.T) {
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "-json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindUsage || !strings.Contains(env.Error.Message, "ISSUE_ID") {
		t.Fatalf("envelope = %+v, want structured error for -json", env)
	}

	s, out, _ = newStreams()
	s.OutIsTTY = true
	if rc := Run(context.Background(), []string{"issues", "get", "-json"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	env = decodeEnvelope(t, out.Bytes())
	if env.Error == nil || env.Error.Kind != kindUsage || !strings.Contains(env.Error.Message, "ISSUE_ID") {
		t.Fatalf("envelope = %+v, want structured envelope on TTY for -json", env)
	}

	s, out, _ = newStreams()
	s.OutIsTTY = true
	if rc := Run(context.Background(), []string{"issues", "get", "--json=false"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if out.Len() != 0 {
		t.Errorf("stdout = %q, want no envelope for explicit --json=false", out.String())
	}
}

func TestSkillInstallExplicitDir(t *testing.T) {
	dir := t.TempDir()
	s, out, _ := newStreams()
	if rc := Run(context.Background(), []string{"skill", "install", "--dir", dir, "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	env := decodeEnvelope(t, out.Bytes())
	if !env.OK || env.Command != "skill" {
		t.Fatalf("envelope = %+v", env)
	}
	target := filepath.Join(dir, ".agents", "skills", "snyk", "SKILL.md")
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != embedded.SkillMD {
		t.Error("installed SKILL.md differs from the embedded one")
	}

	s, out, _ = newStreams()
	if rc := Run(context.Background(), []string{"skill", "install", "--dir", dir, "--json"}, s); rc != 0 {
		t.Fatalf("reinstall rc = %d", rc)
	}
	env = decodeEnvelope(t, out.Bytes())
	if !strings.Contains(env.Summary, "already up to date") {
		t.Errorf("reinstall summary = %q, want idempotent no-op", env.Summary)
	}
}

// TestSkillInstallReplacesStaleFileAndPermissions exercises the atomic
// write path: an existing (stale) SKILL.md is replaced wholesale with the
// embedded content, and the file lands with 0644 permissions.
func TestSkillInstallReplacesStaleFileAndPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ".agents", "skills", "snyk", "SKILL.md")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"skill", "install", "--dir", dir, "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != embedded.SkillMD {
		t.Error("stale SKILL.md was not replaced with the embedded content")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Errorf("perm = %v, want 0644", info.Mode().Perm())
	}
}

func TestSkillInstallGlobalUsesHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"skill", "install", "--global", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	target := filepath.Join(home, ".agents", "skills", "snyk", "SKILL.md")
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("global install missing: %v", err)
	}
}

// where renders "file:line" from the primary location; issues without one
// get a placeholder dash.
func TestWhereRendersLocation(t *testing.T) {
	cases := []struct {
		name string
		it   snyk.Issue
		want string
	}{
		{"primary location", snyk.Issue{Location: &snyk.Location{File: "src/auth.js", StartLine: 7}}, "src/auth.js:7"},
		{"no location", snyk.Issue{}, "-"},
	}
	for _, c := range cases {
		if got := where(c.it); got != c.want {
			t.Errorf("%s: where = %q, want %q", c.name, got, c.want)
		}
	}
}

// truncateLeft keeps the tail so long paths still show the file name.
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

// tableRow projects an issue onto the presentation row: ids shortened,
// where rendered — output stays decoupled from the domain model.
func TestTableRowProjectsTheIssue(t *testing.T) {
	it := snyk.Issue{
		ID: "abcdefghij", Severity: "high", IssueType: "code", Title: "T", ProjectID: "12345678-abcd",
		Location: &snyk.Location{File: "src/auth.js", StartLine: 7},
	}
	row := tableRow(it)
	if row.Severity != "high" || row.Type != "code" || row.Title != "T" ||
		row.Where != "src/auth.js:7" || row.Project != "12345678" || row.ID != "abcdefgh" {
		t.Errorf("row = %+v", row)
	}
}

func TestSummarizeReflectsEffectiveFilters(t *testing.T) {
	cases := []struct {
		n              int
		status         string
		includeIgnored bool
		severity       string
		createdAfter   string
		truncated      bool
		want           string
	}{
		{0, "", false, "", "", false, "0 issues · status=open · ignored=false · type=code"},
		{7, "open,resolved", true, "", "", false, "7 issues · status=open,resolved · ignored=any · type=code"},
		{5, "", false, "low", "", false, "5 issues · status=open · ignored=false · type=code · severity=low"},
		{2, "", false, "", "2026-08-01T00:00:00Z", false, "2 issues · status=open · ignored=false · type=code · created_after=2026-08-01T00:00:00Z"},
		{3, "", false, "", "", true, "3 issues · status=open · ignored=false · type=code · truncated=true"},
	}
	for _, c := range cases {
		if got := summarize(c.n, c.status, c.includeIgnored, c.severity, c.createdAfter, c.truncated); got != c.want {
			t.Errorf("summarize(%d,%q,%v,%q,%q,%v) = %q, want %q", c.n, c.status, c.includeIgnored, c.severity, c.createdAfter, c.truncated, got, c.want)
		}
	}
}

func TestListCreatedAfterValidatedAndSentToAPI(t *testing.T) {
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		lastQuery = r.URL.Query()
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if lastQuery.Has("created_after") {
		t.Errorf("created_after present by default: %q", lastQuery.Get("created_after"))
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--quiet", "--created-after", "2026-08-01T12:34:56Z"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := lastQuery.Get("created_after"); got != "2026-08-01T12:34:56Z" {
		t.Errorf("created_after param = %q, want verbatim RFC3339 value", got)
	}

	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--created-after", "not-a-date"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2 for invalid RFC3339", rc)
	}
	if !strings.Contains(errOut.String(), "invalid --created-after") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestListValidatesAndNormalizesListFlags(t *testing.T) {
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		lastQuery = r.URL.Query()
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	for _, bad := range [][]string{
		{"--severity", "critcial"},
		{"--severity", "high,"},
		{"--status", "bogus"},
	} {
		s, _, errOut := newStreams()
		args := append([]string{"issues", "list", "--org", "o", "--project", "p"}, bad...)
		if rc := Run(context.Background(), args, s); rc != 2 {
			t.Fatalf("Run(%v) rc = %d, want 2", bad, rc)
		}
		if !strings.Contains(errOut.String(), bad[0]) {
			t.Errorf("Run(%v) stderr = %q, want mention of %s", bad, errOut.String(), bad[0])
		}
	}

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--quiet", "--severity", "high, HIGH ,critical,high"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := lastQuery.Get("effective_severity_level"); got != "high,critical" {
		t.Errorf("severity param = %q, want normalized high,critical", got)
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--quiet", "--status", "Open ,RESOLVED"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := lastQuery.Get("status"); got != "open,resolved" {
		t.Errorf("status param = %q, want normalized open,resolved", got)
	}
}

func TestListTypeFlagIsRejected(t *testing.T) {
	clearScopeEnv(t)
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--type", "code"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2 for removed --type flag", rc)
	}
	if !strings.Contains(errOut.String(), "not defined") {
		t.Errorf("stderr = %q, want unknown-flag error", errOut.String())
	}
}

func TestListSeveritySentToAPIOnlyWhenRequested(t *testing.T) {
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		lastQuery = r.URL.Query()
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if lastQuery.Has("effective_severity_level") {
		t.Errorf("severity param present by default: %q", lastQuery.Get("effective_severity_level"))
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p", "--quiet", "--severity", "LOW"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if got := lastQuery.Get("effective_severity_level"); got != "low" {
		t.Errorf("explicit severity param = %q, want low (verbatim)", got)
	}
}

func TestListDefaultsToCodeFilter(t *testing.T) {
	var gotQuery url.Values
	var gotUA string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		fmt.Fprint(w, `{"data":[],"links":{}}`)
		if r.URL.Path == "/rest/orgs/o/issues" && gotQuery == nil {
			gotQuery = r.URL.Query()
			gotUA = r.Header.Get("User-Agent")
		}
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, s); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if gotQuery == nil {
		t.Fatal("list endpoint was not called")
	}
	if got := gotQuery.Get("type"); got != "code" {
		t.Errorf("type param = %q, want code always (code-only tool)", got)
	}
	if got := gotQuery.Get("scan_item.id"); got != "p1" {
		t.Errorf("scan_item.id param = %q, want p1 (project is required)", got)
	}
	if got := gotQuery.Get("scan_item.type"); got != "project" {
		t.Errorf("scan_item.type param = %q, want project always (project-scoped tool)", got)
	}
	if gotQuery.Has("effective_severity_level") {
		t.Errorf("severity param present by default: %q", gotQuery.Get("effective_severity_level"))
	}
	if want := "snyk-cli/" + Version; gotUA != want {
		t.Errorf("User-Agent = %q, want %q (versioned)", gotUA, want)
	}
}

func TestEnvVarsProvideOrgAndProject(t *testing.T) {
	var lastPath string
	var lastQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.api+json")
		lastPath = r.URL.Path
		lastQuery = r.URL.Query()
		if strings.Contains(r.URL.Path, "/issues/") {
			fmt.Fprint(w, `{"data":{"id":"c","attributes":{"key":"k","title":"C","type":"code","effective_severity_level":"low","status":"open","ignored":false}}}`)
			return
		}
		fmt.Fprint(w, `{"data":[],"links":{}}`)
	}))
	defer srv.Close()
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_API_URL", srv.URL)
	t.Setenv("SNYK_ORG_ID", "envorg")
	t.Setenv("SNYK_PROJECT_ID", "envproj")

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d with env-only invocation", rc)
	}
	if lastPath != "/rest/orgs/envorg/issues" {
		t.Errorf("org from env not used, path = %q", lastPath)
	}
	if got := lastQuery.Get("scan_item.id"); got != "envproj" {
		t.Errorf("project from env not used, scan_item.id = %q", got)
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "flagorg", "--project", "flagproj", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d with flag invocation", rc)
	}
	if lastPath != "/rest/orgs/flagorg/issues" {
		t.Errorf("flag org must win over env, path = %q", lastPath)
	}
	if got := lastQuery.Get("scan_item.id"); got != "flagproj" {
		t.Errorf("flag project must win over env, scan_item.id = %q", got)
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "c", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d for get with SNYK_ORG_ID only", rc)
	}
	if lastPath != "/rest/orgs/envorg/issues/c" {
		t.Errorf("get did not resolve org from env, path = %q", lastPath)
	}

	s, _, _ = newStreams()
	if rc := Run(context.Background(), []string{"issues", "get", "c", "--org", "flagorg", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d for get with explicit org", rc)
	}
	if lastPath != "/rest/orgs/flagorg/issues/c" {
		t.Errorf("get did not honor explicit org, path = %q", lastPath)
	}
}

// SNYK_HTTP_TIMEOUT tunes the per-request timeout; valid values are
// accepted (the request goes through), anything that is not a positive
// duration is a usage error before any call is made.
func TestSnykHTTPTimeout(t *testing.T) {
	startMockSnyk(t)

	s, _, _ := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--quiet", "--json"}, s); rc != 0 {
		t.Fatalf("rc = %d without SNYK_HTTP_TIMEOUT", rc)
	}

	s, _, errOut := newStreams()
	t.Setenv("SNYK_HTTP_TIMEOUT", "-1s")
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, s); rc != 2 {
		t.Fatalf("rc = %d for negative SNYK_HTTP_TIMEOUT, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "invalid SNYK_HTTP_TIMEOUT") {
		t.Errorf("stderr = %q", errOut.String())
	}

	s, _, errOut = newStreams()
	t.Setenv("SNYK_HTTP_TIMEOUT", "not-a-duration")
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, s); rc != 2 {
		t.Fatalf("rc = %d for invalid SNYK_HTTP_TIMEOUT, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "invalid SNYK_HTTP_TIMEOUT") {
		t.Errorf("stderr = %q", errOut.String())
	}

	s, _, _ = newStreams()
	t.Setenv("SNYK_HTTP_TIMEOUT", "90s")
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--quiet"}, s); rc != 0 {
		t.Fatalf("rc = %d with valid SNYK_HTTP_TIMEOUT", rc)
	}
}

// Progress events reach stderr only on interactive terminals; piped
// consumers — scripts, agents — get a silent run and a clean stream.
func TestProgressOnTTYOnly(t *testing.T) {
	startMock429Once := func(t *testing.T) {
		t.Helper()
		attempts := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			attempts++
			w.Header().Set("Retry-After", "0")
			if attempts == 1 {
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			w.Header().Set("Content-Type", "application/vnd.api+json")
			fmt.Fprint(w, `{"data":[],"links":{}}`)
		}))
		t.Cleanup(srv.Close)
		clearScopeEnv(t)
		t.Setenv("SNYK_TOKEN", "t")
		t.Setenv("SNYK_API_URL", srv.URL)
	}

	startMock429Once(t)
	sTTY, _, errTTY := newStreams()
	sTTY.ErrIsTTY = true
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, sTTY); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.Contains(errTTY.String(), "snyk: HTTP 429, retrying") {
		t.Errorf("stderr on TTY = %q, want retry progress", errTTY.String())
	}

	startMock429Once(t)
	sPipe, outPipe, errPipe := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1"}, sPipe); rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if errPipe.Len() != 0 {
		t.Errorf("piped stderr = %q, want silence", errPipe.String())
	}
	env := decodeEnvelope(t, outPipe.Bytes())
	if !env.OK {
		t.Fatalf("envelope = %+v", env)
	}
}

type failingWriter struct{}

func (failingWriter) Write(p []byte) (int, error) { return 0, errors.New("write failed") }

func TestEmitWriteErrorReturnsOne(t *testing.T) {
	s := Streams{Out: failingWriter{}, Err: &bytes.Buffer{}, OutIsTTY: false}
	rc := emit(s, output.ModeJSON, false, "issues list", "s", map[string]any{}, func(w io.Writer) error { return nil })
	if rc != 1 {
		t.Fatalf("rc = %d, want 1 on write failure", rc)
	}
	rc = emit(s, output.ModeQuiet, true, "issues list", "s", map[string]any{}, func(w io.Writer) error { return nil })
	if rc != 1 {
		t.Fatalf("compact rc = %d, want 1 on write failure", rc)
	}
}

// Human output is held to the same contract: a failed render is a runtime
// error (exit 1), never a silent half-written table.
func TestEmitHumanWriteErrorReturnsOne(t *testing.T) {
	s := Streams{Out: failingWriter{}, Err: &bytes.Buffer{}, OutIsTTY: true}
	rc := emit(s, output.ModeAuto, false, "issues list", "s", map[string]any{}, func(w io.Writer) error {
		return errors.New("write failed")
	})
	if rc != 1 {
		t.Fatalf("rc = %d, want 1 on human render failure", rc)
	}
	if !strings.Contains(s.Err.(*bytes.Buffer).String(), "write failed") {
		t.Errorf("stderr = %q, want the render error", s.Err.(*bytes.Buffer).String())
	}
}

// The dispatch table and the command catalog are pinned together: every
// catalog command must be reachable from Run, and every dispatch entry
// must be documented by the catalog — either side drifting alone breaks
// `help --json` consumers or leaves a command undiscoverable.
func TestDispatchCoversCatalog(t *testing.T) {
	first := func(name string) string { return strings.Fields(name)[0] }
	for _, c := range catalog() {
		if _, ok := dispatch[first(c.Name)]; !ok {
			t.Errorf("catalog command %q: top-level word %q missing from dispatch", c.Name, first(c.Name))
		}
	}
	for word := range dispatch {
		found := false
		for _, c := range catalog() {
			if first(c.Name) == word {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("dispatch word %q is not documented by any catalog command", word)
		}
	}
}

func TestRunEmptyArgsUsageError(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), nil, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "missing command") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestVersionAliases(t *testing.T) {
	for _, args := range [][]string{{"--version"}, {"-v"}} {
		s, out, _ := newStreams()
		if rc := Run(context.Background(), args, s); rc != 0 {
			t.Fatalf("Run(%v) rc = %d", args, rc)
		}
		if !strings.Contains(out.String(), Version) {
			t.Errorf("out = %q, want version %q", out.String(), Version)
		}
	}
}

// version --json routes the version through the standard envelope, so
// agents read it without parsing prose.
func TestVersionJSON(t *testing.T) {
	for _, args := range [][]string{{"version", "--json"}, {"--version", "--json"}} {
		s, out, _ := newStreams()
		if rc := Run(context.Background(), args, s); rc != 0 {
			t.Fatalf("Run(%v) rc = %d", args, rc)
		}
		env := decodeEnvelope(t, out.Bytes())
		if !env.OK || env.Command != "version" {
			t.Fatalf("envelope = %+v", env)
		}
		data, _ := json.Marshal(env.Data)
		var payload struct {
			Version string `json:"version"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
		if payload.Version != Version {
			t.Errorf("data.version = %q, want %q", payload.Version, Version)
		}
	}
}

func TestFlagMissingValueIsUsageError(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "--severity"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "flag needs an argument") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func FuzzFlagsFirst(f *testing.F) {
	f.Add("c", "--org")
	f.Add("--org", "o")
	f.Add("--status=open,resolved", "id1")
	f.Add("--include-ignored", "--quiet")
	f.Add("a", "--")
	f.Add("--severity", "")
	f.Add("--org", "--json")
	f.Fuzz(func(t *testing.T, a, b string) {
		args := []string{a, b}
		flags, positional, err := flagsFirst(args)
		if err != nil {
			// The rejection is only legal when a known value flag is
			// followed by a flag-shaped token; anything else must parse.
			missingValue := valueFlags[strings.TrimLeft(a, "-")] && !strings.Contains(a, "=") && isFlagShaped(b)
			if !missingValue {
				t.Fatalf("unexpected rejection for %q %q: %v", a, b, err)
			}
			return
		}
		total := len(flags) + len(positional)
		hasTerminator := slices.Contains(args, "--")
		if total > len(args) || (!hasTerminator && total != len(args)) {
			t.Fatalf("args not conserved: in=%d flags=%d pos=%d", len(args), len(flags), len(positional))
		}
	})
}

// FuzzNormalizeList pins the list-normalizer contract on arbitrary input:
// a successful parse yields only allowed tokens, lowercased, deduplicated
// and in input order; anything else is a rejection, never a panic.
func FuzzNormalizeList(f *testing.F) {
	for _, s := range []string{"", "high", "HIGH, low", "info,info", " , ", "critical,unknown", " medium "} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, value string) {
		out, err := normalizeList(value, severities, "severity")
		if err != nil {
			return
		}
		lower := strings.ToLower(value)
		prev := -1
		seen := map[string]bool{}
		for _, tok := range out {
			if !slices.Contains(severities, tok) {
				t.Fatalf("token %q not in the allowed set (input %q)", tok, value)
			}
			if seen[tok] {
				t.Fatalf("duplicate token %q (input %q)", tok, value)
			}
			seen[tok] = true
			at := strings.Index(lower, tok)
			if at < prev {
				t.Fatalf("tokens out of input order: %v (input %q)", out, value)
			}
			prev = at
		}
	})
}

func TestHelpRejectsPositional(t *testing.T) {
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"help", "issues"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "takes no positional arguments") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

func TestListRejectsPositional(t *testing.T) {
	clearScopeEnv(t)
	s, _, errOut := newStreams()
	if rc := Run(context.Background(), []string{"issues", "list", "stray"}, s); rc != 2 {
		t.Fatalf("rc = %d, want 2", rc)
	}
	if !strings.Contains(errOut.String(), "takes no positional arguments") {
		t.Errorf("stderr = %q", errOut.String())
	}
}

// SNYK_TIMEOUT bounds the whole run: when the deadline fires, in-flight
// work aborts with a canceled-kind envelope instead of hanging on the
// (slow) server response.
func TestRunTimeoutAbortsRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	clearScopeEnv(t)
	t.Setenv("SNYK_API_URL", srv.URL)
	t.Setenv("SNYK_TOKEN", "t")
	t.Setenv("SNYK_TIMEOUT", "50ms")

	s, out, _ := newStreams()
	done := make(chan int, 1)
	go func() {
		done <- Run(context.Background(), []string{"issues", "list", "--org", "o", "--project", "p1", "--json"}, s)
	}()
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("rc = %d, want 1 on expired SNYK_TIMEOUT", rc)
		}
		env := decodeEnvelope(t, out.Bytes())
		if env.Error == nil || env.Error.Kind != kindCanceled || !strings.Contains(env.Error.Message, "context deadline exceeded") {
			t.Fatalf("envelope = %+v, want kind %q with the deadline error", env, kindCanceled)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on the SNYK_TIMEOUT deadline")
	}
}

// An invalid SNYK_TIMEOUT is a usage error (exit 2) before any command
// work happens — a misconfigured duration must never silently disable
// the deadline.
func TestRunInvalidTimeoutIsUsageError(t *testing.T) {
	for _, v := range []string{"nope", "-1s", "0s"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("SNYK_TIMEOUT", v)
			s, _, errOut := newStreams()
			if rc := Run(context.Background(), []string{"version"}, s); rc != 2 {
				t.Fatalf("SNYK_TIMEOUT=%q rc = %d, want 2", v, rc)
			}
			if !strings.Contains(errOut.String(), "invalid SNYK_TIMEOUT") {
				t.Errorf("stderr = %q", errOut.String())
			}
		})
	}
}

// TestRunContextCanceledPropagatesToClient pins the contract that the
// context handed to Run reaches the API client: a canceled context aborts
// the call instead of waiting for the (slow) server response.
func TestRunContextCanceledPropagatesToClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	t.Setenv("SNYK_API_URL", srv.URL)
	t.Setenv("SNYK_TOKEN", "t")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, out, _ := newStreams()
	done := make(chan int, 1)
	go func() {
		done <- Run(ctx, []string{"issues", "list", "--org", "o", "--project", "p1", "--json"}, s)
	}()
	select {
	case rc := <-done:
		if rc != 1 {
			t.Fatalf("rc = %d, want 1 on canceled context", rc)
		}
		env := decodeEnvelope(t, out.Bytes())
		if env.Error == nil || env.Error.Kind != kindCanceled || !strings.Contains(env.Error.Message, "context canceled") {
			t.Fatalf("envelope = %+v, want kind %q with the context error", env, kindCanceled)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return on canceled context")
	}
}
