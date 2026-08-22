package snyk

import (
	"encoding/json"
	"strings"
	"testing"
)

// ossRichFixture mirrors a package_vulnerability payload. The CLI is
// code-only, but normalization must stay total: any issue the API returns
// is normalized without error, ignoring fields that do not apply to code.
const ossRichFixture = `{
  "id": "d5b640e5-d88c-4c17-9bf0-93597b7a1ce2",
  "attributes": {
    "key": "npm:hoek:20180212:hoek:2.16.3",
    "title": "Hoek - Prototype Pollution",
    "type": "package_vulnerability",
    "effective_severity_level": "medium",
    "status": "open",
    "ignored": false,
    "created_at": "2022-09-27T20:09:05Z",
    "updated_at": "2022-09-28T20:09:05Z",
    "description": "Prototype pollution vulnerability.",
    "coordinates": [
      {
        "is_upgradeable": true,
        "remedies": [
          {"type": "indeterminate", "meta": {"data": {"semver_vulnerable": ["<2.16.4"], "fixed_in": ["2.16.4"]}}},
          {"type": "cli", "description": "snyk wizard"}
        ],
        "representations": [{"dependency": {"package_name": "hoek", "package_version": "2.16.3"}}]
      }
    ],
    "problems": [
      {"id": "npm:hoek:20180212", "url": "https://security.snyk.io/vuln/npm/hoek"},
      {"id": "CVE-2018-16477"},
      {"id": "cwe-1321"},
      {"id": "dup", "url": "https://security.snyk.io/vuln/npm/hoek"}
    ],
    "severities": [
      {"score": 7.5, "vector": "CVSS:3.1/AV:N"},
      {"score": 9.8, "vector": "CVSS:4.0/AV:N"},
      {"score": 7.5, "vector": "CVSS:3.1/AV:L"}
    ],
    "risk": {"score": {"value": 640}}
  },
  "relationships": {
    "organization": {"data": {"id": "o1"}},
    "scan_item": {"data": {"id": "p1", "type": "project"}}
  }
}`

func mustNormalize(t *testing.T, fixture string) Issue {
	t.Helper()
	var raw RawIssue
	if err := json.Unmarshal([]byte(fixture), &raw); err != nil {
		t.Fatal(err)
	}
	return Normalize(raw)
}

func TestNormalizeOSSRich(t *testing.T) {
	item := mustNormalize(t, ossRichFixture)

	checks := map[string]struct{ got, want any }{
		"id":         {item.ID, "d5b640e5-d88c-4c17-9bf0-93597b7a1ce2"},
		"key":        {item.Key, "npm:hoek:20180212:hoek:2.16.3"},
		"issue_type": {item.IssueType, "package_vulnerability"},
		"severity":   {item.Severity, "medium"},
		"org_id":     {item.OrgID, "o1"},
		"project_id": {item.ProjectID, "p1"},
	}
	for name, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", name, c.got, c.want)
		}
	}
	if item.Remediation != nil {
		t.Errorf("remediation = %+v, want nil without manual remedy", item.Remediation)
	}
	if item.RiskScore == nil || *item.RiskScore != 640 {
		t.Errorf("risk_score = %v", item.RiskScore)
	}
	if item.Location != nil {
		t.Errorf("location = %+v, want nil", item.Location)
	}
	if len(item.CWEs) != 1 || item.CWEs[0] != "CWE-1321" {
		t.Errorf("cwes = %v", item.CWEs)
	}
	if len(item.Locations) != 0 {
		t.Errorf("locations = %v", item.Locations)
	}
}

const codeFixture = `{
  "id": "aaa-bbb",
  "attributes": {
    "key": "k",
    "title": "Insecure hash function used",
    "type": "code",
    "effective_severity_level": "high",
    "status": "open",
    "ignored": false,
    "created_at": "2022-09-27T20:09:05Z",
    "updated_at": "2022-09-27T20:09:05Z",
    "coordinates": [
      {
        "remedies": [{"type": "manual", "description": "Use bcrypt instead."}],
        "representations": [
          {"sourceLocation": {"file": "src/hash.js", "region": {"start": {"line": 12, "column": 5}, "end": {"line": 14, "column": 1}}}},
          {"sourceLocation": {"file": "src/util.js", "region": {"start": {"line": 3, "column": 0}}}}
        ]
      }
    ]
  },
  "relationships": {
    "organization": {"data": {"id": "o1"}},
    "scan_item": {"data": {"id": "e1", "type": "environment"}}
  }
}`

func TestNormalizeCodeLocationAndScanItem(t *testing.T) {
	item := mustNormalize(t, codeFixture)

	if item.Location == nil || item.Location.File != "src/hash.js" || item.Location.StartLine != 12 {
		t.Errorf("location = %+v", item.Location)
	}
	if len(item.Locations) != 2 ||
		item.Locations[0].File != "src/hash.js" || item.Locations[0].StartLine != 12 ||
		item.Locations[1].File != "src/util.js" || item.Locations[1].StartLine != 3 {
		t.Errorf("locations = %+v", item.Locations)
	}
	if item.ProjectID != "" {
		t.Errorf("project_id = %q, want empty for environment scan item", item.ProjectID)
	}
	if item.Remediation == nil || item.Remediation.ManualSteps != "Use bcrypt instead." {
		t.Errorf("remediation = %+v", item.Remediation)
	}
}

func TestNormalizeCodeTriageSignals(t *testing.T) {
	item := mustNormalize(t, codeTriageFixture)

	if len(item.CWEs) != 1 || item.CWEs[0] != "CWE-94" {
		t.Errorf("cwes = %v, want [CWE-94] from classes (code items carry no CWE in problems)", item.CWEs)
	}
	if item.IntroducedAt != "2026-08-21T14:14:46.015Z" {
		t.Errorf("introduced_at = %q", item.IntroducedAt)
	}
	if item.LastResolvedAt != "2026-03-25T10:38:26.184Z" || item.LastResolvedDetails != "DISAPPEARED" {
		t.Errorf("last_resolved = %q/%q, want regression signal", item.LastResolvedAt, item.LastResolvedDetails)
	}
	if !item.FixableManually || item.FixableSnyk || item.FixableUpstream {
		t.Errorf("fixable flags = %v/%v/%v", item.FixableManually, item.FixableSnyk, item.FixableUpstream)
	}
	if item.Location == nil || item.Location.CommitID != "a2c24dae7542aa017f105eb8bddfac836150dd8f" {
		t.Errorf("location = %+v, want commit_id", item.Location)
	}
	if len(item.CodeFlows) != 2 {
		t.Fatalf("code_flows = %d flows, want 2", len(item.CodeFlows))
	}
	f0 := item.CodeFlows[0]
	if len(f0) != 3 || f0[0].File != "app/input.rb" || f0[0].Line != 4 ||
		f0[1].Line != 18 || f0[2].Line != 21 {
		t.Errorf("code_flows[0] = %+v", f0)
	}
	if !item.CodeFlowsOmitted {
		t.Error("code_flows_omitted = false, want true")
	}
}

// Mirrors a real GET /orgs/{org_id}/issues payload for type=code with
// include_code_flows=true (version 2026-03-25).
const codeTriageFixture = `{
  "id": "d7e3bc0c-6311-49b9-ab86-5fd5ee4472d7",
  "attributes": {
    "key": "cf443527-6174-43f8-9f7a-0b954a51f697",
    "title": "Code Injection",
    "type": "code",
    "effective_severity_level": "high",
    "status": "open",
    "ignored": false,
    "created_at": "2026-03-24T18:35:53.083Z",
    "updated_at": "2026-08-26T08:08:00.385Z",
    "description": "Unsanitized input from a database flows to select a class/method and payload dynamically executed in \"post.send\".",
    "classes": [{"id": "CWE-94", "source": "CWE", "type": "weakness"}],
    "problems": [{"id": "cf443527-6174-43f8-9f7a-0b954a51f697", "source": "SNYK", "type": "vulnerability"}],
    "risk": {"factors": [], "score": {"model": "v1", "value": 825}},
    "coordinates": [
      {
        "created_at": "2026-03-24T18:35:53.083Z",
        "is_fixable_manually": false,
        "is_fixable_snyk": false,
        "is_fixable_upstream": false,
        "last_introduced_at": "2026-08-21T14:14:46.015Z",
        "last_resolved_at": "2026-03-25T10:38:26.184Z",
        "last_resolved_details": "DISAPPEARED",
        "code_flows_omitted": true,
        "code_flows": [
          {
            "thread_flows": [
              {
                "locations": [
                  {"file": "app/input.rb", "region": {"start": {"line": 4, "column": 8}, "end": {"line": 4, "column": 30}}},
                  {"file": "app/input.rb", "region": {"start": {"line": 18, "column": 1}, "end": {"line": 18, "column": 9}}},
                  {"file": "app/exec.rb", "region": {"start": {"line": 21, "column": 18}, "end": {"line": 21, "column": 35}}}
                ]
              }
            ]
          },
          {
            "thread_flows": [
              {
                "locations": [
                  {"file": "app/other.rb", "region": {"start": {"line": 7, "column": 2}, "end": {"line": 7, "column": 12}}}
                ]
              }
            ]
          }
        ],
        "remedies": [{"description": "generic prevention boilerplate", "type": "indeterminate"}],
        "representations": [
          {"sourceLocation": {"commit_id": "a2c24dae7542aa017f105eb8bddfac836150dd8f", "file": "app/controllers/forum.rb", "region": {"end": {"column": 35, "line": 21}, "start": {"column": 18, "line": 21}}}}
        ],
        "state": "open",
        "updated_at": "2026-08-26T08:08:00.385Z"
      },
      {
        "is_fixable_manually": true,
        "representations": [
          {"sourceLocation": {"file": "app/second.rb", "region": {"start": {"line": 9, "column": 0}}}}
        ]
      }
    ]
  },
  "relationships": {
    "organization": {"data": {"id": "o1"}},
    "scan_item": {"data": {"id": "p1", "type": "project"}}
  }
}`

func TestNormalizeEmitsClosedStructure(t *testing.T) {
	item := mustNormalize(t, `{
      "id": "i1",
      "attributes": {"key":"k","title":"T","type":"code","effective_severity_level":"low","status":"resolved","ignored":true},
      "relationships": {"organization":{"data":{"id":"o1"}},"scan_item":{"data":{"id":"p1","type":"project"}}}
    }`)

	if !item.Ignored || item.Status != "resolved" {
		t.Errorf("flags = %+v", item)
	}
	if item.Description != "" || item.Remediation != nil ||
		item.RiskScore != nil || item.Location != nil {
		t.Errorf("absent payloads must be zero-valued: %+v", item)
	}
	if item.Locations == nil || item.CWEs == nil ||
		item.CodeFlows == nil {
		t.Errorf("absent collections must be empty arrays, not nil: %+v", item)
	}

	out, err := json.Marshal(item)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"id", "key", "title", "issue_type", "severity", "status", "ignored",
		"org_id", "project_id", "created_at", "updated_at", "description",
		"remediation", "risk_score", "location",
		"locations", "cwes",
		"introduced_at", "last_resolved_at", "last_resolved_details",
		"fixable_manually", "fixable_snyk", "fixable_upstream",
		"code_flows", "code_flows_omitted",
	} {
		if !strings.Contains(string(out), `"`+key+`":`) {
			t.Errorf("closed structure missing key %q: %s", key, out)
		}
	}
	for _, banned := range []string{"package", "license", "cvss", "references"} {
		if strings.Contains(string(out), `"`+banned+`":`) {
			t.Errorf("code payload must not carry %q: %s", banned, out)
		}
	}
	for _, nullCollection := range []string{"locations", "cwes", "code_flows"} {
		if strings.Contains(string(out), `"`+nullCollection+`":null`) {
			t.Errorf("collection %q must serialize as [], not null: %s", nullCollection, out)
		}
	}
}

func TestGroupByTypeOrdersGroupsAlphabeticallyByName(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "x1", Key: "k-x", Title: "Zeta rule", Severity: "critical"},
		{ID: "y1", Key: "k-y", Title: "Alpha rule", Severity: "low"},
		{ID: "z1", Key: "k-z", Title: "Mid rule", Severity: "high"},
	})

	want := []string{"Alpha rule", "Mid rule", "Zeta rule"}
	if len(groups) != len(want) {
		t.Fatalf("groups = %d, want %d", len(groups), len(want))
	}
	for i, name := range want {
		if groups[i].Type != name {
			t.Fatalf("group %d = %q, want %q (all: %+v)", i, groups[i].Type, name, groups)
		}
	}
	if groups[0].Severity != "low" {
		t.Errorf("group severity must stay the worst present, got %q", groups[0].Severity)
	}
}

func TestGroupSlugNormalizesTitles(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SQL Injection", "sql-injection"},
		{"  SQL   Injection  ", "sql-injection"},
		{"Hoek - Prototype Pollution", "hoek-prototype-pollution"},
		{"XSS (reflected) / v2.0", "xss-reflected-v2-0"},
		{"Inyección SQL", "inyección-sql"},
		{"", "unknown"},
		{"???", "unknown"},
	}
	for _, c := range cases {
		if got := groupSlug(c.in); got != c.want {
			t.Errorf("groupSlug(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGroupByTypeSlugIsDeterministicOnCollision(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "i1", Title: "SQL Injection", Severity: "high"},
		{ID: "i2", Title: "sql  injection!", Severity: "low"},
	})
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2 (distinct titles)", len(groups))
	}
	if groups[0].ID != "sql-injection" || groups[1].ID != "sql-injection-2" {
		t.Fatalf("group ids = %q, %q", groups[0].ID, groups[1].ID)
	}
}

func TestGroupByTypeSuffixesEveryCollisionUniquely(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "i1", Title: "X rule", Severity: "high"},
		{ID: "i2", Title: "x rule!", Severity: "medium"},
		{ID: "i3", Title: "X RULE", Severity: "low"},
	})
	if len(groups) != 3 {
		t.Fatalf("groups = %d, want 3", len(groups))
	}
	seen := map[string]bool{}
	for _, g := range groups {
		if seen[g.ID] {
			t.Fatalf("duplicate group id %q", g.ID)
		}
		seen[g.ID] = true
	}
	want := []string{"x-rule", "x-rule-2", "x-rule-3"}
	for i, id := range want {
		if groups[i].ID != id {
			t.Fatalf("group %d id = %q, want %q", i, groups[i].ID, id)
		}
	}
}

func TestGroupPayloadOmitsDisplayName(t *testing.T) {
	groups := GroupByType([]Issue{{ID: "i1", Title: "SQL Injection", Severity: "high"}})
	out, err := json.Marshal(groups[0])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), `"type"`) {
		t.Errorf("payload must not carry the display name: %s", out)
	}
	if !strings.Contains(string(out), `"id":"sql-injection"`) {
		t.Errorf("payload must carry the normalized id: %s", out)
	}
}

func TestGroupByTypeKeepsDeterministicOrderInsideGroup(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "z-med", Key: "k", Title: "Rule", Severity: "medium"},
		{ID: "m-low", Key: "k", Title: "Rule", Severity: "low"},
		{ID: "b-high", Key: "k", Title: "Rule", Severity: "high"},
		{ID: "a-med", Key: "k", Title: "Rule", Severity: "medium"},
	})
	g := groups[0]
	want := []string{"b-high", "a-med", "z-med", "m-low"}
	for i, id := range want {
		if g.Issues[i].ID != id {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, g.Issues[i].ID, id, ids(g.Issues))
		}
	}
}

func TestGroupByTypeOrdersSameSeverityByNewestFirst(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "old", Title: "Rule", Severity: "medium", CreatedAt: "2024-05-01T00:00:00Z"},
		{ID: "zzz-new", Title: "Rule", Severity: "medium", CreatedAt: "2024-06-01T00:00:00Z"},
		{ID: "critical", Title: "Rule", Severity: "critical", CreatedAt: "2024-01-01T00:00:00Z"},
	})
	g := groups[0]
	want := []string{"critical", "zzz-new", "old"}
	for i, id := range want {
		if g.Issues[i].ID != id {
			t.Fatalf("position %d = %q, want %q (order: %v)", i, g.Issues[i].ID, id, ids(g.Issues))
		}
	}
}

func TestGroupByTypeIsDeterministicOnFullTie(t *testing.T) {
	build := func(order []string) []Issue {
		items := make([]Issue, 0, len(order))
		for _, id := range order {
			items = append(items, Issue{ID: id, Key: "k-" + id, Title: id + " rule", Severity: "low"})
		}
		return items
	}
	first := GroupByType(build([]string{"z", "a", "m"}))
	second := GroupByType(build([]string{"m", "a", "z"}))
	for i := range first {
		if first[i].Type != second[i].Type {
			t.Fatalf("group order differs at %d: %s vs %s", i, first[i].Type, second[i].Type)
		}
	}
	if first[0].Type != "a rule" || first[1].Type != "m rule" || first[2].Type != "z rule" {
		t.Fatalf("groups not sorted by name on tie: %+v", first)
	}
}

func TestGroupByTypeFallsBackToTitleAndMergesSameRule(t *testing.T) {
	groups := GroupByType([]Issue{
		{ID: "i1", Title: "SQL Injection", Severity: "high"},
		{ID: "i2", Title: "SQL Injection", Severity: "medium"},
	})
	if len(groups) != 1 {
		t.Fatalf("groups = %d, want 1 (same title merges)", len(groups))
	}
	g := groups[0]
	if g.Type != "SQL Injection" || g.ID != "sql-injection" || g.Severity != "high" || len(g.Issues) != 2 {
		t.Fatalf("group = %+v", g)
	}
}

func ids(items []Issue) []string {
	out := make([]string, len(items))
	for i, it := range items {
		out[i] = it.ID
	}
	return out
}

func FuzzNormalize(f *testing.F) {
	seeds := [][]byte{
		[]byte(ossRichFixture),
		[]byte(codeFixture),
		[]byte(`{"id":"i1","attributes":{"key":"k","title":"T","type":"license","effective_severity_level":"low","status":"resolved","ignored":true},"relationships":{}}`),
		[]byte(`{}`),
		[]byte(`null`),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var raw RawIssue
		if err := json.Unmarshal(data, &raw); err != nil {
			return
		}
		item := Normalize(raw)
		out, err := json.Marshal(item)
		if err != nil {
			t.Fatalf("normalized issue must stay JSON-marshalable: %v", err)
		}
		if len(out) == 0 {
			t.Fatal("empty marshaled issue")
		}
	})
}
