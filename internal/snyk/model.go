package snyk

import (
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"
)

type RawIssue struct {
	ID            string     `json:"id"`
	Attributes    Attributes `json:"attributes"`
	Relationships struct {
		Organization struct {
			Data struct {
				ID string `json:"id"`
			} `json:"data"`
		} `json:"organization"`
		ScanItem struct {
			Data struct {
				ID   string `json:"id"`
				Type string `json:"type"`
			} `json:"data"`
		} `json:"scan_item"`
	} `json:"relationships"`
}

type Attributes struct {
	Key                    string       `json:"key"`
	Title                  string       `json:"title"`
	Type                   string       `json:"type"`
	EffectiveSeverityLevel string       `json:"effective_severity_level"`
	Status                 string       `json:"status"`
	Ignored                bool         `json:"ignored"`
	CreatedAt              string       `json:"created_at"`
	UpdatedAt              string       `json:"updated_at"`
	Description            string       `json:"description,omitempty"`
	Coordinates            []Coordinate `json:"coordinates,omitempty"`
	Classes                []Class      `json:"classes,omitempty"`
	Problems               []Problem    `json:"problems,omitempty"`
	Risk                   *Risk        `json:"risk,omitempty"`
}

type Class struct {
	ID     string `json:"id,omitempty"`
	Source string `json:"source,omitempty"`
}

type Coordinate struct {
	Remedies            []Remedy         `json:"remedies,omitempty"`
	IsFixableManually   *bool            `json:"is_fixable_manually,omitempty"`
	IsFixableSnyk       *bool            `json:"is_fixable_snyk,omitempty"`
	IsFixableUpstream   *bool            `json:"is_fixable_upstream,omitempty"`
	LastIntroducedAt    string           `json:"last_introduced_at,omitempty"`
	LastResolvedAt      string           `json:"last_resolved_at,omitempty"`
	LastResolvedDetails string           `json:"last_resolved_details,omitempty"`
	CodeFlowsOmitted    *bool            `json:"code_flows_omitted,omitempty"`
	CodeFlows           []CodeFlow       `json:"code_flows,omitempty"`
	Representations     []Representation `json:"representations,omitempty"`
}

type CodeFlow struct {
	ThreadFlows []ThreadFlow `json:"thread_flows"`
}

type ThreadFlow struct {
	Locations []FlowLocation `json:"locations"`
}

// FlowStep is a condensed step of a data flow: start position only, which is
// what triage and remediation need to locate the source/sink hops.
type FlowStep struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column,omitempty"`
}

type FlowLocation struct {
	File   string `json:"file"`
	Region Region `json:"region"`
}

type Region struct {
	Start Position `json:"start"`
}

type Remedy struct {
	Type        string `json:"type,omitempty"`
	Description string `json:"description,omitempty"`
}

type Representation struct {
	SourceLocation *SourceLocation `json:"sourceLocation,omitempty"`
}

type SourceLocation struct {
	CommitID string  `json:"commit_id,omitempty"`
	File     string  `json:"file"`
	Region   *Region `json:"region"`
}

type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

type Problem struct {
	ID string `json:"id"`
}

type Risk struct {
	Score *struct {
		Value float64 `json:"value"`
	} `json:"score,omitempty"`
}

// Issue is the normalized, closed issue payload the CLI emits: every key is
// always present, with ""/[] or null values where the API returns no data.
type Issue struct {
	ID          string       `json:"id"`
	Key         string       `json:"key"`
	Title       string       `json:"title"`
	IssueType   string       `json:"issue_type"`
	Severity    string       `json:"severity"`
	Status      string       `json:"status"`
	Ignored     bool         `json:"ignored"`
	OrgID       string       `json:"org_id"`
	ProjectID   string       `json:"project_id"`
	CreatedAt   string       `json:"created_at"`
	UpdatedAt   string       `json:"updated_at"`
	Description string       `json:"description"`
	Remediation *Remediation `json:"remediation"`
	RiskScore   *float64     `json:"risk_score"`
	Location    *Location    `json:"location"`
	Locations   []Location   `json:"locations"`
	CWEs        []string     `json:"cwes"`
	// Triage signals for Snyk Code items.
	IntroducedAt        string       `json:"introduced_at"`
	LastResolvedAt      string       `json:"last_resolved_at"`
	LastResolvedDetails string       `json:"last_resolved_details"`
	FixableManually     bool         `json:"fixable_manually"`
	FixableSnyk         bool         `json:"fixable_snyk"`
	FixableUpstream     bool         `json:"fixable_upstream"`
	CodeFlows           [][]FlowStep `json:"code_flows"`
	CodeFlowsOmitted    bool         `json:"code_flows_omitted"`
}

type Remediation struct {
	ManualSteps string `json:"manual_steps"`
}

// Location mirrors one source location. Like Issue, the structure is
// closed: empty values stay in the payload as "", 0, "".
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	CommitID  string `json:"commit_id"`
}

type IssueGroup struct {
	ID string `json:"id"`
	// Title is the display name (the rule title) shared by every issue in
	// the group; ID is its deterministic slug.
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Issues   []Issue `json:"issues"`
}

// ListData is the `issues list` payload: the flat issue count plus the
// grouped, ordered view. Truncated is true when the listing hit the
// MaxPages cap with more pages available — the run still succeeds; narrow
// with filters to see the rest.
type ListData struct {
	TotalIssues int          `json:"total_issues"`
	Groups      []IssueGroup `json:"groups"`
	Truncated   bool         `json:"truncated"`
}

// GroupByType clusters issues by their vulnerability type (the rule title,
// falling back to "unknown"). Group titles are unique by construction, so
// groups are ordered alphabetically by type name — a total order; issues
// inside each group by severity, then most recent created_at, with the
// stable id as final tie-break. Issues are copied into their group by
// value; the copies are shallow — strings and slices share storage — so
// the duplication cost is bounded and small.
func GroupByType(items []Issue) []IssueGroup {
	index := map[string]int{}
	groups := make([]IssueGroup, 0, len(items))
	for _, it := range items {
		name := it.Title
		if name == "" {
			name = "unknown"
		}
		if idx, ok := index[name]; ok {
			g := &groups[idx]
			g.Issues = append(g.Issues, it)
			if severityRank(it.Severity) > severityRank(g.Severity) {
				g.Severity = it.Severity
			}
			continue
		}
		index[name] = len(groups)
		groups = append(groups, IssueGroup{
			Title:    name,
			Severity: it.Severity,
			Issues:   []Issue{it},
		})
	}
	slices.SortFunc(groups, func(a, b IssueGroup) int { return strings.Compare(a.Title, b.Title) })
	for i := range groups {
		g := &groups[i]
		sortIssues(g.Issues)
		g.ID = groupSlug(g.Title)
	}
	taken := map[string]bool{}
	for i := range groups {
		base := groups[i].ID
		for n := 2; taken[base]; n++ {
			base = fmt.Sprintf("%s-%d", groups[i].ID, n)
		}
		taken[base] = true
		groups[i].ID = base
	}
	return groups
}

// issueSortKey pairs an issue with its created_at parsed once, so the
// in-group sort does not re-parse the timestamp on every comparison.
type issueSortKey struct {
	issue Issue
	t     time.Time
	ok    bool
}

// sortIssues orders issues in place: severity first (critical before
// info), then most recent created_at, with the stable id as final
// tie-break — a total order on any input.
func sortIssues(items []Issue) {
	keys := make([]issueSortKey, len(items))
	for i, it := range items {
		keys[i] = issueSortKey{issue: it}
		keys[i].t, keys[i].ok = parseTimestamp(it.CreatedAt)
	}
	slices.SortFunc(keys, func(a, b issueSortKey) int {
		if ra, rb := severityRank(a.issue.Severity), severityRank(b.issue.Severity); ra != rb {
			return rb - ra
		}
		switch {
		case a.ok && b.ok:
			switch {
			case a.t.After(b.t):
				return -1
			case a.t.Before(b.t):
				return 1
			}
		case a.ok:
			return -1
		case b.ok:
			return 1
		}
		return strings.Compare(a.issue.ID, b.issue.ID)
	})
	for i := range keys {
		items[i] = keys[i].issue
	}
}

// groupSlug turns a group title into a deterministic identifier: lowercase,
// runs of non letter/digit runes collapsed to a single dash. Titles that
// normalize to nothing fall back to "unknown"; a duplicate slug within one
// call gets a "-2", "-3", ... suffix in group order, which is deterministic.
func groupSlug(title string) string {
	var b strings.Builder
	dashed := true
	for _, r := range strings.ToLower(strings.TrimSpace(title)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(r)
			dashed = false
			continue
		}
		if !dashed {
			b.WriteByte('-')
			dashed = true
		}
	}
	if out := strings.Trim(b.String(), "-"); out != "" {
		return out
	}
	return "unknown"
}

// NormalizeAll normalizes every raw issue, preserving input order.
func NormalizeAll(raw []RawIssue) []Issue {
	items := make([]Issue, 0, len(raw))
	for _, r := range raw {
		items = append(items, Normalize(r))
	}
	return items
}

// Normalize flattens a RawIssue (Snyk JSON:API shape) into the closed Issue
// payload: locations, remediation, CWEs, triage signals and code flows are
// derived from the attributes/relationships in one pass.
func Normalize(r RawIssue) Issue {
	a := r.Attributes
	item := Issue{
		ID:          r.ID,
		Key:         a.Key,
		Title:       a.Title,
		IssueType:   a.Type,
		Severity:    a.EffectiveSeverityLevel,
		Status:      a.Status,
		Ignored:     a.Ignored,
		OrgID:       r.Relationships.Organization.Data.ID,
		CreatedAt:   a.CreatedAt,
		UpdatedAt:   a.UpdatedAt,
		Description: a.Description,
	}
	if r.Relationships.ScanItem.Data.Type == "project" {
		item.ProjectID = r.Relationships.ScanItem.Data.ID
	}
	item.Remediation = buildRemediation(a.Coordinates)
	item.RiskScore = riskValue(a.Risk)
	locations := collectLocations(a.Coordinates)
	item.Locations = locations
	if len(locations) > 0 {
		first := locations[0]
		item.Location = &first
	}
	item.CWEs = collectCWEs(a.Problems, a.Classes)
	item.IntroducedAt = latestIntroduced(a.Coordinates)
	item.LastResolvedAt, item.LastResolvedDetails = lastResolved(a.Coordinates)
	for _, c := range a.Coordinates {
		if truthy(c.IsFixableManually) {
			item.FixableManually = true
		}
		if truthy(c.IsFixableSnyk) {
			item.FixableSnyk = true
		}
		if truthy(c.IsFixableUpstream) {
			item.FixableUpstream = true
		}
		if truthy(c.CodeFlowsOmitted) {
			item.CodeFlowsOmitted = true
		}
	}
	item.CodeFlows = collectCodeFlows(a.Coordinates)
	return item
}

func truthy(b *bool) bool {
	return b != nil && *b
}

func collectCodeFlows(coords []Coordinate) [][]FlowStep {
	out := [][]FlowStep{}
	for _, c := range coords {
		for _, cf := range c.CodeFlows {
			for _, tf := range cf.ThreadFlows {
				steps := make([]FlowStep, 0, len(tf.Locations))
				for _, l := range tf.Locations {
					steps = append(steps, FlowStep{
						File:   l.File,
						Line:   l.Region.Start.Line,
						Column: l.Region.Start.Column,
					})
				}
				if len(steps) > 0 {
					out = append(out, steps)
				}
			}
		}
	}
	return out
}

// latestIntroduced returns the most recent last_introduced_at across
// coordinates: for Code items this is when the finding (re)appeared in the
// code, i.e. its effective age for triage.
func latestIntroduced(coords []Coordinate) string {
	best := ""
	var bestT time.Time
	for _, c := range coords {
		if c.LastIntroducedAt == "" {
			continue
		}
		t, ok := parseTimestamp(c.LastIntroducedAt)
		switch {
		case ok && (best == "" || t.After(bestT)):
			best, bestT = c.LastIntroducedAt, t
		case !ok && best == "":
			best = c.LastIntroducedAt
		}
	}
	return best
}

// lastResolved returns the most recent last_resolved_at across coordinates
// with its details. An open issue with a non-empty value reappeared after a
// previous resolution — a regression signal for triage.
func lastResolved(coords []Coordinate) (string, string) {
	at, details := "", ""
	var bestT time.Time
	for _, c := range coords {
		if c.LastResolvedAt == "" {
			continue
		}
		t, ok := parseTimestamp(c.LastResolvedAt)
		switch {
		case ok && (at == "" || t.After(bestT)):
			at, details, bestT = c.LastResolvedAt, c.LastResolvedDetails, t
		case !ok && at == "":
			at, details = c.LastResolvedAt, c.LastResolvedDetails
		}
	}
	return at, details
}

// buildRemediation extracts the manual remediation guidance for code items.
func buildRemediation(coords []Coordinate) *Remediation {
	for _, c := range coords {
		for _, r := range c.Remedies {
			if r.Type == "manual" && r.Description != "" {
				return &Remediation{ManualSteps: r.Description}
			}
		}
	}
	return nil
}

func riskValue(r *Risk) *float64 {
	if r == nil || r.Score == nil {
		return nil
	}
	v := r.Score.Value
	return &v
}

func collectLocations(coords []Coordinate) []Location {
	type locationKey struct {
		file string
		line int
	}
	out := []Location{}
	seen := map[locationKey]bool{}
	for _, c := range coords {
		for _, rep := range c.Representations {
			sl := rep.SourceLocation
			if sl == nil || sl.File == "" {
				continue
			}
			loc := Location{File: sl.File, CommitID: sl.CommitID}
			if sl.Region != nil {
				loc.StartLine = sl.Region.Start.Line
			}
			key := locationKey{file: loc.File, line: loc.StartLine}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, loc)
		}
	}
	return out
}

// collectCWEs gathers CWE identifiers from problems and classes (Snyk Code
// items put their weakness class there).
func collectCWEs(problems []Problem, classes []Class) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.ToUpper(strings.TrimSpace(id))
		if !strings.HasPrefix(id, "CWE-") || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, p := range problems {
		add(p.ID)
	}
	for _, c := range classes {
		if strings.EqualFold(c.Source, "CWE") {
			add(c.ID)
		}
	}
	slices.Sort(out)
	return out
}

func parseTimestamp(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// severityRank maps a severity name to its rank (higher = worse). Unknown
// values rank as info.
func severityRank(severity string) int {
	switch severity {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
