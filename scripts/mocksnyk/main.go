// Command mocksnyk is the minimal in-process Snyk REST mock the e2e
// suite (scripts/e2e.sh) runs against: two pages of issues with
// severity filtering, a detail endpoint for issue "c" and 404s for
// everything else. It serves the same fixtures the former python mock
// did, so the e2e assertions are unchanged — and the suite no longer
// needs python3. It binds an ephemeral port and prints the listen
// address on stdout, so parallel or concurrent CI runs cannot collide
// on a fixed port.
package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func issue(id, key, title, itype, sev string, extra map[string]any, org, scanID, scanType string) map[string]any {
	attrs := map[string]any{
		"key": key, "title": title, "type": itype,
		"effective_severity_level": sev, "status": "open", "ignored": false,
	}
	for k, v := range extra {
		attrs[k] = v
	}
	return map[string]any{
		"id": id, "attributes": attrs,
		"relationships": map[string]any{
			"organization": map[string]any{"data": map[string]any{"id": org}},
			"scan_item":    map[string]any{"data": map[string]any{"id": scanID, "type": scanType}},
		},
	}
}

func page1() []map[string]any {
	return []map[string]any{
		issue("b", "k2", "B issue", "code", "high", map[string]any{
			"created_at":  "2024-01-01T00:00:00Z",
			"updated_at":  "2024-01-01T00:00:00Z",
			"description": "desc-b",
		}, "o1", "p1", "project"),
		issue("a", "k1", "A issue", "package_vulnerability", "critical", nil, "o1", "p1", "project"),
		issue("d", "k0", "D issue", "code", "low", map[string]any{
			"created_at": "2024-02-02T00:00:00Z",
		}, "o1", "p1", "project"),
	}
}

func page2() []map[string]any {
	return []map[string]any{
		issue("c", "k3", "C issue", "cloud", "medium", map[string]any{
			"description": "desc-c",
			"coordinates": []map[string]any{
				{"remedies": []map[string]any{{"type": "manual", "description": "Fix it"}}},
			},
		}, "o1", "e1", "environment"),
	}
}

func detailC() map[string]any {
	return map[string]any{"data": issue("c", "k3", "C detail", "cloud", "medium", nil, "o1", "p1", "project")}
}

// matches filters issues by the effective_severity_level query value;
// a nil set means "no filter".
func matches(items []map[string]any, sev map[string]bool) []map[string]any {
	if sev == nil {
		return items
	}
	out := []map[string]any{}
	for _, it := range items {
		s := it["attributes"].(map[string]any)["effective_severity_level"].(string)
		if sev[s] {
			out = append(out, it)
		}
	}
	return out
}

func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/vnd.api+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func handler(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var sev map[string]bool
	if s := q.Get("effective_severity_level"); s != "" {
		sev = map[string]bool{}
		for _, t := range strings.Split(s, ",") {
			sev[t] = true
		}
	}
	switch {
	case strings.HasPrefix(r.URL.Path, "/rest/orgs/o/issues/"):
		id := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
		if id == "c" {
			write(w, http.StatusOK, detailC())
		} else {
			write(w, http.StatusNotFound, map[string]any{
				"errors": []map[string]any{{"code": "NOT_FOUND", "detail": "issue not found"}},
			})
		}
	case q.Has("starting_after"):
		write(w, http.StatusOK, map[string]any{"data": matches(page2(), sev), "links": map[string]any{}})
	default:
		write(w, http.StatusOK, map[string]any{
			"data":  matches(page1(), sev),
			"links": map[string]any{"next": "/rest/orgs/o/issues?starting_after=zz"},
		})
	}
}

func main() {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(ln.Addr())
	if err := http.Serve(ln, http.HandlerFunc(handler)); err != nil {
		panic(err)
	}
}
