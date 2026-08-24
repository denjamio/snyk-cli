import json
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer


def issue(id, key, title, itype, sev, extra=None, org="o1", scan=("p1", "project")):
    attrs = {
        "key": key, "title": title, "type": itype,
        "effective_severity_level": sev, "status": "open", "ignored": False,
    }
    if extra:
        attrs.update(extra)
    return {
        "id": id, "attributes": attrs,
        "relationships": {
            "organization": {"data": {"id": org}},
            "scan_item": {"data": {"id": scan[0], "type": scan[1]}},
        },
    }


PAGE1 = {
    "data": [
        issue("b", "k2", "B issue", "code", "high",
              {"created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z",
               "description": "desc-b"}),
        issue("a", "k1", "A issue", "package_vulnerability", "critical"),
        issue("d", "k0", "D issue", "code", "low",
              {"created_at": "2024-02-02T00:00:00Z"}),
    ],
    "links": {"next": "/rest/orgs/o/issues?starting_after=zz"},
}

PAGE2 = {
    "data": [
        issue("c", "k3", "C issue", "cloud", "medium",
              {"description": "desc-c",
               "coordinates": [{"remedies": [{"type": "manual", "description": "Fix it"}]}]},
              scan=("e1", "environment")),
    ],
    "links": {},
}

DETAIL_C = {"data": issue("c", "k3", "C detail", "cloud", "medium")}


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        sev = None
        if "effective_severity_level" in qs:
            sev = set(qs["effective_severity_level"][0].split(","))

        def matches(items):
            if sev is None:
                return items
            return [i for i in items if i["attributes"]["effective_severity_level"] in sev]

        if parsed.path.startswith("/rest/orgs/o/issues/"):
            issue_id = parsed.path.rsplit("/", 1)[-1].split("?")[0]
            if issue_id == "c":
                body = json.dumps(DETAIL_C).encode()
                self.send_response(200)
            else:
                body = json.dumps({"errors": [{"code": "NOT_FOUND", "detail": "issue not found"}]}).encode()
                self.send_response(404)
        elif "starting_after" in parsed.query or "starting_after" in self.path:
            body = json.dumps({"data": matches(PAGE2["data"]), "links": PAGE2["links"]}).encode()
            self.send_response(200)
        else:
            body = json.dumps({"data": matches(PAGE1["data"]), "links": PAGE1["links"]}).encode()
            self.send_response(200)
        self.send_header("Content-Type", "application/vnd.api+json")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    HTTPServer(("127.0.0.1", 8899), H).serve_forever()
