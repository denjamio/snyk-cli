# snyk-cli

[![CI](https://github.com/denjamio/snyk-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/denjamio/snyk-cli/actions/workflows/ci.yml)
[![golangci-lint](https://img.shields.io/badge/golangci--lint-v2.13.1-00ADD8?logo=go&logoColor=white)](https://golangci-lint.run)
[![Go Reference](https://pkg.go.dev/badge/github.com/denjamio/snyk-cli.svg)](https://pkg.go.dev/github.com/denjamio/snyk-cli)
[![codecov](https://codecov.io/gh/denjamio/snyk-cli/graph/badge.svg)](https://codecov.io/gh/denjamio/snyk-cli)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Read-only CLI (binary: `snyk`) to retrieve **existing** Snyk issues — what you
already see in the Snyk web UI — with deterministic, structured JSON output.
Built for humans in terminals and for AI agents in pipelines.

## Why

The Snyk web UI shows your issues; Snyk's official CLI focuses on scanning for
new ones. Neither hands you a clean, scriptable export of what you already
have — that is the gap this fills:

- **Automation-grade**: one command, three output modes (table · JSON
  envelope · bare data), meaningful exit codes. The same invocation serves a
  terminal or a pipeline — no special-casing.
- **Predictable**: issues are grouped by vulnerability type (the rule behind
  them); groups are ordered alphabetically by name and issues inside each
  group by severity, then most recent `created_at`, with the stable `id` as
  final tie-break — a total order. Diff two runs, schedule an export, store
  once — no noise to filter.
- **Hands-off reliability**: pagination, transient-failure retries (HTTP
  429/5xx and network-level errors, with jittered exponential backoff)
  and rate-limit waits are handled inside the binary, not in your script.
  Retry waits share a per-request cumulative budget (2 minutes by
  default), so a hostile `Retry-After` fails fast instead of stalling
  the run. Progress (pages fetched, retry
  waits) is reported on stderr only when it is a terminal — piped
  and `--json` runs stay silent, so their output is the whole story
  (the one exception: the truncation warning, below).
- **No baggage**: a single static Go binary, standard library only,
  checksummed installers for linux/darwin/windows.

## Install

Linux / macOS:

```bash
curl -fsSL https://raw.githubusercontent.com/denjamio/snyk-cli/main/scripts/install.sh | bash
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/denjamio/snyk-cli/main/scripts/install.ps1 | iex
```

Both detect platform/arch, verify the SHA-256 checksum and install to
`~/.local/bin` (Linux/macOS) or `%LOCALAPPDATA%\Programs\snyk`
(Windows, added to your user PATH).

Pin a version or relocate with `SNYK_CLI_VERSION=vX.Y.Z` and
`SNYK_CLI_INSTALL_DIR`. Verify the install with:

```bash
snyk version
```

### From source

```bash
bash scripts/build.sh              # Docker, no toolchain needed
go build -trimpath -o bin/snyk ./cmd/snyk   # Go 1.25+
```

## Quick start

```bash
export SNYK_TOKEN=<your token>
export SNYK_ORG_ID=<org id>          # optional: default for --org
export SNYK_PROJECT_ID=<project id>  # optional: default for --project

snyk issues list --org <ORG_ID> --project <PROJECT_ID>                      # table in terminal
snyk issues list --org <ORG_ID> --project <PROJECT_ID> --json > issues.json # JSON envelope
snyk issues get <ISSUE_ID> --org <ORG_ID> --json                            # full detail
```

`--org` and `--project` fall back to `SNYK_ORG_ID` / `SNYK_PROJECT_ID` when
the flag is omitted; an explicit flag always wins (see
[Configuration](#configuration)).

Server-side defaults: `issues list` queries the required project
(`scan_item.id` +
`scan_item.type=project`) and returns only open, non-ignored **Snyk Code**
issues (`type=code` — the tool is code-only and the filter is not
configurable), across **all severities**, grouped by vulnerability type in
the output.

## Commands

Resources and actions (`snyk <resource> <action>`; new API surfaces plug in
as new resources):

| Command | Description |
|---|---|
| `issues list` | List issues of a project |
| `issues get ISSUE_ID` | Get a single issue with full detail |
| `skill [--global] [--dir DIR] [--print]` | Install or print the embedded agent skill (see [Agent integration](#agent-integration)) |
| `help [--json]` | Usage text or machine-readable command catalog |
| `version [--json]` | Print version (plain text or JSON envelope) |

`issues list` filters:

| Flag | Effect |
|---|---|
| `--org ID` | Snyk organization ID (**required**, or set `SNYK_ORG_ID`) |
| `--project ID` | Project ID (**required**, or set `SNYK_PROJECT_ID`) — scopes the query to that project (`scan_item.id`) |
| `--severity LIST` | `info,low,medium,high,critical` — default: all severities |
| `--status LIST` | `open,resolved` — default: `open` |
| `--created-after TS` | RFC3339 date-time (e.g. `2026-08-01T00:00:00Z`) — only issues created after |
| `--include-ignored` | Include ignored issues |
| `--include-code-flows` | Include data flows (source→sink) for code issues — heavier payload; `issues get` always includes them |

`issues get` takes `--org` (same env fallback) plus the `ISSUE_ID`
positional.
Missing `--org`/`--project` exit 2 (usage error) without calling the API.
Flag values are validated client-side: invalid values also exit 2, listing
the allowed set.

Output modes: auto (TTY → table · piped → envelope), `--json` (envelope
always), `--quiet` (bare array for `issues list`, single object for
`issues get`), and `--compact` (JSON without indentation — envelope or
bare data — for large exports piped into other tools; it never affects
the human table). Errors are structured too: piped runs, and `--json`/
`--quiet` runs even on a terminal, get
`{"ok":false,"command":...,"error":{"kind":...,"message":...}}` on
stdout — for runtime errors and usage errors alike (usage errors also
print the usage text on stderr); a plain terminal run gets the plain
message on stderr. Exit
codes: `0` success · `1` runtime/API
error · `2` usage error.

`error.kind` classifies every failure, so scripts and agents branch on
it instead of matching message strings:

| Kind | Meaning |
|---|---|
| `usage` | invalid invocation (exit 2): unknown flag or value, missing org/project |
| `config` | environment misconfiguration (e.g. `SNYK_TOKEN` not set) |
| `auth` | HTTP 401/403 — token revoked or unauthorized (the message hints at the region: the default base URL serves the EU) |
| `not_found` | HTTP 404 — unknown org, project or issue id |
| `rate_limit` | HTTP 429 past the internal retry budget or wait cap |
| `transient` | HTTP 502/503/504 past the internal retry budget or wait cap |
| `network` | transport failure past the retries or the wait cap (refused/reset connection, timeout) |
| `canceled` | the run was interrupted (SIGINT/SIGTERM) or its deadline passed |
| `api` | any other non-200 HTTP status |
| `decode` | a 200 response whose body is not the expected JSON |
| `internal` | unexpected local failure |

## Output contract

```json
{
  "ok": true,
  "command": "issues list",
  "summary": "2 issues · status=open · ignored=false · type=code",
  "data": {
    "total_issues": 2,
    "groups": [
      {
        "id": "sql-injection",
        "title": "SQL Injection",
        "severity": "high",
        "issues": [
          {
            "id": "d5b640e5-d88c-4c17-9bf0-93597b7a1ce2",
            "key": "js/sql-injection",
            "title": "SQL Injection",
            "issue_type": "code",
            "severity": "high",
            "status": "open",
            "ignored": false,
            "org_id": "...",
            "project_id": "...",
            "created_at": "2022-09-27T20:09:05Z",
            "updated_at": "2022-09-28T20:09:05Z",
            "description": "...",
            "remediation": { "manual_steps": "..." },
            "risk_score": 640,
            "location": { "file": "src/hash.js", "start_line": 12, "commit_id": "a2c24..." },
            "locations": [
              { "file": "src/hash.js", "start_line": 12, "commit_id": "a2c24..." },
              { "file": "src/util.js", "start_line": 3 }
            ],
            "cwes": ["CWE-89"],
            "introduced_at": "2026-08-21T14:14:46.015Z",
            "last_resolved_at": "2026-03-25T10:38:26.184Z",
            "last_resolved_details": "DISAPPEARED",
            "fixable_manually": true,
            "fixable_snyk": false,
            "fixable_upstream": false,
            "code_flows": [
              [
                { "file": "app/input.rb", "line": 4, "column": 8 },
                { "file": "app/exec.rb", "line": 21, "column": 18 }
              ]
            ],
            "code_flows_omitted": false
          }
        ]
      },
      {
        "id": "hoek-prototype-pollution",
        "title": "Hoek - Prototype Pollution",
        "severity": "medium",
        "issues": ["..."]
      }
    ],
    "truncated": false
  }
}
```

Guarantees:

- REST API version pinned to `2026-03-25`.
- The query is always `type=code` and scoped to a single project
  (`scan_item.id` + `scan_item.type=project`) — the CLI is code-only and
  project-scoped by design; there is no `--type` flag and no cross-project
  listing, and the payload carries only fields the Snyk Code payload
  provides (no `package`, `license`, `cvss` or `references`).
- Groups are clusters of the same vulnerability type (the rule title),
  ordered alphabetically by name. Issues inside a group are ordered by
  severity, then most recent `created_at`, with the unique `id` as final
  tie-break — a total order, so identical API state produces byte-stable
  output, safe for diffing.
- Each group's `id` is a deterministic slug of its type name (lowercase,
  non-alphanumerics collapsed to dashes) — the natural key for matching
  tickets or state per group; the group also carries its `title` (the
  rule name shared by every issue in it), so `--quiet` consumers need not
  recover the display name from the issues.
- Issue payload mirrors the Snyk API: every issue field is derived from the
  real payload; triage signals include `cwes` (from `classes`),
  `introduced_at` (last introduction), `last_resolved_at` /
  `last_resolved_details` (an open issue with these set reappeared after a
  previous resolution — a regression), `fixable_*` (fix capability),
  `commit_id` per location, and `code_flows` (source→sink steps; only with
  `--include-code-flows` on `issues list`, always on `issues get`;
  `code_flows_omitted`
  flags truncated flows).
- The issue structure is closed: every issue carries the same set of keys,
  with `""`/`[]` or `null` values when the API does not return them
  (nested `location` entries and the group payload are closed the same
  way); the singular `location` mirrors the first entry of `locations`.
  Use
  `issues get` when
  full detail is required.
- Listings are capped at 100 pages (10,000 issues at the default page
  size). When the cap trips with more pages available the run still
  succeeds: the payload carries `"truncated": true`, the summary line
  appends `truncated=true`, and a warning is printed to stderr — even on
  piped runs, the only stderr output they ever get. Narrow with
  `--severity`/`--created-after` to fetch the rest.
- `--quiet` prints the bare `groups` array; `issues get` prints the single
  issue
  object.

## Configuration

| Variable | Purpose |
|---|---|
| `SNYK_TOKEN` | Required API token |
| `SNYK_ORG_ID` | Default for `--org` on `issues list` and `issues get` (flag wins) |
| `SNYK_PROJECT_ID` | Default for `--project` on `issues list` (flag wins) |
| `SNYK_API_URL` | Optional base URL (default `https://api.eu.snyk.io`) |
| `SNYK_HTTP_TIMEOUT` | Optional per-request HTTP timeout, Go duration like `90s` (default `60s`) |
| `SNYK_TIMEOUT` | Optional whole-run deadline, Go duration like `2m` (default none); on expiry the run fails with `error.kind` `canceled` |

Precedence is flag > env var: an explicit `--org`/`--project` overrides the
matching env var; an env var set to the empty string counts as unset.

## Agent integration

Ships `skills/snyk/SKILL.md` (open skills format): scope rules
(read-only retrieval only), flag semantics, output contract and failure
handling — so any AI assistant that can run shell commands uses the CLI
correctly.

The skill is embedded in the binary, so the simplest install is the
binary itself — always version-matched, no network needed:

```bash
snyk skill install --global  # ~/.agents/skills (all projects)
snyk skill install           # ./.agents/skills (current project)
snyk skill --print           # emit the embedded SKILL.md
```

Alternatively, download the skill straight from `main` — global
(auto-discovered by compatible tools in every project):

```bash
mkdir -p ~/.agents/skills/snyk && curl -fsSL \
  https://raw.githubusercontent.com/denjamio/snyk-cli/main/skills/snyk/SKILL.md \
  -o ~/.agents/skills/snyk/SKILL.md
```

Or at project level, into the repository where the CLI will be used:

```bash
mkdir -p .agents/skills/snyk && curl -fsSL \
  https://raw.githubusercontent.com/denjamio/snyk-cli/main/skills/snyk/SKILL.md \
  -o .agents/skills/snyk/SKILL.md
```

Using the [`skills`](https://github.com/vercel-labs/skills) CLI, which installs
into every detected agent:

```bash
npx skills add denjamio/snyk-cli --skill snyk     # project level (cwd)
npx skills add denjamio/snyk-cli --skill snyk -g  # global
```

Ground rules baked into the skill: always pass `--json`; take `<ORG_ID>` and
`<PROJECT_ID>` from context or ask — never guess; credentials come
exclusively from `SNYK_TOKEN` and are never stored or logged.

## Development

All quality gates run through Docker (and in CI):

```bash
bash scripts/test.sh   # gofmt gate + go vet + go test -race ./...
bash scripts/build.sh  # cross-toolchain build -> bin/snyk
bash scripts/e2e.sh    # end-to-end against a local mock Snyk API
```

```
cmd/snyk/              entrypoint (thin)
internal/cli/          command layer: flags, modes, envelopes (tested)
internal/output/       output modes, table rendering, TTY detection (tested)
internal/snyk/         REST client, pagination, retries, normalization (tested)
scripts/               installers, build / test / e2e + mock server
skills/                agent skill definition
.github/workflows/     CI (lint, race+coverage, e2e, build matrix) · Release
```

Pushing a tag `vX.Y.Z` triggers GoReleaser: linux/darwin/windows on
amd64/arm64 (six platforms), SHA-256 checksums, draft GitHub release.

## Changelog

Notable changes are documented in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE)
