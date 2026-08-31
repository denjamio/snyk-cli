---
name: snyk
description: >
  Retrieve EXISTING Snyk issues or findings via the snyk CLI (`snyk issues`,
  repo snyk-cli): list the issues of a project, get full issue detail, or
  export deterministic structured JSON. Use when the user mentions snyk
  issues, snyk report, snyk vulnerabilities, or asks to fetch/extract snyk
  findings for tickets, triage or persistence. Do NOT use for running new
  scans (snyk test / snyk monitor), Snyk account configuration, or any
  other security tooling.
---

# snyk

Read-only CLI over the Snyk REST Issues API: it retrieves the issues you
already see in the Snyk web UI as deterministic, structured JSON. It never
scans, mutates or configures anything. Run it as `snyk` from PATH;
if the command is not found, ask the user to install it — do not build or
fetch binaries yourself.

## Workflow

1. Resolve the scope: take `<ORG_ID>` and `<PROJECT_ID>` from context or
   ask the user — never guess. Exporting `SNYK_ORG_ID` and
   `SNYK_PROJECT_ID` once is enough; explicit flags override them.
2. List the issues of the project:

   ```bash
   snyk issues list --org <ORG_ID> --project <PROJECT_ID> --json
   ```

3. Get full detail (remediation, code flows) for one finding:

   ```bash
   snyk issues get <ISSUE_ID> --org <ORG_ID> --json
   ```

## Rules

- Always pass `--json`; never rely on terminal auto-formatting.
- `snyk issues list` requires `--org` and `--project`; `snyk issues get`
  requires `--org`. When a
  flag is omitted it falls back to the `SNYK_ORG_ID` / `SNYK_PROJECT_ID`
  environment variables; an explicit flag wins. Missing values exit 2
  (usage error) without calling the API.
- The tool is code-only and project-scoped: the query is always `type=code`
  of a single project (`scan_item.id` + `scan_item.type=project`; there is
  no `--type` flag and no cross-project listing). Defaults apply
  server-side: only `status=open`, non-ignored issues, across **all
  severities**.
- Request resolved/ignored items explicitly when needed: `--status
  open,resolved`, `--include-ignored`. Narrow severities with `--severity
  <list>` (e.g. `--severity high,critical`); filter by creation date with
  `--created-after <RFC3339>` (e.g. `2026-08-01T00:00:00Z`); add data-flow
  evidence with `--include-code-flows` (heavier payload).
- Credentials come exclusively from the `SNYK_TOKEN` environment variable:
  never echo, store or persist it anywhere.
- `SNYK_TIMEOUT` optionally bounds the whole run with a Go duration (e.g.
  `2m`): on expiry the run fails with `error.kind` `canceled`. Set it when
  an invocation must not hang.
- Pagination, retries (429/5xx and network-level errors) and API-version
  pinning are handled inside the binary. Do not paginate manually or
  re-run in a retry loop; an exit 1 means retries were exhausted or the
  request was invalid.
- A listing is capped at 10,000 issues (100 pages). If the cap trips the
  run still exits 0, with `"truncated": true` in `data` and a warning on
  stderr; narrow with `--severity`/`--created-after` and re-run for the
  rest instead of assuming the result is complete.
- Progress lines (pages fetched, retries) may appear on stderr in
  interactive terminals; piped `--json` runs are silent — the only
  stderr output they ever get is the truncation warning. Parse stdout
  only.
- Use `--quiet` only when the bare groups array is needed for scripting.
  Add `--compact` for unindented, single-line JSON when piping large
  exports into other tools.

## Output envelope

```json
{"ok": true, "command": "issues list", "summary": "...", "data": {"total_issues": N, "groups": [...]}}
```

Each group represents one vulnerability type and carries `id` (a
deterministic slug of the type name — the natural key for matching
tickets), `title` (the rule name shared by every issue in the group),
`severity` (worst in the group) and `issues`. Issue fields: `id` (stable
identity), `key`, `title`,
`issue_type`, `severity`, `status`, `ignored`, `org_id`, `project_id`,
timestamps, `description`, `remediation` (`manual_steps`), `risk_score`,
`location`, `locations`, `cwes`, plus code-triage signals: `introduced_at`
(last introduction — age of the finding),
`last_resolved_at`/`last_resolved_details` (set on an open issue = it
reappeared after a previous resolution, a regression),
`fixable_manually`/`fixable_snyk`/`fixable_upstream`, `commit_id` per
location, `code_flows` (source→sink steps `file/line/column`, only with
`--include-code-flows` on `list`; `get` always includes them) and
`code_flows_omitted`. The structure is closed: every key is always present,
with empty or null values when the API does not return them; use `get` for
guaranteed detail.

Groups are ordered alphabetically by type name; issues inside a group by
severity (critical first), then most recent `created_at`, with the unique
`id` as final tie-break: identical state produces byte-stable output, safe
for diffing and downstream persistence keyed by `id`.

## Examples

Worst-severity groups, ready for triage:

```bash
snyk issues list --org "$SNYK_ORG_ID" --project "$SNYK_PROJECT_ID" \
  --severity high,critical --json | jq -r '.data.groups[] | "\(.severity) \(.id)"'
```

Re-audit run including resolved and ignored issues:

```bash
snyk issues list --org "$SNYK_ORG_ID" --project "$SNYK_PROJECT_ID" \
  --status open,resolved --include-ignored --json > snyk-audit.json
```

## Failure handling

Exit codes decide the next action:

- `0` → success: parse `data`.
- `1` → runtime/API error: read the envelope `error` and surface it to
  the user. Transient HTTP 429/5xx were already retried internally; do
  not retry blindly. `error.kind` classifies the failure (`config`,
  `auth`, `not_found`, `rate_limit`, `transient`, `network`, `canceled`,
  `api`, `decode`, `internal`) — branch on it instead of matching the
  message.
- `2` → usage error (`error.kind` is `usage`): read the envelope `error`
  on stdout (the usage text goes to stderr), fix the invocation (unknown
  flag value, missing org/project) and retry.

Common issues:

- kind `config`, message `SNYK_TOKEN not set` → ask the user to export
  `SNYK_TOKEN` before retrying.
- kind `auth` → the token was rejected: check `SNYK_TOKEN`, and if the org
  lives outside the EU region set `SNYK_API_URL` to its regional endpoint
  (the error message carries the same hint; the default base URL serves
  the EU).
- `--org is required (or set SNYK_ORG_ID)` / `--project is required (or
  set SNYK_PROJECT_ID)` → resolve the ID from context or ask the user;
  retry with the flag or the env var.
- `command not found` → the CLI is not installed; ask the user to install
  it (one-line installers in the repository README). Verify an existing
  install with `snyk version --json` (envelope, `data.version`).
- kind `not_found` on `issues get` → the `ISSUE_ID` is wrong or does not
  belong to this org; re-check the id instead of retrying.
