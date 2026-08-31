# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Changed

- Usage errors (exit 2) also emit a structured `{"ok":false}` envelope on
  stdout when piped or when `--json`/`--quiet` was requested — the same
  contract as runtime errors — so agents and scripts parse every failure
  uniformly; the plain message and usage text remain on stderr.
- `help` is part of the machine-readable catalog, so `help --json` is
  self-describing; the human usage text and `help --json` are both
  generated from one declarative command spec, together with the flag
  bindings.
- Cancellation: `SIGINT`/`SIGTERM` cancel in-flight API calls; retry waits
  abort immediately instead of sleeping through them.
- API responses larger than 10 MB are rejected with a clear error instead
  of being silently truncated (which surfaced as a JSON decode error).
- `help` and `issues list` reject unexpected positional arguments
  (usage error, exit 2).
- The API base URL (`SNYK_API_URL`) is resolved in the CLI layer and
  injected into the client; the client package no longer reads the
  environment.
- The human usage text is generated from the command catalog that also
  backs `help --json`, so the two help surfaces cannot drift apart.

### Added

- Progress reporting for humans: fetched pages and retry waits are logged
  to stderr — only when it is a terminal. Piped and `--json` runs (agents,
  scripts) stay silent, keeping their stdout payload the whole story.
- `SNYK_HTTP_TIMEOUT` env var: optional per-request HTTP timeout as a Go
  duration (e.g. `90s`, default `60s`), so pipelines can bound the worst
  case; invalid values are usage errors (exit 2) before any call is made.
- Fuzz tests for the flag pre-parser and the group slug generator.

### Fixed

- API error snippets never end in a malformed UTF-8 sequence after the
  300-byte cut.
- TTY detection probes the terminal (ioctl/console query) instead of the
  `ModeCharDevice` heuristic, so character devices like `/dev/null` are no
  longer mistaken for a terminal — `snyk issues list > /dev/null` stays on
  the structured path.
- `snyk skill install` writes `SKILL.md` atomically (temp file + rename);
  an interrupted install can no longer leave a truncated file behind.

## [0.1.0] - 2026-08-29

### Added

- `snyk` CLI (repo `snyk-cli`): read-only retrieval of existing Snyk issues
  via the REST Issues API (version pinned to `2026-03-25`), organized as
  `snyk <resource> <action>` so future API surfaces plug in as new
  resources.
- `issues list`: lists a project's issues grouped by vulnerability type.
  Always project-scoped (`scan_item.id` + `scan_item.type=project`) and
  code-only (`type=code`, no `--type` flag); filters `--severity`,
  `--status`, `--created-after` (RFC3339, validated client-side),
  `--include-ignored` and `--include-code-flows`. Groups are ordered
  alphabetically by type name; issues inside each group by severity, then
  most recent `created_at`, with the stable `id` as final tie-break —
  identical API state produces byte-stable output. Each group carries a
  deterministic slug `id` of its type name.
- `issues get ISSUE_ID`: full detail of a single issue, including
  remediation (`manual_steps`), code flows (source→sink as
  `file/line/column`) and triage signals: `introduced_at`,
  `last_resolved_at`/`last_resolved_details` (regression marker),
  `fixable_manually`/`fixable_snyk`/`fixable_upstream`, `cwes` and
  `commit_id` per location.
- Closed issue payload: every key is always present, with `""`/`[]` or
  `null` values where the API returns no data; only fields the Snyk Code
  payload provides (no `package`, `license`, `cvss` or `references`).
- Three output modes: human table on TTY, JSON envelope when piped or with
  `--json`, raw data with `--quiet` (bare groups array for `issues list`,
  single object for `issues get`). The envelope `command` field carries
  the full command path (`issues list`, `issues get`). Errors are
  structured too; exit codes: `0` success · `1` runtime/API error ·
  `2` usage error.
- Client-side flag validation: unknown values for `--severity`,
  `--status` and `--created-after` exit 2 without calling the API; lists
  are normalized (trimmed, lowercased, deduplicated, order kept).
- Configuration via environment variables with flag-over-env precedence:
  `SNYK_TOKEN` (required), `SNYK_ORG_ID` (default for `--org`),
  `SNYK_PROJECT_ID` (default for `--project`), `SNYK_API_URL` (default
  `https://api.eu.snyk.io`); an empty env var counts as unset.
- Hands-off reliability: cursor pagination, `429` honoring `Retry-After`,
  linear backoff on `502/503/504`, pagination guard and bounded HTTP
  timeout.
- Machine-readable help: `snyk help --json` emits the command catalog.
- Embedded agent skill (`skills/snyk/SKILL.md`, open skills format) shipped
  inside the binary: `snyk skill install` (project), `--global`
  (`~/.agents/skills`), `--dir PATH` or `--print`; always version-matched,
  reinstall over an identical file is an idempotent no-op.
- Installers for Linux/macOS (`scripts/install.sh`) and Windows
  (`scripts/install.ps1`): platform detection, latest-release download,
  SHA-256 checksum verification, install to `~/.local/bin` /
  `%LOCALAPPDATA%\Programs\snyk` (overridable via `SNYK_CLI_INSTALL_DIR`,
  pinnable via `SNYK_CLI_VERSION`).
- Tests: unit coverage across cli/output/snyk packages plus fuzz targets
  over the argument splitter; end-to-end suite against a local mock Snyk
  API (`scripts/e2e.sh`).
- CI: gofmt gate, `go vet`, golangci-lint, race/coverage tests with
  Codecov, e2e job and five-platform build matrix; tag-driven releases via
  GoReleaser with SHA-256 checksums.
