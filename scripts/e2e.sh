#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=./bin/snyk
if [ ! -x "$BIN" ]; then
  echo "binary not found; run: go build -o bin/snyk ./cmd/snyk" >&2
  exit 1
fi

python3 scripts/mock_snyk.py &
MOCK=$!
trap 'kill "$MOCK" 2>/dev/null || true' EXIT

export SNYK_TOKEN=fake
export SNYK_API_URL=http://127.0.0.1:8899
export SNYK_ORG_ID=o
export SNYK_PROJECT_ID=p1

out=""
for _ in $(seq 1 30); do
  if out=$("$BIN" issues list --org o --project p1 --json 2>/dev/null); then
    break
  fi
  sleep 0.2
done

fail() { echo "E2E FAIL: $1" >&2; exit 1; }

echo "$out" | grep -q '"ok": true' || fail "envelope not ok"
echo "$out" | grep -q '"total_issues": 4' || fail "expected 4 issues by default (all severities)"
echo "$out" | grep -q '"id": "d"' || fail "low issue missing from default output"
! echo "$out" | grep -q 'severity=' || fail "summary should not show severity when unfiltered"
echo "$out" | grep -q 'type=code' || fail "summary must always show type=code"
echo "$out" | grep -q '"title": "A issue"' || fail "group payload must carry the rule title"
echo "$out" | grep -q '"truncated": false' || fail "list payload must always carry the truncated flag"
echo "$out" | grep -q '"id": "a-issue"' || fail "group id missing"

ia=$(printf '%s' "$out" | grep -bo '"id": "a"' | head -1 | cut -d: -f1)
ib=$(printf '%s' "$out" | grep -bo '"id": "b"' | head -1 | cut -d: -f1)
ic=$(printf '%s' "$out" | grep -bo '"id": "c"' | head -1 | cut -d: -f1)
id=$(printf '%s' "$out" | grep -bo '"id": "d"' | head -1 | cut -d: -f1)
[ -n "$ia" ] && [ -n "$ib" ] && [ -n "$ic" ] && [ -n "$id" ] || fail "missing items"
[ "$ia" -lt "$ib" ] && [ "$ib" -lt "$ic" ] && [ "$ic" -lt "$id" ] || fail "groups not ordered by name"

sevout=$("$BIN" issues list --org o --project p1 --quiet --severity high,critical)
echo "$sevout" | grep -q '"id": "a"' || fail "--severity filter dropped critical"
! echo "$sevout" | grep -q '"id": "d"' || fail "--severity filter leaked low issue"
sva=$(printf '%s' "$sevout" | grep -bo '"id": "a-issue"' | head -1 | cut -d: -f1)
svb=$(printf '%s' "$sevout" | grep -bo '"id": "b-issue"' | head -1 | cut -d: -f1)
[ -n "$sva" ] && [ -n "$svb" ] || fail "missing groups in quiet output"
[ "$sva" -lt "$svb" ] || fail "quiet output not ordered by severity"

envout=$("$BIN" issues list --json)
echo "$envout" | grep -q '"ok": true' || fail "env-var-only invocation (SNYK_ORG_ID/SNYK_PROJECT_ID) failed"
flagout=$("$BIN" issues list --org o --project p2 --quiet)
[ "${flagout:0:1}" = "[" ] || fail "flags must win over env vars"

"$BIN" issues list --org o --project p1 --quiet --created-after 2026-01-01T00:00:00Z >/dev/null || fail "valid created-after rejected"
set +e
"$BIN" issues list --org o --project p1 --quiet --created-after not-a-date >/dev/null 2>&1
badrc=$?
"$BIN" issues list --org o --project p1 --quiet --type code >/dev/null 2>&1
typerc=$?
env -u SNYK_PROJECT_ID "$BIN" issues list --org o --quiet >/dev/null 2>&1
noprojrc=$?
env -u SNYK_ORG_ID "$BIN" issues list --quiet >/dev/null 2>&1
noorgrc=$?
SNYK_PROJECT_ID= "$BIN" issues list --org o --quiet >/dev/null 2>&1
emptyprojrc=$?
set -e
[ "$badrc" -eq 2 ] || fail "invalid created-after must exit 2, got $badrc"
[ "$typerc" -eq 2 ] || fail "--type must be rejected (code-only tool), got $typerc"
[ "$noprojrc" -eq 2 ] || fail "missing --project/SNYK_PROJECT_ID must exit 2, got $noprojrc"
[ "$noorgrc" -eq 2 ] || fail "missing --org/SNYK_ORG_ID must exit 2, got $noorgrc"
[ "$emptyprojrc" -eq 2 ] || fail "empty SNYK_PROJECT_ID must not satisfy --project requirement, got $emptyprojrc"

detail=$("$BIN" issues get c --org o --json)
echo "$detail" | grep -q '"command": "issues get"' || fail "get envelope wrong"

qout=$("$BIN" issues list --org o --project p1 --quiet)
echo "$qout" | grep -q '"id": "c-issue"' || fail "quiet mode wrong"
[ "${qout:0:1}" = "[" ] || fail "quiet output is not a bare array"

set +e
err=$("$BIN" issues get nope --org o --json 2>/dev/null)
rc=$?
set -e
[ "$rc" -eq 1 ] || fail "expected rc=1 for missing issue, got $rc"
echo "$err" | grep -q '"ok": false' || fail "error envelope wrong"

skillout=$("$BIN" skill --print)
echo "$skillout" | grep -q '^name: snyk' || fail "embedded skill frontmatter missing"
skilldir=$(mktemp -d)
"$BIN" skill install --dir "$skilldir" --json | grep -q '"command": "skill"' || fail "skill install envelope wrong"
[ -f "$skilldir/.agents/skills/snyk/SKILL.md" ] || fail "skill not installed to --dir"
skillrc=$("$BIN" skill install --dir "$skilldir" --json | grep -c 'already up to date')
[ "$skillrc" -eq 1 ] || fail "skill reinstall is not an idempotent no-op"
rm -rf "$skilldir"

echo "E2E OK"
