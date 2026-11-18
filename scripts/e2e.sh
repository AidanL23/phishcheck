#!/usr/bin/env bash
# End-to-end test of the Day 1 slice: CLI -> API -> Redis -> worker -> report.
# It automates the manual run: build, start a throwaway Redis, start the API
# and one worker, push emails through the CLI, then check the CLI output, the
# Redis keys, and the service logs.
#
# Usage: scripts/e2e.sh          (or: make e2e)
# Needs: go, docker, jq.
#
# It never touches the dev Redis on 6379 or an API on 50051: Redis runs in
# its own container on E2E_REDIS_PORT and the API listens on E2E_API_PORT.
# If cgo is available the binaries are built with -race, so the concurrent
# submit-dir --wait path also runs under the race detector.
#
# On failure the work directory, with every log, is kept and its path printed.

set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
REDIS_PORT=${E2E_REDIS_PORT:-6390}
API_PORT=${E2E_API_PORT:-50061}
CAP=262144 # PHISHCHECK_MAX_EMAIL_BYTES for this run: 256 KiB = exactly 4 chunks
REDIS_CTR="phishcheck-e2e-$$"
WORK=$(mktemp -d "${TMPDIR:-/tmp}/phishcheck-e2e.XXXXXX")
BIN="$WORK/bin"

API_PID=""
WORKER_PID=""
PASSED=0
FAILED=0

for tool in go docker jq; do
  command -v "$tool" >/dev/null || { echo "e2e: $tool is required" >&2; exit 2; }
done

# ---- helpers -----------------------------------------------------------------

if [ -t 1 ]; then GREEN=$'\033[32m' RED=$'\033[31m' RESET=$'\033[0m'; else GREEN="" RED="" RESET=""; fi
pass() { PASSED=$((PASSED + 1)); printf '  %sok%s   %s\n' "$GREEN" "$RESET" "$1"; }
fail() { FAILED=$((FAILED + 1)); printf '  %sFAIL%s %s\n' "$RED" "$RESET" "$1"; }

# check NAME CMD...: runs CMD, passes if it exits 0.
check() {
  local name=$1; shift
  if "$@"; then pass "$name"; else fail "$name"; fi
}

section() { printf '\n%s\n' "$1"; }

rcli() { docker exec "$REDIS_CTR" redis-cli "$@"; }

# cli ARGS...: runs the CLI against the test API. Sets OUT, ERR and RC; never exits.
cli() {
  set +e
  PHISHCHECK_ADDR="127.0.0.1:$API_PORT" "$BIN/phishcheck" "$@" >"$WORK/out" 2>"$WORK/err"
  RC=$?
  set -e
  OUT=$(cat "$WORK/out")
  ERR=$(cat "$WORK/err")
  cat "$WORK/out" "$WORK/err" >>"$WORK/cli.log"
}

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1; }

# wait_for SECONDS CMD...: retries CMD every 0.1 s until it succeeds or time runs out.
wait_for() {
  local deadline=$(($(date +%s) + $1)); shift
  until "$@" 2>/dev/null; do
    [ "$(date +%s)" -lt "$deadline" ] || return 1
    sleep 0.1
  done
}

job_state() { rcli HGET "phishcheck:job:$1" state; }
state_is() { [ "$(job_state "$1")" = "$2" ]; }
job_count() { rcli --scan --pattern 'phishcheck:job:*' | wc -l | tr -d ' '; }
# pending_count: entries read by a worker but never XACKed. Should always end at 0.
pending_count() { rcli XPENDING phishcheck:jobs workers | sed -n 1p; }
log_has() { grep -q "$2" "$WORK/$1.log"; }
# rejected_with TEXT: the last cli call failed and its stderr contains TEXT.
rejected_with() { [ "$RC" -ne 0 ] && grep -q "$1" <<<"$ERR"; }
# no_raw_controls: the last cli call failed and printed no raw ESC or CR.
no_raw_controls() { [ "$RC" -ne 0 ] && [[ $OUT$ERR != *$'\e'* && $OUT$ERR != *$'\r'* ]] && grep -qF '\x1b[31mINVOICE' <<<"$ERR"; }
no_pending() { [ "$(pending_count)" = "0" ]; }
all_json() { jq -e . "$1" >/dev/null; }
# jqr FILTER: jq -e on report.json, quietly (exit status only).
jqr() { jq -e "$@" "$WORK/report.json" >/dev/null; }
is_uuid() { [[ $1 =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; }

cleanup() {
  local status=$?
  [ -n "$WORKER_PID" ] && kill "$WORKER_PID" 2>/dev/null || true
  [ -n "$API_PID" ] && kill "$API_PID" 2>/dev/null || true
  docker rm -f "$REDIS_CTR" >/dev/null 2>&1 || true
  if [ "$status" -eq 0 ] && [ "$FAILED" -eq 0 ]; then
    rm -rf "$WORK"
  else
    echo
    for f in api worker; do
      [ -f "$WORK/$f.log" ] && { echo "--- last lines of $f.log"; tail -n 15 "$WORK/$f.log"; }
    done
    echo "logs kept in $WORK"
  fi
}
trap cleanup EXIT

# ---- setup -------------------------------------------------------------------

section "setup"

RACE=""
if [ "$(go env CGO_ENABLED)" = "1" ] && command -v "$(go env CC)" >/dev/null 2>&1; then
  RACE="-race"
fi
(cd "$ROOT" && go build $RACE -o "$BIN/" ./cmd/...)
pass "built api, worker, phishcheck ${RACE:-(no -race: cgo unavailable)}"

docker run -d --rm --name "$REDIS_CTR" -p "127.0.0.1:$REDIS_PORT:6379" redis:7-alpine >/dev/null
wait_for 15 sh -c "docker exec $REDIS_CTR redis-cli PING | grep -q PONG" || { fail "redis did not start"; exit 1; }
pass "throwaway redis on 127.0.0.1:$REDIS_PORT"

export REDIS_ADDR="127.0.0.1:$REDIS_PORT"
export PHISHCHECK_GRPC_ADDR="127.0.0.1:$API_PORT"
export PHISHCHECK_MAX_EMAIL_BYTES=$CAP
export PHISHCHECK_TTL=1h

"$BIN/api" >"$WORK/api.log" 2>&1 &
API_PID=$!
wait_for 15 log_has api '"msg":"api listening"' || { fail "api did not start"; exit 1; }
pass "api listening on $PHISHCHECK_GRPC_ADDR"

"$BIN/worker" >"$WORK/worker.log" 2>&1 &
WORKER_PID=$!
wait_for 15 log_has worker '"msg":"worker ready"' || { fail "worker did not start"; exit 1; }
pass "worker ready"

# ---- happy path --------------------------------------------------------------

section "submit --wait: the clean sample"

SAMPLE="$ROOT/samples/synthetic/clean.eml"
cli submit "$SAMPLE" --wait
JOB=$(printf '%s\n' "$OUT" | head -1)
check "exit 0" [ "$RC" -eq 0 ]
check "first stdout line is the job ID (a UUID)" is_uuid "$JOB"
check "report says CLEAN, score 0" grep -q '^verdict   CLEAN (score 0)$' <<<"$OUT"
check "report names the file" grep -q '^file      clean.eml$' <<<"$OUT"
check "progress on stderr ends at DONE with a worker" grep -Eq '^DONE  worker=.+-[0-9a-f]{4}$' <<<"$ERR"

section "report --json: the stored report"

cli report "$JOB" --json
check "exit 0" [ "$RC" -eq 0 ]
echo "$OUT" >"$WORK/report.json"
WANT_SHA=$(sha256 "$SAMPLE")
check "job_id matches"            jqr --arg j "$JOB" '.job_id == $j'
check "verdict VERDICT_CLEAN"     jqr '.verdict == "VERDICT_CLEAN"'
check "score is 0, not missing"   jqr '.score == 0'
check "findings is [], not null"  jqr '.findings == []'
check "filename is the base name" jqr '.filename == "clean.eml"'
check "sha256 matches the file"   jqr --arg s "$WANT_SHA" '.sha256 == $s'
check "analyzed_at is set"        jqr '.analyzed_at != null'
WORKER_ID=$(jq -r .worker_id "$WORK/report.json")

cli report "$JOB"
check "text report works too" [ "$RC" -eq 0 ]

section "redis state after the job"

check "job hash says DONE"                   [ "$(job_state "$JOB")" = "JOB_STATE_DONE" ]
check "job hash worker_id matches report"    [ "$(rcli HGET "phishcheck:job:$JOB" worker_id)" = "$WORKER_ID" ]
check "job hash kept the filename from QUEUED" [ "$(rcli HGET "phishcheck:job:$JOB" filename)" = "clean.eml" ]
for kind in email job report; do
  ttl=$(rcli TTL "phishcheck:$kind:$JOB")
  check "$kind key has a TTL (got $ttl, want 1..3600)" [ "$ttl" -gt 0 -a "$ttl" -le 3600 ]
done
check "stream entry was acked (nothing pending)" no_pending

# ---- size cap and chunking ---------------------------------------------------

section "size cap: $CAP bytes"

head -c "$CAP" /dev/urandom >"$WORK/at-cap.eml"
cli submit "$WORK/at-cap.eml" --wait
check "exactly at the cap is accepted (4 x 64 KB chunks)" [ "$RC" -eq 0 ]
AT_CAP_JOB=$(printf '%s\n' "$OUT" | head -1)
cli report "$AT_CAP_JOB" --json
check "server hashed the same bytes we sent" [ "$(jq -r .sha256 <<<"$OUT")" = "$(sha256 "$WORK/at-cap.eml")" ]

BEFORE=$(job_count)
head -c $((CAP + 1)) /dev/urandom >"$WORK/over-cap.eml"
cli submit "$WORK/over-cap.eml"
check "one byte over is rejected with the server's message" rejected_with "exceeds $CAP byte limit"
check "a rejected upload creates no job" [ "$(job_count)" = "$BEFORE" ]

: >"$WORK/empty.eml"
cli submit "$WORK/empty.eml"
check "empty file is rejected before upload" rejected_with "is empty"

# A Subject-derived file name with an escape sequence and a CR in it. Every
# error that repeats the path must print it cleaned.
mkdir "$WORK/evil"
EVIL="$WORK/evil/"$'\e[31mINVOICE\e[0m\r.eml'
: >"$EVIL"
cli submit "$EVIL"
check "submit: path in the error is cleaned" no_raw_controls
cli submit-dir "$WORK/evil"
check "submit-dir: path in the error is cleaned" no_raw_controls

# ---- bad job IDs -------------------------------------------------------------

section "report: bad and unknown IDs"

cli report not-a-uuid
check "non-UUID is rejected" rejected_with "must be a UUID"
cli report 00000000-0000-4000-8000-000000000000
check "unknown UUID is NotFound" rejected_with "not found or expired"
cli report "$(tr 'a-f' 'A-F' <<<"$JOB")" --json
check "an uppercase copy of a real ID finds the job" [ "$RC" -eq 0 ]
check "and the report gives the canonical lowercase ID" [ "$(jq -r .job_id <<<"$OUT")" = "$JOB" ]

# ---- worker failure paths ----------------------------------------------------

section "worker failure paths"

# A job whose email never existed: the worker must mark it FAILED with a
# reason, and still ack it.
GHOST=$(cat /proc/sys/kernel/random/uuid 2>/dev/null || uuidgen | tr 'A-F' 'a-f')
rcli XADD phishcheck:jobs '*' job_id "$GHOST" >/dev/null
check "missing email -> job FAILED" wait_for 10 state_is "$GHOST" JOB_STATE_FAILED
cli report "$GHOST"
check "report shows the failure reason" rejected_with "failed: get email"

# An entry with no job_id at all: Next acks it so it can't sit pending forever.
rcli XADD phishcheck:jobs '*' not_a_job_id x >/dev/null
check "malformed entry is skipped with a WARN, not a read error" wait_for 10 log_has worker '"level":"WARN","msg":"skipped malformed stream entry"'
check "and no read-error backoff was triggered" bash -c "! grep -q '\"msg\":\"read from stream\"' '$WORK/worker.log'"
check "nothing left pending" wait_for 5 no_pending

cli submit "$SAMPLE" --wait
check "worker still processes jobs afterwards" [ "$RC" -eq 0 ]

# ---- submit-dir --wait (concurrent watchers) ----------------------------------

section "submit-dir --wait"

mkdir "$WORK/batch"
for i in 1 2 3 4 5; do cp "$SAMPLE" "$WORK/batch/sample-$i.eml"; done
: >"$WORK/batch/zz-empty.eml"
cli submit-dir "$WORK/batch" --wait
check "exit is non-zero because one file failed" [ "$RC" -ne 0 ]
check "says 1 of 6 failed" grep -q "1 of 6 files failed" <<<"$ERR"
check "5 CLEAN rows in the table" [ "$(grep -c '^sample-[1-5]\.eml  *CLEAN' <<<"$OUT")" = 5 ]
check "the empty file is an ERROR row" grep -Eq '^zz-empty\.eml +ERROR' <<<"$OUT"
check "nothing left pending" no_pending

# ---- logs --------------------------------------------------------------------

section "logs"

for svc in api worker; do
  check "every $svc log line is JSON" all_json "$WORK/$svc.log"
done
check "the redis password state is logged, not a password" log_has api '"redis_password_set":false'
check "no data races reported" bash -c "! grep -q 'DATA RACE' '$WORK/api.log' '$WORK/worker.log' '$WORK/cli.log'"

# ---- shutdown ----------------------------------------------------------------

section "graceful shutdown"

kill -TERM "$WORKER_PID"
set +e; wait "$WORKER_PID"; WRC=$?; set -e
WORKER_PID=""
check "worker exits 0 on SIGTERM (got $WRC)" [ "$WRC" -eq 0 ]
check "worker logged 'worker stopping'" log_has worker '"msg":"worker stopping"'

kill -TERM "$API_PID"
set +e; wait "$API_PID"; ARC=$?; set -e
API_PID=""
check "api exits 0 on SIGTERM (got $ARC)" [ "$ARC" -eq 0 ]
check "api logged 'api stopped cleanly'" log_has api '"msg":"api stopped cleanly"'

cli submit "$SAMPLE"
check "CLI explains an unreachable API" rejected_with "API unreachable"

# ---- result ------------------------------------------------------------------

printf '\n%d passed, %d failed\n' "$PASSED" "$FAILED"
[ "$FAILED" -eq 0 ]
