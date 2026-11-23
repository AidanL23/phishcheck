# Testing

Three layers. Run the first two before every commit; the third is the review at the end of each day.

| Layer | Command | Needs | Time |
|---|---|---|---|
| Unit tests (pure logic: no Redis, no network) | `make test` | Go | ~1 s |
| End-to-end slice with a real Redis | `make e2e` | Go, Docker, jq | ~12 s |
| Code review against the fixed checklist | [review/CHECKLIST.md](review/CHECKLIST.md) | you | — |

Optional: `make fuzz` runs `FuzzClean` for 30 s. `go test` alone already runs its seed corpus.

## 1. Unit tests

Every test runs without Redis or a socket. Where the code takes a gRPC client or stream, the test passes an in-memory fake. Where a function would reach Redis, the test passes a **nil** store or client: if the code under test touches it, the nil pointer panics and the test fails. That is how the tests prove "rejected before Redis".

| Package | What is covered |
|---|---|
| `cmd/phishcheck` | `clean()`: a table of cases, a check of **every Unicode code point**, and a fuzz target. Also `enumName`, `parseInterspersed`, `rpcErr` (including `errors.Is(errUnreachable)`), `emlFiles` (sorting, `.EML`, skips dirs and symlinks, glob characters in the dir name), `batchErr`, `printReport` (severity order, stable sort, caller's slice untouched, filename and evidence cleaned and truncated, nil timestamp, score-mismatch warning), `printJSON` (proto names, zero values present, exact bytes kept, no raw ESC), `printDirTable`, `runSubmitDir` cleaning the path inside error text. `submitFile` runs against a fake stream: sizes around the 64 KB boundary, filename on the first message only, buffers not reused after `Send`, empty file or directory never opens a stream, server abort mid-upload, integrity mismatch, stream context cancelled on an early return. `waitForReport`: DONE, FAILED (error cleaned), stream closed early, DONE with no report |
| `cmd/worker` | `nextStep` (a job already read is handled even once shutdown has started), `newWorkerID` format and randomness, `sleepCtx` (sleeps; returns at once on cancel), `redisLogger` emits one JSON line |
| `internal/api` | `isTerminal` (fails if a new `JobState` is added without a decision), `toStatus`, `normalizeJobID` (all 5 forms `uuid.Parse` accepts), `lookupJob`, `GetReport` and `WatchReport` reject non-UUIDs before Redis, `SubmitEmail` rejections (no data, over the cap, cap crossed mid-stream stops reading, client error passed through, filename over 255 bytes), the upload timeout (and that the receive goroutine exits afterwards), and a client hang-up returning Canceled rather than Internal |
| `internal/store` | key names and prefix, `New` refuses a TTL ≤ 0 |
| `internal/queue` | `Enqueue("")` refused before Redis |
| `internal/config` | defaults, overrides, bad values, **every** bad variable reported at once, `LogValue` never prints the password |

Not unit-tested on purpose: the Redis-backed methods of `store` and `queue`, `worker.process`/`handle`, and `cmd/api` `main`. They are only meaningful against a real Redis, so the e2e script covers them.

## 2. End-to-end: `scripts/e2e.sh`

This is the manual Day 1 run, written down. The script:

1. Builds `api`, `worker` and `phishcheck`, with `-race` when cgo is available (it is in CI, but not on this WSL box).
2. Starts a **throwaway** `redis:7-alpine` container on `127.0.0.1:6390`, an API on `127.0.0.1:50061` with a 256 KiB cap, and one worker. It never touches the dev Redis on 6379 or an API on 50051. To change the ports, set `E2E_REDIS_PORT` and `E2E_API_PORT`.
3. Runs 56 checks, grouped:
   - **happy path**: `submit --wait` on `samples/synthetic/clean.eml`, then `report --json`. Checks the verdict, score, filename, that sha256 equals `sha256sum`, and the worker ID.
   - **Redis state**: the job hash is DONE with the right worker and the filename kept from QUEUED; email, job and report keys all have a TTL; nothing is left in the pending list (XACK happened).
   - **size cap**: exactly 256 KiB (4 chunks) is accepted and hashes the same; one byte over is rejected with the server's message and creates no job; an empty file is refused; a file named with ESC and CR prints only a cleaned path in `submit` and `submit-dir` errors.
   - **bad IDs**: a non-UUID, an unknown UUID, and an uppercase copy of a real ID (which must find the job and return the lowercase ID).
   - **worker failure paths**: a stream entry whose email doesn't exist ends FAILED, and `report` shows the reason. An entry with no `job_id` is acked, not left pending, and is logged as a WARN skip rather than a read error. The worker keeps going afterwards.
   - **submit-dir --wait**: 5 good files and 1 empty one. Checks the table rows, the exit code and the failure count, and that nothing is pending. Under `-race`, this is the concurrent watcher path.
   - **logs**: every API and worker line is valid JSON, no password is logged, no `DATA RACE`.
   - **shutdown**: SIGTERM makes both services exit 0 with their clean-stop log lines; afterwards the CLI reports "API unreachable".
4. Stops everything and removes the container. On failure it prints the last log lines and keeps the work directory.

CI runs it as the `e2e` job.

The `test-integration` target (`go test -tags integration`) is unchanged and still has no tagged tests. It's left for Go-level Redis tests of `store` and `queue` if you want them later.

## 3. Day 2: store, queue and worker tests

What each test suite covers, how to run it, and what is still untested.
This feeds the README "Testing" section on Day 7 (§7.1, item 8).

### Running

```bash
go test ./...            # all unit tests, about 11 s
go test -short ./...     # skips the two tests that wait out the 5 s BLOCK
go test -race ./...      # what CI runs
scripts/e2e.sh           # end to end: real Redis, API, worker, CLI

# Integration: needs a real Redis. Uses DB 15 and flushes only that DB.
REDIS_ADDR=localhost:6379 go test -tags integration ./...
```

The unit tests need no Redis. They use `github.com/alicebob/miniredis/v2`,
an in-memory Redis that starts per test. Tests that depend on something
miniredis doesn't model sit behind `//go:build integration`, as §2.8 says.

### Suites

| Package | File | Covers |
| --- | --- | --- |
| `internal/store` | `store_redis_test.go` | Email, job and report round trips; the 7-day TTL on every key; the TTL refreshed on each job write; job state changes, `attempts` and timestamps; a retry clearing the previous error (§2.8) |
| `internal/queue` | `queue_redis_test.go` | Enqueue, read and ack; the PEL; `EnsureGroup` running twice; malformed entries in Next and Claim; claiming only idle entries; dead-letter writes, the ack, and extra commands in the same transaction; Next ignoring cancel until the BLOCK ends (§2.7, below) (§2.8) |
| `internal/queue` | `claim_integration_test.go` | Real Redis only: a trimmed pending entry is reported by Claim; `OtherActiveConsumers` sees live consumers and drops quiet ones |
| `internal/worker` | `worker_test.go` | Handle's ack decision, every reclaim() case and its order, the timing budget, and the §2.4 and §2.5 "Done when" scenarios (below) |
| `cmd/phishcheck` | `main_test.go` | Output sanitizing, report and JSON printing, 64 KB chunking, `submit-dir`, `--wait`, and the §2.6 timeline (`TestTimeline`: ms and s offsets, missed phases, the reclaim RUNNING line, dead-letter, clock skew) |
| `cmd/worker` | `main_test.go` | Worker ID format, backoff sleep, go-redis log adapter, the main loop's `nextStep` decision |
| `scripts/e2e.sh` | | `submit --wait` progress format (§2.6), worker exit on SIGTERM (§2.7) |

#### internal/worker

The guide's §2.8 asks only for store and queue tests. These tests were added
because the worker holds the core Day 2 decisions: getting one wrong either
loses a job (acked too early) or retries it forever, and none of the other
tests would notice.

**Handle, one attempt, then ack or not:**

| Outcome | Expected | Test |
| --- | --- | --- |
| Success | DONE, report stored, acked | `TestHandleSuccessAcks` |
| Ordinary error (email expired) | FAILED with error, acked | `TestHandleErrorFailsAndAcks` |
| Panic | stays RUNNING with the error recorded, not acked | `TestHandlePanicLeavesPending` |
| Redis write failed | job untouched, not acked | `TestHandleRedisWriteFailureLeavesPending` |
| Timeout | FAILED with "timed out after …", acked | `TestHandleTimeoutFailsAndAcks` (timeout shortened to 100 ms through the unexported `jobTimeout` field) |

**reclaim, one claimed entry.** The `switch` is first-match, so the case
order is part of the logic. `TestReclaimCases` checks each case:

| Job state | Expected |
| --- | --- |
| hash missing | dead-lettered with attempts 0; hash not recreated |
| Redis read error | left pending |
| DONE (any attempts, even 3) | acked only; never rerun or dead-lettered |
| FAILED (any attempts, even 3) | acked only: a recorded ordinary failure, not a poison job |
| RUNNING, attempts 3 | FAILED, dead-lettered with the last error, acked, in one MULTI/EXEC |
| RUNNING or QUEUED, attempts under 3 | rerun through Handle |

FAILED can come before the attempts check because `giveUp` writes FAILED in
the same transaction as the dead-letter record and the XACK. It never leaves
a FAILED entry pending, so a pending FAILED entry always means "fail()
recorded it, then the XACK was lost".

**Timing budget.** `TestMaxHoldTimeBelowMinIdle` fails if `MaxHoldTime`
(reclaim's 2 s job read + `JobTimeout` 50 s + `FinishTimeout` 5 s = 57 s)
reaches `ReclaimMinIdle` (60 s). Past that, a second worker can claim an
entry the first is still finishing, and the job runs twice.

**End to end, no real waiting.** miniredis's clock is pinned with
`SetTime` and moved 61 s forward, so the real 60 s `ReclaimMinIdle` applies:

- `TestPanicThreeTimesIsDeadLettered` (§2.5): three panics give exactly one
  dead-letter entry, FAILED, attempts 3, and an empty PEL. A fourth pass adds
  nothing.
- `TestCrashedJobIsReclaimedByAnotherWorker` (§2.4): a job left RUNNING by a
  dead consumer is untouched before 60 s idle, then finished by the other
  worker with attempts 2 and that worker's ID on the report.

**Checked by breaking the code on purpose.** Each change below made at least
one test fail:
- moving the attempts check back above FAILED
- moving the attempts check above DONE
- dropping the FAILED write from `giveUp`
- acking panics
- making Claim ignore the trimmed list (caught by the integration test)

### Gaps and known limits

- **A trimmed pending job is reported, not saved.** If `MAXLEN ~ 10000` on
  Enqueue trims an entry that is still pending, Redis 7 removes it from the
  PEL and its job ID is gone. Claim now returns those stream IDs and reclaim
  logs each one at Error ("pending job lost …"), but the job hash still says
  RUNNING or QUEUED and `submit --wait` on it never ends. Preventing it means
  trimming differently from Appendix B.3 (for example `XTRIM MINID` at the
  oldest pending ID), which is a design decision still open.
- **The panic-demo guard checks once, at startup.** A worker started after
  the panic worker isn't caught. A worker that stopped less than 60 s ago
  still counts as live, so the §2.5 demo needs a minute's wait after stopping
  the other workers.
- **The `kill -9` and dead-letter demos (§2.4, §2.5) are not in CI.** The
  worker tests cover the same logic on miniredis. See "Demo runs" below for
  the last manual run against real Redis.
- **`phishcheck report` does not show `attempts`.** §2.4 says the report shows
  `attempts: 2`, but `Report` has no attempts field. The count is on the job
  hash, in `JobStatus`, and on the `--wait` RUNNING line (`attempt 2`).

### Where the code and the guide differ

- **§2.7 says go-redis cancels a blocking read on context cancel. It doesn't.**
  `TestNextIgnoresCancelUntilBlockEnds` shows Next waiting out the full 5 s
  BLOCK on miniredis, and the same was measured on Redis 7.4. The worker
  still shuts down correctly, but SIGTERM can take up to 5 s longer than the
  in-flight job. The comment in `cmd/worker/main.go` was already right.
- **Dead-letter entries carry more fields than B.3 lists.** B.3 has `job_id`
  and `error`. The code also writes `stream_id`, `attempts` and
  `dead_lettered_by`. The length cap matches B.3 (`MAXLEN ~ 1000`).

### Demo runs against real Redis

Last run 2026-11-22 against `redis:7-alpine`, binaries built from
`feat/queue-hardening`, following §2.4 and §2.5 as written. This run was
before the review fixes. The panic-demo guard has been checked on real Redis
since then: it refuses to start next to a live worker and starts normally
when there is none.

**§2.4 crash recovery: pass.** Worker A ran with `PHISHCHECK_DEBUG_SLEEP=45s`
and took the job, then got `kill -9` 3 s in. Worker B's reclaim loop finished
it 58 s after the kill (the guide's bound is 90 s). Job hash: DONE,
`attempts 2`, B's `worker_id`. Report `worker_id` is B. PEL empty afterwards.
`--wait` printed:

```text
QUEUED   0.0s
RUNNING  +1.4ms    (LAPTOP-KB519V12-f8c2)
RUNNING  +60.7s    (LAPTOP-KB519V12-b80c, attempt 2)
DONE     +60.7s
```

**§2.5 dead-letter: pass.** One worker ran alone with `PHISHCHECK_DEBUG_PANIC=1`
and `PHISHCHECK_RECLAIM_IDLE=5s`. `attempts` reached 2 at +29 s and 3 at +59 s,
and the job went FAILED at +89 s, one reclaim tick (`ReclaimEvery`, 30 s)
apart. `XLEN phishcheck:jobs:dead` was 1. The entry held `job_id`,
`stream_id`, `attempts 3`, the panic message and `dead_lettered_by`. The PEL
was empty afterwards. The worker logged 3 panics and stayed up, and
`submit --wait` exited non-zero with the panic reason.

**SIGTERM:** worker B, stopped between the two demos, exited 0.

### miniredis pitfalls

- **Don't simulate outages with SetError.** `miniredis.SetError` rejects
  commands only while it is set. go-redis gives up on a MULTI/EXEC after the
  first error reply. If the test then clears the error, miniredis runs the
  commands still in its buffer (`HINCRBY`, `EXPIRE`) outside the transaction.
  The write-failure test failed in about half of runs that way, with a
  half-applied transaction that real Redis can't produce. The worker tests use
  `m.Close()` and `m.Restart()` instead (the `outage` helper), and the client
  sets `MaxRetries: -1` so the test doesn't sit through retries.
- **Trimmed pending entries vanish silently.** Real Redis 7 reports them in
  XAUTOCLAIM's third element, but miniredis returns an empty list, so the
  trimmed-entry test is integration-only.
- **Consumer idle times aren't tracked for XREADGROUP.** miniredis reports -1
  ("always active"), and its consumer timestamps ignore `SetTime`. The
  `OtherActiveConsumers` test is integration-only.
