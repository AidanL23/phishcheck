# Testing

What each test suite covers, how to run it, and what is still untested.
This feeds the README "Testing" section on Day 7 (§7.1, item 8).

## Running

```bash
go test ./...            # all unit tests, about 6 s
go test -short ./...     # skips the one test that waits out the 5 s BLOCK
go test -race ./...      # what CI runs
scripts/e2e.sh           # end to end: real Redis, API, worker, CLI
```

The unit tests need no Redis. They use `github.com/alicebob/miniredis/v2`,
an in-memory Redis that starts per test.

## Suites

| Package | File | Covers |
| --- | --- | --- |
| `internal/store` | `store_redis_test.go` | Email, job and report round trips; the 7-day TTL on every key; the TTL refreshed on each job write; job state changes, `attempts` and timestamps; a retry clearing the previous error (§2.8) |
| `internal/queue` | `queue_redis_test.go` | Enqueue, read and ack; the PEL; `EnsureGroup` running twice; malformed entries; claiming only idle entries; dead-letter writes and acks (§2.8) |
| `internal/worker` | `worker_test.go` | Handle's ack decision, every reclaim() case and its order, and the §2.4 and §2.5 "Done when" scenarios (below) |
| `cmd/phishcheck` | `main_test.go` | Output sanitizing, report and JSON printing, 64 KB chunking, `submit-dir`, `--wait` (only with no timestamps; see Gaps) |
| `cmd/worker` | `main_test.go` | Worker ID format, backoff sleep, go-redis log adapter, the main loop's `nextStep` decision |
| `scripts/e2e.sh` | | `submit --wait` progress format (§2.6), worker exit on SIGTERM (§2.7) |

### internal/worker

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
| Timeout | FAILED, acked | **not tested**, see Gaps |

**reclaim, one claimed entry.** The `switch` is first-match, so the case
order is part of the logic. `TestReclaimCases` checks each case, including the
two that only pass if the order is right:

| Job state | Expected |
| --- | --- |
| hash missing | dead-lettered with attempts 0; hash not recreated |
| Redis read error | left pending |
| DONE (any attempts, even 3) | acked only; never rerun or dead-lettered |
| RUNNING or FAILED, attempts 3 | FAILED, dead-lettered with the last error |
| FAILED, attempts under 3 | acked only |
| RUNNING or QUEUED, attempts under 3 | rerun through Handle |

**End to end, no real waiting.** miniredis's clock is pinned with
`SetTime` and moved 61 s forward, so the real 60 s `ReclaimMinIdle` applies:

- `TestPanicThreeTimesIsDeadLettered` (§2.5): three panics give exactly one
  dead-letter entry, FAILED, attempts 3, and an empty PEL. A fourth pass adds
  nothing.
- `TestCrashedJobIsReclaimedByAnotherWorker` (§2.4): a job left RUNNING by a
  dead consumer is untouched before 60 s idle, then finished by the other
  worker with attempts 2 and that worker's ID on the report.

**Checked by breaking the code on purpose:** moving the FAILED case above the
attempts check fails `TestReclaimCases`, and acking panics fails the three
panic tests.

## Gaps and known quirks

- **Timeout path untested.** `JobTimeout` is a fixed 50 s constant, and
  Handle's finish deadline derives from the same parent context, so the path
  can't be triggered quickly. Testing it means making the timeout a field on
  `Worker`.
- **`--wait` timeline offsets untested in unit tests.** `TestWaitForReport`
  only covers statuses with no timestamps (every line prints `-`). The
  `+0.3ms` / `+1.8s` formatting and the extra RUNNING line on a reclaim are
  checked only by the regexes in `scripts/e2e.sh`, and the reclaim line not at all.
- **The `kill -9` and dead-letter demos (§2.4, §2.5) are not in CI.** The
  worker tests cover the same logic on miniredis. See "Demo runs" below for
  the last manual run against real Redis.
- **`phishcheck report` does not show `attempts`.** §2.4 says the report shows
  `attempts: 2`, but `Report` has no attempts field. The count is on the job
  hash, in `JobStatus`, and on the `--wait` RUNNING line (`attempt 2`).
- **An attempt-3 ordinary error with a lost XACK gets dead-lettered.** Its
  state (FAILED, attempts 3) matches a failed `giveUp`, so reclaim
  dead-letters it, while attempts 1 and 2 would just be acked. The result is an
  extra, harmless dead-letter record. Telling the two apart would need another
  field on the job hash.

## Demo runs against real Redis

Last run 2026-11-22 against `redis:7-alpine`, binaries built from
`feat/queue-hardening`, following §2.4 and §2.5 as written.

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

## miniredis pitfall: don't simulate outages with SetError

`miniredis.SetError` rejects commands only while it is set. go-redis gives up
on a MULTI/EXEC after the first error reply. If the test then clears the
error, miniredis runs the commands still in its buffer (`HINCRBY`, `EXPIRE`)
outside the transaction. The write-failure test failed in about half of runs
that way, with a half-applied transaction that real Redis can't produce. The
worker tests use `m.Close()` and `m.Restart()` instead (the `outage` helper),
and the client sets `MaxRetries: -1` so the test doesn't sit through retries.
