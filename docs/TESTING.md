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
