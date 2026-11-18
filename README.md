# PhishCheck

Submit a suspicious .eml file through a CLI. A worker analyzes it and returns a report with findings, a score, and a verdict (clean, suspicious, likely phishing). It automates the first five minutes of a SOC phishing ticket.

## Status

**Day 1 of 7: the vertical slice works end to end.** The analysis itself is still a stub: every email comes back `CLEAN` with score 0. Real findings start on Day 3.

What works today:

- **CLI** (`cmd/phishcheck`): `submit` streams an .eml in 64 KB chunks and checks the server's SHA-256 against its own. `--wait` follows the job to the end. `report` prints a report as text or `--json`. `submit-dir` uploads a whole folder and shows a table of results. Anything taken from an email is escaped before it reaches the terminal.
- **API** (`cmd/api`): a gRPC server with `SubmitEmail`, `GetReport` and `WatchReport`. It enforces a size cap (25 MB by default), a filename cap and an upload timeout, and shuts down gracefully.
- **Queue and store** (Redis): the job ID goes on a Redis Stream read by a consumer group. The email, job state and report each live under their own key, and every key has a TTL.
- **Worker** (`cmd/worker`): reads a job, marks it RUNNING, writes the stub report, then marks it DONE (or FAILED with the reason), and acks. On SIGTERM it finishes the job in hand before exiting. Logs are one JSON object per line.

Next: Day 2 adds crash recovery (reclaiming jobs a dead worker left pending) and retry attempts and timings in the job status.

## Run it locally

Needs Go and Docker.

```bash
make up                      # Redis in Docker, on 127.0.0.1:6379
go run ./cmd/api             # terminal 1
go run ./cmd/worker          # terminal 2
go run ./cmd/phishcheck submit samples/synthetic/clean.eml --wait
```

`make down` stops Redis and deletes its data.

Settings come from environment variables: `REDIS_ADDR`, `PHISHCHECK_GRPC_ADDR`, `PHISHCHECK_MAX_EMAIL_BYTES`, `PHISHCHECK_TTL` and others; see `internal/config`. The CLI dials `PHISHCHECK_ADDR` (default `localhost:50051`).

## Testing

```bash
make test                    # unit tests, no Redis needed (~1 s)
make e2e                     # whole slice against a throwaway Redis container (~12 s; needs Docker and jq)
```

CI runs both on every pull request, with the race detector on in the e2e job. [docs/TESTING.md](docs/TESTING.md) describes what each layer covers. [docs/review/CHECKLIST.md](docs/review/CHECKLIST.md) is the checklist for the review at the end of each day.

## Known limitations

- **Plaintext and unauthenticated.** The API listens without TLS or auth, and gRPC reflection is on. It's meant for a local machine only.
- **A failed enqueue strands a job.** If the email and job hash are written but the XADD fails, the job says QUEUED with nothing on the stream. No worker will ever pick it up; it disappears when its TTL expires.
- **No crash recovery yet.** If a worker dies mid-job, that job stays pending until Day 2 adds reclaiming.
- **WatchReport polls.** It re-reads the job hash every 500 ms rather than using pub/sub. That's fine at this scale.
