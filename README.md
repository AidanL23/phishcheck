# PhishCheck

Submit a suspicious .eml file through a CLI. A worker analyzes it and returns a report with findings, a score, and a verdict (clean, suspicious, likely phishing). It automates the first five minutes of a SOC phishing ticket.

## Status

**Day 2 of 7: the queue survives worker crashes.** The analysis itself is still a stub: every email comes back `CLEAN` with score 0. Real findings start on Day 3.

What works today:

- **CLI** (`cmd/phishcheck`): `submit` streams an .eml in 64 KB chunks and checks the server's SHA-256 against its own. `--wait` follows the job to the end and prints a timeline: when it was queued, each worker that started it (with the attempt number), and when it finished. `report` prints a report as text or `--json`. `submit-dir` uploads a whole folder and shows a table of results. Anything taken from an email is escaped before it reaches the terminal.
- **API** (`cmd/api`): a gRPC server with `SubmitEmail`, `GetReport` and `WatchReport`. It enforces a size cap (25 MB by default), a filename cap and an upload timeout, and shuts down gracefully.
- **Queue and store** (Redis): the job ID goes on a Redis Stream read by a consumer group. The email, job state and report each live under their own key, and every key has a TTL.
- **Worker** (`cmd/worker`): reads a job, marks it RUNNING, writes the stub report, then marks it DONE (or FAILED with the reason), and acks. Each job has a 50 s timeout, and a panic is recovered instead of killing the worker. On SIGTERM it finishes the job in hand before exiting. Logs are one JSON object per line.
- **Crash recovery**: every 30 s each worker runs `XAUTOCLAIM` and takes over any job left pending for more than 60 s, so a job whose worker died is finished by another one. The job hash counts attempts; after 3, the job is marked FAILED and moved to the `phishcheck:jobs:dead` stream instead of retrying forever. [docs/queue-failure-model.md](docs/queue-failure-model.md) explains the failure model.

Next: Day 3 parses the email (MIME, Received chain, Authentication-Results) and adds the first header rules.

## Run it locally

Needs Go and Docker.

```bash
make up                      # Redis in Docker, on 127.0.0.1:6379
go run ./cmd/api             # terminal 1
go run ./cmd/worker          # terminal 2
go run ./cmd/phishcheck submit samples/synthetic/clean.eml --wait
```

`make down` stops Redis and deletes its data.

Settings come from environment variables: `REDIS_ADDR`, `PHISHCHECK_GRPC_ADDR`, `PHISHCHECK_MAX_EMAIL_BYTES`, `PHISHCHECK_TTL` and others; see `internal/config`. `PHISHCHECK_DEBUG_SLEEP`, `PHISHCHECK_DEBUG_PANIC` and `PHISHCHECK_RECLAIM_IDLE` exist only for the crash and dead-letter demos; leave them unset. The CLI dials `PHISHCHECK_ADDR` (default `localhost:50051`).

## Testing

```bash
make test                    # unit tests, Redis faked in memory (~11 s)
make e2e                     # whole slice against a throwaway Redis container (~12 s; needs Docker and jq)
```

CI runs both on every pull request, with the race detector on in the e2e job. [docs/TESTING.md](docs/TESTING.md) describes what each layer covers. [docs/review/CHECKLIST.md](docs/review/CHECKLIST.md) is the checklist for the review at the end of each day.

## Known limitations

- **Plaintext and unauthenticated.** The API listens without TLS or auth, and gRPC reflection is on. It's meant for a local machine only.
- **A failed enqueue strands a job.** If the email and job hash are written but the XADD fails, the job says QUEUED with nothing on the stream. No worker will ever pick it up; it disappears when its TTL expires.
- **A pending job can be trimmed away.** The jobs stream is capped at about 10,000 entries. If the cap trims a job that is still pending, Redis drops it, and reclaim can only log it as lost. The job hash stays RUNNING or QUEUED, and `submit --wait` on it never gets a report: it runs until its `--timeout` and exits with an error.
- **Recovery is slow by design.** A crashed worker's job waits up to about 90 s (60 s idle plus one 30 s reclaim tick) before another worker picks it up.
- **WatchReport polls.** It re-reads the job hash every 500 ms rather than using pub/sub. That's fine at this scale.
