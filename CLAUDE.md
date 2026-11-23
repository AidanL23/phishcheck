# PhishCheck

A phishing email analyzer. You hand it a suspicious `.eml` file through a CLI. It queues the email, a worker analyzes it, and you get back a structured report: every finding with evidence, an overall score, and a verdict of clean, suspicious, or likely phishing. It automates the first five minutes of a phishing ticket in a SOC.

Stack: Go, gRPC + protobuf (buf), Redis Streams (consumer group, XAUTOCLAIM, dead-letter), Docker (distroless, from Day 6), GitHub Actions.

Layout: `cmd/api` (gRPC server), `cmd/worker` (queue consumer), `cmd/phishcheck` (CLI), `internal/{config,store,queue,worker,api}`, `proto/` → `gen/`, `deploy/docker-compose.yml`, `scripts/e2e.sh`.

## Where the plan lives

- The build guide is the source of truth: a 7-day build (Day 0 to Day 7) with exact designs, rule tables, scoring weights and reference files in Appendix B. Its "Read this first" table lists the design decisions every day depends on.
- The build checklist tracks progress. Section numbers (§) match the guide.
- Both live as claude.ai artifacts that I keep editing; the link is on line 3 of each local copy. Read the guide with the Claude Docs connector and the checklist's ticks from its `progress.json`, through the Artifact tool.
- The live doc is the only copy of the build guide that gets edited. `docs/phishcheck-build-guide.md` is an export of it: after any change to the live doc, re-export it to `docs/` and `diff` to confirm. Never edit the export directly. If the export has something the live doc lacks, say so before syncing.
- `docs/phishcheck-build-checklist.md` is a local export of the checklist and lags; its boxes are never ticked, so never judge progress from it.
- I tick the checklist myself. Don't edit the checklist artifact; when a task finishes, tell me which boxes it covers.
- The local copies are kept out of the repo on purpose through `.git/info/exclude`. Never `git add` them, and don't put the artifact links in committed files.
- Committed docs: `docs/TESTING.md` (what each test covers), `docs/queue-failure-model.md`, `docs/review/CHECKLIST.md` (the end-of-day review) and `docs/review/YYYY-MM-DD-dayN.md` (past reviews).

When I ask you to work on a day or a task, read the matching guide section first and follow it. If the guide and the code disagree, say so before changing either.

## Rules that must not be broken

- Never commit anything under `samples/real/` (gitignored). Only synthetic `.eml` files in `samples/synthetic/` are committed. Run `git ls-files samples/` before any push. Reading a real `.eml` as text is fine; never extract, decode to disk, or run its attachments.
- Nothing under `internal/` or `cmd/worker/` may import `net/http`, fetch URLs, or open attachments. CI enforces the import ban from Day 4 (§4.4); until then it is on us. Watch for indirect pulls such as `http.DetectContentType` (Day 4 uses its own magic-byte table instead).
- Only look up DNS for the sender (From and Reply-To) domains, never for hostnames found in links.
- Trust an Authentication-Results header only if its authserv-id matches `PHISHCHECK_TRUSTED_AUTHSERV`. Empty config or empty authserv-id means untrusted.
- Generated protobuf code in `gen/` is committed; CI checks it is fresh. After any `.proto` change, run `make gen` and commit `gen/` in the same commit.
- Everything derived from the email is untrusted: filename, headers, addresses, URLs, attachment names, finding evidence, and worker error strings that quote it. It goes through `clean()` before any terminal print (including inside `err.Error()`), and is never used as a path, Redis key, command argument or format string.

## Invariants already in the code

Check these whenever you touch the API, store, queue or worker. `docs/review/CHECKLIST.md` has the full list.

- Write order: email, then job state, then XADD. Whatever makes a job visible to someone else is written last. Only the job ID goes on the stream.
- Every Redis key has a TTL; every stream has a `MAXLEN`.
- Every entry read from the consumer group is XACKed or left for the reclaim loop. A job already read is never dropped on shutdown.
- gRPC handlers return `status` errors with the right code and never put internal error text in the message. Client cancellation is Canceled/DeadlineExceeded, not Internal.
- Errors are wrapped with the step that failed, using `%w`; sentinels are checked with `errors.Is`.

## Guidelines

### 1. Think before coding

Don't assume. Don't hide confusion. Surface tradeoffs. Before implementing:

- State your assumptions explicitly. If uncertain, ask.
- If multiple interpretations exist, present them; don't pick silently.
- If a simpler approach exists, say so. Push back when warranted, including on the guide.
- If something is unclear, stop. Name what's confusing. Ask.

### 2. Simplicity first

Minimum code that solves the problem. Nothing speculative.

- No features beyond what was asked or what the current guide step names.
- No abstractions for single-use code.
- No "flexibility" or "configurability" that wasn't requested.
- No error handling for impossible scenarios.
- If you write 200 lines and it could be 50, rewrite it.

Ask yourself: "Would a senior engineer say this is overcomplicated?" If yes, simplify.

### 3. Surgical changes

Touch only what you must. Clean up only your own mess. When editing existing code:

- Don't "improve" adjacent code, comments, or formatting.
- Don't refactor things that aren't broken.
- Match existing style, even if you'd do it differently.
- If you notice unrelated dead code, mention it; don't delete it.

When your changes create orphans, remove the imports, variables and functions that your changes made unused. Don't remove pre-existing dead code unless asked.

The test: every changed line should trace directly to the request. (Exception: during an end-of-day review, fixing comments that no longer match the code is the task.)

### 4. Goal-driven execution

Define success criteria. Loop until verified. Turn tasks into verifiable goals:

- "Add validation" → write tests for invalid inputs, then make them pass.
- "Fix the bug" → write a test that reproduces it, then make it pass.
- "Refactor X" → ensure tests pass before and after.

For multi-step tasks, state a brief plan:

```
1. [Step] → verify: [check]
2. [Step] → verify: [check]
3. [Step] → verify: [check]
```

Each guide section ends with a "Done when" line; that is the success criterion for the day.

## Working style

- Build the day the guide names, in the order it gives. Do not jump ahead (for example, no reclaim loop on Day 1).
- One branch per day (`feat/<topic>`), merged into `main` by a squash-merged PR with a description of what changed, why, and how it was tested.
- Small conventional commits with a scope where it helps: `feat(queue):`, `fix(api):`, `build:`, `test:`, `docs:`, `ci:`, `chore:`. Imperative mood, subject under 72 characters, body says why.

## Verifying

Before calling a task done, all of these pass:

```bash
go vet ./...
make test          # go test ./... (about 11 s; -short skips the two BLOCK waits)
make e2e           # real Redis in a throwaway container; needs docker and jq
```

- `-race` needs cgo, which this WSL box lacks. CI's e2e job builds the binaries with `-race`, so a race only shows up there.
- `make e2e` uses Redis on 6390 and the API on 50061. The dev stack (`make up`) uses 6379 and 50051; don't touch it from tests.
- New tests follow `docs/TESTING.md`: unit tests need no Redis or socket (pass a nil store to prove "rejected before Redis"; miniredis for store, queue and worker). Update `docs/TESTING.md` when coverage changes.
- At the end of each day, review against `docs/review/CHECKLIST.md` and write the result to `docs/review/YYYY-MM-DD-dayN.md`.
