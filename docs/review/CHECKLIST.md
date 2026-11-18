# Review checklist

The same five items every day, in this order. For each one, record **findings** (file:line, what goes wrong, a fix) and **checked, OK** (what you looked at and why it holds), so the next review can tell what was actually covered.

Before you start: `go vet ./... && make test && make e2e` must pass. The review is for what tests don't catch.

Severity: **High** loses or corrupts data, or is exploitable as shipped · **Medium** wrong behavior on a realistic path · **Low** edge case, or defense in depth · **Nit** wording.

---

## 1. Error handling

- Every returned `error` is checked. `_ =` needs a comment saying why.
- Wrapped with the step that failed (`fmt.Errorf("get email: %w", err)`), and wrapped with `%w`, not `%v`, wherever a caller uses `errors.Is` or `errors.As`.
- Sentinel checks use `errors.Is`, never `==` (`redis.Nil`, `io.EOF`, `store.ErrNotFound`).
- gRPC handlers return `status` errors with the right code, and the message never includes internal error text. The detail goes to the log.
- Client cancellation (`ctx.Err() != nil`) is reported as Canceled or DeadlineExceeded, not as Internal, and not logged as a server error.
- Each kind of failure gets its own branch: a malformed input isn't handled like a Redis outage.
- The CLI exits non-zero on every failure, and a script piping stdout gets nothing on failure.

How to check: `grep -n 'err != nil' -A3`, and look for any branch that only logs and then carries on as if it had succeeded.

## 2. Email-derived text reaching output without `clean()`

**Email-derived** means any of: the filename (sent by the client, *and* local file names, since mail clients name saved `.eml` files after the Subject), headers, subject, addresses, URLs, attachment names and content types, finding `evidence` and `description`, and worker error strings, which can quote the email. Treat the whole report as untrusted, except the fields the server computes itself (job ID, sha256, worker ID, enums, numbers).

- Every terminal-bound print (`fmt.Print*`, `Fprint*` to stdout or stderr, tabwriter) passes untrusted text through `clean()`.
- **Errors count.** `os.PathError`, `fmt.Errorf("%s ...", path)` and wrapped server messages often carry a filename. Check what `err.Error()` contains, not just the variables named at the print site.
- Truncation limits are applied in the text output; `--json` keeps the full text.
- JSON outputs (`--json`, slog) escape C0 control characters only. U+202E, C1 controls and zero-width characters go through raw. That's fine for machines, so don't describe it as terminal-safe.
- No untrusted text is used as a path, key, command argument or format string.

How to check: `grep -n 'Print\|Fprint\|Errorf' cmd/phishcheck/*.go`, and trace each argument back to its source.

## 3. Resource cleanup

- Every `Open`, `NewClient`, `NewTicker`, `NewTimer` and `WithCancel`/`WithTimeout` has a `defer` close, stop or cancel on every return path.
- gRPC client streams end on every path: `CloseAndRecv`, `Recv` until an error, or the stream's context cancelled. An early `return` mid-stream leaks it until the parent context ends.
- Every Redis key written has a TTL, and every stream has a length cap. Every entry read from the consumer group gets XACKed (or is reclaimed, from Day 2 on).
- Shutdown order: stop accepting work, drain, then close Redis.
- `os.Exit` skips deferred calls; only use it where nothing is deferred.
- Anything sized by the client (upload buffer, filename, number of open streams) has a cap and a deadline.

How to check: `grep -n 'defer\|os.Exit\|Set(\|HSet\|XAdd' -r cmd internal`.

## 4. Concurrency

- Shared state between goroutines is a channel, a mutex, or disjoint indices with a `Wait` before anything reads it.
- Every `select` and `switch` on `ctx.Err()` is checked for what happens to work already in hand. Never drop a job you read but haven't finished.
- Signal or shutdown cancellation: which in-flight Redis writes does it abort, and what state does that leave behind?
- Write ordering across processes: whatever makes a job visible to someone else (XADD, setting DONE) is written last.
- Goroutines always exit: buffered result channels, ctx-aware waits, no unbounded fan-out.
- `make e2e` under `-race` (CI) reports no `DATA RACE`.

## 5. Comments match the code

- Every comment that states a fact (an order, a guarantee, a number, "never", "always", "README says") is checked against the code, and against the docs it names.
- Doc comments name the identifiers that actually exist (`ErrNoJob`, not `errNoJob`).
- Every "Day N / §x.y" deferral is still accurate. If the gap it defers causes a bug today, file the bug, not just the TODO.
