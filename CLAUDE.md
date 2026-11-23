# PhishCheck

A phishing email analyzer. You hand it a suspicious `.eml` file through a CLI. It queues the email, a worker analyzes it, and you get back a structured report: every finding with evidence, an overall score, and a verdict of clean, suspicious, or likely phishing. It automates the first five minutes of a phishing ticket in a SOC.

Stack: Go, gRPC + protobuf (buf), Redis Streams (consumer group, XAUTOCLAIM, dead-letter), Docker (distroless), GitHub Actions.

## Where the plan lives

- `docs/phishcheck-build-guide.md` is the source of truth: a 7-day build (Day 0 to Day 7) with exact designs, rule tables, scoring weights and reference files in Appendix B.
- `docs/phishcheck-build-checklist.md` tracks progress. Section numbers (§) match the guide. Tick boxes as tasks finish.
- Both files are kept out of the repo on purpose through `.git/info/exclude`, so they exist only in this local clone.

When I ask you to work on a day or a task, read the matching guide section first and follow it. If the guide and the code disagree, say so before changing either.

## Rules that must not be broken

- Never commit anything under `samples/real/` (gitignored). Only synthetic `.eml` files in `samples/synthetic/` are committed.
- The worker must never import `net/http`, fetch URLs, or open attachments. CI enforces this.
- Only look up DNS for the sender (From and Reply-To) domains, never for hostnames found in links.
- Trust an Authentication-Results header only if its authserv-id matches `PHISHCHECK_TRUSTED_AUTHSERV`. Empty config or empty authserv-id means untrusted.
- Generated protobuf code in `gen/` is committed; CI checks it is fresh.

## Working style

- Build the day the guide names, in the order it gives. Do not jump ahead (for example, no reclaim loop on Day 1).
- Keep commits small, conventional (`feat:`, `fix:`, `build:`, `test:`), one branch per day.
- Run `go vet ./...` and `go test ./...` before calling a task done.
