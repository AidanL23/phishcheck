// Command phishcheck is the CLI client for the PhishCheck gRPC API.
package main

import (
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"text/tabwriter"
	"time"
	"unicode"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
)

// chunkSize matches the contract comment in phishcheck.proto: every
// SubmitEmailRequest carries at most 64 KB of the raw .eml. This keeps
// each message far under gRPC's 4 MB default per-message limit.
const chunkSize = 64 * 1024

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	// Ctrl+C cancels ctx, which cancels the in-flight RPC cleanly
	// instead of leaving the server holding a half-finished stream.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "submit":
		err = runSubmit(ctx, os.Args[2:])
	case "report":
		err = runReport(ctx, os.Args[2:])
	case "submit-dir":
		err = runSubmitDir(ctx, os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		// Clean the whole message, not just the names in it: errors like
		// *os.PathError embed the file path, and saved .eml files are often
		// named after the email's Subject.
		fmt.Fprintln(os.Stderr, "phishcheck:", clean(err.Error(), 0))
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  phishcheck submit <file.eml> [--wait] [--timeout 3m]
  phishcheck report <job-id> [--json] [--timeout 10s]
  phishcheck submit-dir <dir> [--wait] [--timeout 5m]

environment:
  PHISHCHECK_ADDR  API address to dial (default localhost:50051)`)
}

// dial returns an API client. Plaintext is deliberate this week: the
// server is local and unauthenticated, and the README will say so.
//
// The CLI reads PHISHCHECK_ADDR, not the API's PHISHCHECK_GRPC_ADDR. That
// one is a listen address (":50051"), which isn't a valid dial target.
// One variable name with two meanings breaks once the CLI runs on the
// host against Compose on Day 6.
func dial() (pb.PhishCheckServiceClient, *grpc.ClientConn, error) {
	addr := os.Getenv("PHISHCHECK_ADDR")
	if addr == "" {
		addr = "localhost:50051"
	}
	// NewClient doesn't connect yet; the first RPC does. A wrong address
	// therefore shows up as Unavailable on SubmitEmail, not here.
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	return pb.NewPhishCheckServiceClient(conn), conn, nil
}

// errUnreachable is wrapped rather than only printed, so submit-dir can
// detect it with errors.Is and stop, instead of failing every file the same way.
var errUnreachable = errors.New("API unreachable (is cmd/api running?)")

// rpcErr turns a gRPC status into a one-line message a person can act on.
func rpcErr(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("%w: %s", errUnreachable, st.Message())
	case codes.DeadlineExceeded:
		return errors.New("timed out (raise --timeout, or check a worker is running)")
	case codes.ResourceExhausted, codes.NotFound, codes.InvalidArgument:
		return errors.New(st.Message()) // the server's own message is already clear
	}
	return err
}

// parseInterspersed parses flags anywhere in args and returns the
// positional arguments. Plain fs.Parse would stop at "clean.eml" and
// treat "--wait" as a second positional argument.
func parseInterspersed(fs *flag.FlagSet, args []string) []string {
	var positional []string
	for {
		_ = fs.Parse(args) // ExitOnError: a bad flag exits before returning
		args = fs.Args()
		if len(args) == 0 {
			return positional
		}
		positional = append(positional, args[0]) // take one positional, keep parsing the rest
		args = args[1:]
	}
}

func runSubmit(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("submit", flag.ExitOnError)
	wait := fs.Bool("wait", false, "follow the job and print the result")
	timeout := fs.Duration("timeout", 3*time.Minute, "limit for the whole command, upload plus wait")

	pos := parseInterspersed(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: phishcheck submit <file.eml> [--wait]")
	}
	path := pos[0]

	// 3m leaves room for Day 2's crash demo: 60 s idle before reclaim,
	// a 30 s reclaim tick, then the retry itself.
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	client, conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	resp, err := submitFile(ctx, client, path)
	if err != nil {
		return err
	}

	// Progress goes to stderr and the job ID alone goes to stdout, so
	// `id=$(phishcheck submit x.eml)` captures just the ID.
	fmt.Fprintf(os.Stderr, "submitted %s: %d bytes, sha256 %s…\n",
		clean(filepath.Base(path), 80), resp.GetSizeBytes(), resp.GetSha256()[:12])
	fmt.Println(resp.GetJobId())

	if !*wait {
		return nil
	}
	r, err := waitForReport(ctx, client, resp.GetJobId(), os.Stderr)
	if err != nil {
		return err
	}
	return printReport(os.Stdout, r)
}

// submitFile streams the file to SubmitEmail in 64 KB chunks and checks
// that the server stored exactly the bytes that were sent.
func submitFile(ctx context.Context, client pb.PhishCheckServiceClient, path string) (*pb.SubmitEmailResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err // *PathError already names the file
	}
	defer f.Close()

	// Refuse input the server would accept and turn into a broken job.
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory (submit-dir handles folders)", path)
	}
	if info.Size() == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}

	// The stream gets its own context. Every early return below (a read
	// error, a failed Send) skips CloseAndRecv, and gRPC keeps a stream open
	// until its context ends. Without this, submit-dir would leave it open,
	// and the server holding the partial upload, until the whole command ended.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	stream, err := client.SubmitEmail(ctx)
	if err != nil {
		return nil, rpcErr(err)
	}

	h := sha256.New()           // hash exactly what goes over the wire
	var sent int64              // count it too
	name := filepath.Base(path) // the server sees "clean.eml", not your folder layout
	filenameSent := false

	for {
		// Allocate a new buffer for each chunk. gRPC's docs say not to modify a
		// message after Send, and Data would point into a reused buffer.
		// At the 25 MB cap that's 400 allocations, which costs nothing.
		buf := make([]byte, chunkSize)
		n, readErr := f.Read(buf)

		// Handle n > 0 BEFORE checking readErr: Read can return the last
		// bytes and io.EOF in the same call. Checking err first drops the
		// file's tail, and only for some file sizes.
		if n > 0 {
			req := &pb.SubmitEmailRequest{Data: buf[:n]}
			if !filenameSent {
				req.Filename = name // contract: the filename goes on the first message only
				filenameSent = true
			}
			if err := stream.Send(req); err != nil {
				// When the server aborts the stream (ResourceExhausted past the
				// cap, or our ctx timing out), Send only returns io.EOF. The real
				// status comes from CloseAndRecv, so break and go get it.
				if errors.Is(err, io.EOF) {
					break
				}
				return nil, fmt.Errorf("send chunk: %w", rpcErr(err))
			}
			h.Write(buf[:n])
			sent += int64(n)
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, readErr)
		}
	}

	// CloseAndRecv tells the server we're done (it sees io.EOF) and waits
	// for its response or its error status.
	resp, err := stream.CloseAndRecv()
	if err != nil {
		return nil, rpcErr(err)
	}

	// A successful response only proves the server got *something*. This
	// check proves it got the whole file in order, with no chunk dropped,
	// duplicated, or reordered.
	local := hex.EncodeToString(h.Sum(nil))
	if resp.GetSha256() != local || resp.GetSizeBytes() != sent {
		return nil, fmt.Errorf("integrity mismatch: sent %d bytes (sha256 %s), server stored %d bytes (sha256 %s)",
			sent, local, resp.GetSizeBytes(), resp.GetSha256())
	}
	return resp, nil
}

// enumName strips the proto prefix: VERDICT_LIKELY_PHISHING -> LIKELY_PHISHING.
func enumName(v fmt.Stringer, prefix string) string {
	return strings.TrimPrefix(v.String(), prefix)
}

// clean makes attacker-controlled text safe to print in a terminal. Visible
// characters, including quotes and non-ASCII letters, pass through. Control
// and format characters (ESC, \r, \n, \t, U+202E) are shown as escapes, so
// they can't move the cursor, recolor output, or reorder what you see.
// max > 0 truncates to max runes and adds "…"; --json always keeps the full text.
func clean(s string, max int) string {
	var b strings.Builder
	n := 0
	for _, r := range s { // invalid UTF-8 arrives as U+FFFD, which prints as �
		if max > 0 && n == max {
			b.WriteString("…")
			break
		}
		if unicode.IsGraphic(r) {
			b.WriteRune(r)
		} else {
			q := strconv.QuoteRuneToGraphic(r) // e.g. '\x1b'
			b.WriteString(q[1 : len(q)-1])     // drop the single quotes
		}
		n++
	}
	return b.String()
}

// waitForReport follows the job with WatchReport until it finishes, then
// fetches the report with GetReport. State changes are written to progress.
func waitForReport(ctx context.Context, client pb.PhishCheckServiceClient, jobID string, progress io.Writer) (*pb.Report, error) {
	watch, err := client.WatchReport(ctx, &pb.WatchReportRequest{JobId: jobID})
	if err != nil {
		return nil, rpcErr(err)
	}

	var last *pb.JobStatus
	tl := &timeline{w: progress}
	for {
		msg, err := watch.Recv()
		if errors.Is(err, io.EOF) {
			break // the server closed the stream after DONE or FAILED
		}
		if err != nil {
			return nil, fmt.Errorf("watch: %w", rpcErr(err))
		}
		last = msg.GetStatus()
		tl.update(last)
	}

	// A closed stream doesn't prove the job finished, so check the final
	// state explicitly. Getters are nil-safe: no messages means UNSPECIFIED.
	switch last.GetState() {
	case pb.JobState_JOB_STATE_DONE:
		// fall through to GetReport
	case pb.JobState_JOB_STATE_FAILED:
		// A worker error can quote the email (a parse error, say), so clean it.
		return nil, fmt.Errorf("job %s failed: %s", jobID, clean(last.GetError(), 200))
	default:
		return nil, fmt.Errorf("watch ended with job in state %s", last.GetState())
	}

	got, err := client.GetReport(ctx, &pb.GetReportRequest{JobId: jobID})
	if err != nil {
		return nil, fmt.Errorf("get report: %w", rpcErr(err))
	}
	if got.GetReport() == nil {
		return nil, errors.New("job is DONE but the API returned no report") // a server bug; say so loudly
	}
	return got.GetReport(), nil
}

// timeline prints one line per job phase, timed from submitted_at:
//
//	QUEUED   0.0s
//	RUNNING  +0.3ms    (worker-ab12)
//	DONE     +1.8s
//
// A fast job can be DONE before the first poll, so update rebuilds missed
// phases from the timestamps each status carries.
type timeline struct {
	w       io.Writer
	queued  bool  // QUEUED line printed
	ran     bool  // a RUNNING line printed
	attempt int32 // attempt on the last RUNNING line
}

func (t *timeline) update(st *pb.JobStatus) {
	base := st.GetSubmittedAt() // nil for jobs submitted before §2.6

	if !t.queued {
		t.line("QUEUED", base, base, "")
		t.queued = true
	}

	// A new attempt (a reclaim) gets its own RUNNING line. The state check
	// covers jobs with no started_at.
	started := st.GetStartedAt() != nil || st.GetState() == pb.JobState_JOB_STATE_RUNNING
	if started && (!t.ran || st.GetAttempts() != t.attempt) {
		detail := st.GetWorkerId()
		if n := st.GetAttempts(); n > 1 {
			detail += fmt.Sprintf(", attempt %d", n)
		}
		t.line("RUNNING", base, st.GetStartedAt(), detail)
		t.ran, t.attempt = true, st.GetAttempts()
	}

	// The stream ends after DONE or FAILED, so this prints once.
	if s := st.GetState(); s == pb.JobState_JOB_STATE_DONE || s == pb.JobState_JOB_STATE_FAILED {
		t.line(enumName(s, "JOB_STATE_"), base, st.GetFinishedAt(), "")
	}
}

// line prints one phase with its offset from base, or "-" if either time is
// missing. %+ keeps the sign so clock skew between hosts shows as negative.
func (t *timeline) line(state string, base, at *timestamppb.Timestamp, detail string) {
	offset := "-"
	if base != nil && at != nil {
		d := at.AsTime().Sub(base.AsTime())
		switch {
		case d == 0:
			offset = "0.0s" // QUEUED: the zero point
		case d > -time.Second && d < time.Second:
			// ms under 1 s, or %.1fs would show +0.0s for the stub worker.
			offset = fmt.Sprintf("%+.1fms", float64(d)/float64(time.Millisecond))
		default:
			offset = fmt.Sprintf("%+.1fs", d.Seconds())
		}
	}
	if detail != "" {
		detail = "(" + detail + ")"
	}
	// TrimRight drops the column padding when detail is empty.
	fmt.Fprintln(t.w, strings.TrimRight(fmt.Sprintf("%-8s %-9s %s", state, offset, detail), " "))
}

// printReport writes the human-readable report: a short header, then one
// line per finding, highest severity first. Text that came from the email
// goes through clean() first.
func printReport(w io.Writer, r *pb.Report) error {
	analyzed := "-"
	if ts := r.GetAnalyzedAt(); ts != nil { // AsTime on nil gives 1970, which looks like real data
		analyzed = ts.AsTime().Local().Format(time.DateTime)
	}
	fmt.Fprintf(w, "verdict   %s (score %d)\n", enumName(r.GetVerdict(), "VERDICT_"), r.GetScore())
	fmt.Fprintf(w, "file      %s\n", clean(r.GetFilename(), 80))
	fmt.Fprintf(w, "sha256    %s\n", r.GetSha256())
	fmt.Fprintf(w, "job       %s\n", r.GetJobId())
	fmt.Fprintf(w, "worker    %s at %s\n", r.GetWorkerId(), analyzed)

	// Clone before sorting: SortStableFunc sorts in place, and the report's
	// slice isn't this function's to reorder. Stable keeps the worker's
	// order within the same severity.
	findings := slices.Clone(r.GetFindings())
	slices.SortStableFunc(findings, func(a, b *pb.Finding) int {
		return cmp.Compare(b.GetSeverity(), a.GetSeverity()) // b before a: HIGH first
	})

	fmt.Fprintf(w, "\nfindings (%d)\n", len(findings))
	var sum int32
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0) // aligns columns, 2-space gap
	for _, f := range findings {
		sum += f.GetPoints()
		fmt.Fprintf(tw, "  %s\t%s\t+%d\t%s\n",
			enumName(f.GetSeverity(), "SEVERITY_"),
			clean(f.GetRuleId(), 40),
			f.GetPoints(),
			clean(f.GetEvidence(), 100)) // truncated here; --json has the full evidence
	}
	if len(findings) == 0 {
		fmt.Fprintln(tw, "  none")
	}
	if err := tw.Flush(); err != nil { // tabwriter buffers: nothing prints until Flush
		return err
	}

	// Same idea as submit's sha256 check. The contract says the score is
	// the sum of the findings' points. If they disagree, the worker has a
	// scoring bug, and this is the cheapest place to notice it.
	if sum != r.GetScore() {
		fmt.Fprintf(os.Stderr, "warning: findings add up to %d but score is %d\n", sum, r.GetScore())
	}
	return nil
}

// jsonOpts controls --json output.
var jsonOpts = protojson.MarshalOptions{
	Multiline: true,
	Indent:    "  ",
	// job_id instead of jobId: matches the .proto and the worker's slog
	// lines, so you don't have to remember two spellings in jq.
	UseProtoNames: true,
	// Without this, proto3 zero values are left out. A clean report would
	// have no "score" and no "findings" at all, and `jq .score` would print null.
	EmitUnpopulated: true,
}

// printJSON uses protojson, not encoding/json. encoding/json doesn't know
// the proto JSON mapping: enums come out as numbers and Timestamps as
// {seconds, nanos} objects.
func printJSON(w io.Writer, r *pb.Report) error {
	b, err := jsonOpts.Marshal(r)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	_, err = fmt.Fprintf(w, "%s\n", b)
	return err
}

func runReport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "print the full report as JSON")
	timeout := fs.Duration("timeout", 10*time.Second, "limit for the request")

	pos := parseInterspersed(fs, args) // so both `report ID --json` and `report --json ID` work
	if len(pos) != 1 {
		return errors.New("usage: phishcheck report <job-id> [--json]")
	}
	jobID := pos[0]

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	client, conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	got, err := client.GetReport(ctx, &pb.GetReportRequest{JobId: jobID})
	if err != nil {
		return rpcErr(err) // NotFound covers both unknown IDs and jobs past their TTL
	}

	// Only DONE has a report. Every other state is an error with a non-zero
	// exit and nothing on stdout, so `report $id --json | jq` fails loudly
	// instead of quietly piping an empty object into a script.
	st := got.GetStatus()
	switch st.GetState() {
	case pb.JobState_JOB_STATE_DONE:
		// handled below
	case pb.JobState_JOB_STATE_FAILED:
		return fmt.Errorf("job %s failed: %s", jobID, clean(st.GetError(), 200))
	default:
		return fmt.Errorf("job %s is %s, no report yet (retry, or use submit --wait next time)",
			jobID, enumName(st.GetState(), "JOB_STATE_"))
	}

	r := got.GetReport()
	if r == nil {
		return errors.New("job is DONE but the API returned no report")
	}
	if *asJSON {
		// Full, uncleaned data: machines need the exact bytes. JSON escaping
		// covers C0 controls (ESC, CR, LF) but not bidi overrides like U+202E
		// or C1 controls like U+009B, so this output is for jq and scripts,
		// not for reading raw in a terminal.
		return printJSON(os.Stdout, r)
	}
	return printReport(os.Stdout, r)
}

// dirResult is one file's outcome. Each wait goroutine writes only its own
// element of the results slice, so no mutex is needed.
type dirResult struct {
	file   string     // base name, for display
	jobID  string     // empty if the upload failed
	report *pb.Report // set by --wait on success
	err    error      // upload or wait error
}

// emlFiles lists the .eml files directly inside dir, sorted by name.
// It uses os.ReadDir instead of filepath.Glob for two reasons: Glob treats
// [ ] * ? in the directory name as pattern syntax, and it ignores I/O
// errors, so a missing directory looks the same as "no files".
func emlFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir) // already sorted by filename
	if err != nil {
		return nil, err // "no such file or directory" / "not a directory"
	}
	var files []string
	for _, e := range entries {
		// Regular files only: skips subfolders, symlinks and sockets. It's not
		// recursive on purpose: samples/ holds synthetic/ and real/, and you
		// pick which one to run.
		if e.Type().IsRegular() && strings.EqualFold(filepath.Ext(e.Name()), ".eml") {
			files = append(files, filepath.Join(dir, e.Name()))
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no .eml files in %s", dir)
	}
	return files, nil
}

func runSubmitDir(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("submit-dir", flag.ExitOnError)
	wait := fs.Bool("wait", false, "wait for every job and print a table of results")
	timeout := fs.Duration("timeout", 5*time.Minute, "limit for the whole command, uploads plus waits")

	pos := parseInterspersed(fs, args)
	if len(pos) != 1 {
		return errors.New("usage: phishcheck submit-dir <dir> [--wait]")
	}
	files, err := emlFiles(pos[0])
	if err != nil {
		return err // fails before any RPC
	}

	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	client, conn, err := dial()
	if err != nil {
		return err
	}
	defer conn.Close()

	// Phase 1: upload one file at a time. Each upload takes milliseconds
	// locally, and going in order keeps the output in directory order.
	results := make([]dirResult, len(files))
	for i, path := range files {
		results[i].file = filepath.Base(path)

		resp, err := submitFile(ctx, client, path)
		switch {
		case err == nil:
			results[i].jobID = resp.GetJobId()
			fmt.Printf("%s -> %s\n", clean(results[i].file, 80), resp.GetJobId()) // stdout: the mapping only
		case errors.Is(err, errUnreachable), ctx.Err() != nil:
			// Not this file's fault: every remaining upload would fail the
			// same way. Jobs already submitted stay queued and still run.
			// main cleans the whole message, including err's copy of the path.
			return fmt.Errorf("stopped at %s (file %d of %d): %w",
				clean(results[i].file, 80), i+1, len(files), err)
		default:
			// This file's fault (empty, unreadable, over the size cap).
			// Record it and keep going; one bad sample shouldn't sink the batch.
			results[i].err = err
			// err usually repeats the full path ("<path> is empty"), so it
			// needs clean() as much as the name does.
			fmt.Fprintf(os.Stderr, "%s -> ERROR: %s\n", clean(results[i].file, 80), clean(err.Error(), 0))
		}
	}

	if !*wait {
		return batchErr(results)
	}

	// Phase 2: wait for every job at the same time. Waiting one by one would
	// let a single stuck job use up the whole --timeout, and every job after
	// it would then report "timed out" even if it finished long ago.
	fmt.Fprintln(os.Stderr, "waiting for jobs (Ctrl+C to stop)…")
	sem := make(chan struct{}, 16) // at most 16 WatchReport streams open at once
	var wg sync.WaitGroup
	for i := range results { // Go 1.22+: each iteration gets its own i
		if results[i].err != nil {
			continue // the upload failed; there's no job to wait for
		}
		wg.Go(func() { // Go 1.25+: Add(1), go, and Done in one call
			sem <- struct{}{}        // take a slot
			defer func() { <-sem }() // give it back
			results[i].report, results[i].err = waitForReport(ctx, client, results[i].jobID, io.Discard)
		})
	}
	wg.Wait() // also what makes it safe to read results below (happens-before)

	if err := printDirTable(os.Stdout, results); err != nil {
		return err
	}
	return batchErr(results)
}

// printDirTable prints one row per file in directory order, then a summary
// on stderr of which workers did the work.
func printDirTable(w io.Writer, results []dirResult) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FILE\tVERDICT\tSCORE\tWORKER\tJOB")
	perWorker := map[string]int{}
	for _, res := range results {
		name := clean(res.file, 40)
		if res.err != nil {
			job := res.jobID
			if job == "" {
				job = "-" // the upload itself failed
			}
			fmt.Fprintf(tw, "%s\tERROR\t-\t-\t%s\n", name, job)
			continue
		}
		r := res.report
		perWorker[r.GetWorkerId()]++
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%s\n",
			name, enumName(r.GetVerdict(), "VERDICT_"), r.GetScore(), r.GetWorkerId(), res.jobID)
	}
	if err := tw.Flush(); err != nil {
		return err
	}

	// Wait errors go after the table, so long messages don't stretch its
	// columns. Upload errors were already printed in phase 1.
	for _, res := range results {
		if res.err != nil && res.jobID != "" {
			fmt.Fprintf(os.Stderr, "%s: %s\n", clean(res.file, 40), clean(res.err.Error(), 0))
		}
	}

	// The Day 6 two-replica proof: two worker names here means the consumer
	// group spread the jobs across both replicas.
	var parts []string
	for _, id := range slices.Sorted(maps.Keys(perWorker)) {
		parts = append(parts, fmt.Sprintf("%s=%d", id, perWorker[id]))
	}
	fmt.Fprintf(os.Stderr, "\n%d files, %d workers: %s\n", len(results), len(perWorker), strings.Join(parts, " "))
	return nil
}

// batchErr makes the exit code non-zero if any file failed, so a CI step
// or script running submit-dir notices.
func batchErr(results []dirResult) error {
	failed := 0
	for _, r := range results {
		if r.err != nil {
			failed++
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d files failed", failed, len(results))
	}
	return nil
}
