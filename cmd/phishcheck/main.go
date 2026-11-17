// Command phishcheck is the CLI client for the PhishCheck gRPC API.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

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
	// "report" and "submit-dir" land in the next checklist item.
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "phishcheck:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  phishcheck submit <file.eml> [--wait] [--timeout 3m]

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

// rpcErr turns a gRPC status into a one-line message a person can act on.
func rpcErr(err error) error {
	st, ok := status.FromError(err)
	if !ok {
		return err
	}
	switch st.Code() {
	case codes.Unavailable:
		return fmt.Errorf("API unreachable (is cmd/api running?): %s", st.Message())
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
		filepath.Base(path), resp.GetSizeBytes(), resp.GetSha256()[:12])
	fmt.Println(resp.GetJobId())

	if !*wait {
		return nil
	}
	return waitAndPrint(ctx, client, resp.GetJobId())
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

// waitAndPrint follows the job with WatchReport, prints each state change,
// then fetches the finished report with GetReport.
func waitAndPrint(ctx context.Context, client pb.PhishCheckServiceClient, jobID string) error {
	watch, err := client.WatchReport(ctx, &pb.WatchReportRequest{JobId: jobID})
	if err != nil {
		return rpcErr(err)
	}

	var last *pb.JobStatus
	for {
		msg, err := watch.Recv()
		if errors.Is(err, io.EOF) {
			break // the server closed the stream after DONE or FAILED
		}
		if err != nil {
			return fmt.Errorf("watch: %w", rpcErr(err))
		}
		last = msg.GetStatus()

		line := strings.TrimPrefix(last.GetState().String(), "JOB_STATE_")
		if w := last.GetWorkerId(); w != "" {
			line += "  worker=" + w
		}
		fmt.Fprintln(os.Stderr, line) // progress goes to stderr; Day 2 (§2.6) adds timings here
	}

	// A closed stream doesn't prove the job finished, so check the final
	// state explicitly. The generated getters are nil-safe: if no message
	// arrived, last is nil and GetState() returns UNSPECIFIED.
	switch last.GetState() {
	case pb.JobState_JOB_STATE_DONE:
		// fall through to GetReport
	case pb.JobState_JOB_STATE_FAILED:
		return fmt.Errorf("job %s failed: %s", jobID, last.GetError())
	default:
		return fmt.Errorf("watch ended with job in state %s", last.GetState())
	}

	got, err := client.GetReport(ctx, &pb.GetReportRequest{JobId: jobID})
	if err != nil {
		return fmt.Errorf("get report: %w", rpcErr(err))
	}
	if got.GetReport() == nil {
		return errors.New("job is DONE but the API returned no report") // a server bug; say so loudly
	}

	// Placeholder: the next checklist item builds the full human-readable
	// printer for `report`, and this line gets replaced with a call to it.
	r := got.GetReport()
	fmt.Printf("verdict=%s score=%d findings=%d worker=%s\n",
		strings.TrimPrefix(r.GetVerdict().String(), "VERDICT_"),
		r.GetScore(), len(r.GetFindings()), r.GetWorkerId())
	return nil
}
