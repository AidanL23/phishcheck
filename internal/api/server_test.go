package api

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

// Every test here builds a Server with a nil store and producer. Each path
// under test must return before it touches Redis; if one didn't, the nil
// pointer would panic and fail the test, which is the point.

func TestIsTerminal(t *testing.T) {
	want := map[pb.JobState]bool{
		pb.JobState_JOB_STATE_UNSPECIFIED: false,
		pb.JobState_JOB_STATE_QUEUED:      false,
		pb.JobState_JOB_STATE_RUNNING:     false,
		pb.JobState_JOB_STATE_DONE:        true,
		pb.JobState_JOB_STATE_FAILED:      true,
	}
	// Fails when a new state is added to the proto without a decision here.
	if len(want) != len(pb.JobState_name) {
		t.Fatalf("JobState has %d values, test covers %d", len(pb.JobState_name), len(want))
	}
	for s, w := range want {
		if got := isTerminal(s); got != w {
			t.Errorf("isTerminal(%s) = %v, want %v", s, got, w)
		}
	}
}

func TestToStatus(t *testing.T) {
	j := &store.Job{ID: "id", State: pb.JobState_JOB_STATE_FAILED, WorkerID: "w1", Error: "boom", Filename: "x.eml"}
	got := toStatus(j)
	if got.GetJobId() != "id" || got.GetState() != j.State || got.GetWorkerId() != "w1" || got.GetError() != "boom" {
		t.Errorf("toStatus = %v", got)
	}
}

func TestLookupJobRejectsNonUUID(t *testing.T) {
	s := New(nil, nil, 1)
	for _, id := range []string{
		"",
		"not-a-uuid",
		"*",
		"../../etc/passwd",
		"phishcheck:job:*",
		"00000000-0000-0000-0000-00000000000",   // one char short
		"00000000-0000-0000-0000-0000000000000", // one char long
	} {
		_, err := s.lookupJob(context.Background(), id)
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("lookupJob(%q): code %v, want InvalidArgument", id, status.Code(err))
		}
	}
}

func TestNormalizeJobID(t *testing.T) {
	const want = "6f1c2e8a-0000-4000-8000-00000000abcd"
	for _, in := range []string{
		want,
		"6F1C2E8A-0000-4000-8000-00000000ABCD", // pasted from a tool that uppercases
		"{6f1c2e8a-0000-4000-8000-00000000abcd}",
		"urn:uuid:6f1c2e8a-0000-4000-8000-00000000abcd",
		"6f1c2e8a00004000800000000000abcd",
	} {
		got, err := normalizeJobID(in)
		if err != nil || got != want {
			t.Errorf("normalizeJobID(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := normalizeJobID("nope"); status.Code(err) != codes.InvalidArgument {
		t.Errorf("bad ID: got %v", err)
	}
}

func TestGetAndWatchRejectBadID(t *testing.T) {
	s := New(nil, nil, 1)
	if _, err := s.GetReport(context.Background(), &pb.GetReportRequest{JobId: "nope"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("GetReport: %v", err)
	}
	ws := &fakeWatchServer{ctx: context.Background()}
	if err := s.WatchReport(&pb.WatchReportRequest{JobId: "nope"}, ws); status.Code(err) != codes.InvalidArgument {
		t.Errorf("WatchReport: %v", err)
	}
	if len(ws.sent) != 0 {
		t.Errorf("WatchReport sent %d messages for a bad ID", len(ws.sent))
	}
}

func TestSubmitEmailRejections(t *testing.T) {
	const max = 10
	chunk := func(name string, n int) *pb.SubmitEmailRequest {
		return &pb.SubmitEmailRequest{Filename: name, Data: make([]byte, n)}
	}
	tests := []struct {
		name     string
		reqs     []*pb.SubmitEmailRequest
		recvErr  error
		wantCode codes.Code
		wantRead int // how many messages the server should have read
	}{
		{"no messages", nil, nil, codes.InvalidArgument, 0},
		{"filename only, no data", []*pb.SubmitEmailRequest{chunk("a.eml", 0), chunk("", 0)}, nil, codes.InvalidArgument, 2},
		{"one chunk over cap", []*pb.SubmitEmailRequest{chunk("a.eml", max+1)}, nil, codes.ResourceExhausted, 1},
		{
			"cap crossed on third chunk: stops reading there",
			[]*pb.SubmitEmailRequest{chunk("a.eml", 4), chunk("", 4), chunk("", 3), chunk("", 1)},
			nil, codes.ResourceExhausted, 3,
		},
		{"client error is passed through", nil, status.Error(codes.Canceled, "gone"), codes.Canceled, 0},
		{
			"filename over 255 bytes",
			[]*pb.SubmitEmailRequest{chunk(strings.Repeat("a", maxFilenameBytes+1), 1)},
			nil, codes.InvalidArgument, 1,
		},
		{
			// Gets past the filename check (exactly 255 is fine) and is then
			// stopped by the size cap, before the nil store is touched.
			"filename of exactly 255 bytes is accepted",
			[]*pb.SubmitEmailRequest{chunk(strings.Repeat("a", maxFilenameBytes), max+1)},
			nil, codes.ResourceExhausted, 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss := &fakeSubmitServer{reqs: tt.reqs, err: tt.recvErr}
			err := New(nil, nil, max).SubmitEmail(ss)
			if status.Code(err) != tt.wantCode {
				t.Fatalf("code %v (%v), want %v", status.Code(err), err, tt.wantCode)
			}
			if ss.read != tt.wantRead {
				t.Errorf("read %d messages, want %d", ss.read, tt.wantRead)
			}
			if ss.resp != nil {
				t.Error("SendAndClose called on a rejected upload")
			}
		})
	}
}

func TestSubmitEmailUploadTimeout(t *testing.T) {
	// A client that opens the stream and never finishes. Recv blocks until
	// the stream's context ends, as it does in gRPC.
	ctx, endRPC := context.WithCancel(context.Background())
	ss := &stalledSubmitServer{ctx: ctx, returned: make(chan struct{})}
	s := New(nil, nil, 10)
	s.uploadTimeout = 20 * time.Millisecond

	start := time.Now()
	err := s.SubmitEmail(ss)
	if status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("got %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %s; the timeout is 20ms", d)
	}

	// gRPC cancels the stream once the handler returns. The receive
	// goroutine must then exit, not leak.
	endRPC()
	select {
	case <-ss.returned:
	case <-time.After(time.Second):
		t.Fatal("receive goroutine still blocked after the RPC ended")
	}
}

// After the upload, the client hangs up before the Redis writes finish.
// That is a Canceled, not an Internal server fault, and not an ERROR log.
func TestSubmitEmailClientCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A real client, but go-redis checks the context before it takes a
	// connection, so with ctx already cancelled nothing is dialed.
	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	defer rdb.Close()
	st, err := store.New(rdb, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	defer slog.SetDefault(old)

	ss := &fakeSubmitServer{ctx: ctx, reqs: []*pb.SubmitEmailRequest{{Filename: "a.eml", Data: []byte("x")}}}
	err = New(st, queue.NewProducer(rdb), 10).SubmitEmail(ss)
	if status.Code(err) != codes.Canceled {
		t.Errorf("got %v, want Canceled", err)
	}
	if strings.Contains(logs.String(), `"level":"ERROR"`) {
		t.Errorf("a client hang-up was logged as a server error:\n%s", logs.String())
	}
}

// stalledSubmitServer's Recv blocks until ctx ends, then reports it.
type stalledSubmitServer struct {
	grpc.ServerStream
	ctx      context.Context
	returned chan struct{}
}

func (f *stalledSubmitServer) Context() context.Context { return f.ctx }

func (f *stalledSubmitServer) Recv() (*pb.SubmitEmailRequest, error) {
	<-f.ctx.Done()
	close(f.returned)
	return nil, status.FromContextError(f.ctx.Err()).Err()
}

func (f *stalledSubmitServer) SendAndClose(*pb.SubmitEmailResponse) error { return nil }

// fakeSubmitServer feeds SubmitEmail a fixed list of messages, then io.EOF
// (or err, if set).
type fakeSubmitServer struct {
	grpc.ServerStream                 // nil; only the methods below are called
	ctx               context.Context // nil means context.Background()
	reqs              []*pb.SubmitEmailRequest
	err               error
	read              int
	resp              *pb.SubmitEmailResponse
}

func (f *fakeSubmitServer) Context() context.Context {
	if f.ctx != nil {
		return f.ctx
	}
	return context.Background()
}

func (f *fakeSubmitServer) Recv() (*pb.SubmitEmailRequest, error) {
	if f.read == len(f.reqs) {
		if f.err != nil {
			return nil, f.err
		}
		return nil, io.EOF
	}
	r := f.reqs[f.read]
	f.read++
	return r, nil
}

func (f *fakeSubmitServer) SendAndClose(r *pb.SubmitEmailResponse) error {
	f.resp = r
	return nil
}

type fakeWatchServer struct {
	grpc.ServerStream
	ctx  context.Context
	sent []*pb.WatchReportResponse
}

func (f *fakeWatchServer) Context() context.Context { return f.ctx }

func (f *fakeWatchServer) Send(m *pb.WatchReportResponse) error {
	f.sent = append(f.sent, m)
	return nil
}
