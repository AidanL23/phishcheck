package api

import (
	"context"
	"io"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
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
