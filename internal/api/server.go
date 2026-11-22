// Package api implements the PhishCheck gRPC service.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

// Server implements the PhishCheckServiceServer interface.
type Server struct {
	pb.UnimplementedPhishCheckServiceServer // by value: the generated code checks this

	store         *store.Store
	producer      *queue.Producer
	maxBytes      int64
	uploadTimeout time.Duration // tests shorten it
}

const (
	// defaultUploadTimeout bounds one SubmitEmail stream, first chunk to last.
	// 25 MB in 2 minutes is under 2 Mbit/s, far slower than any real client.
	// It exists so a client that sends part of an email and then stalls
	// can't hold up to maxBytes of server memory forever.
	defaultUploadTimeout = 2 * time.Minute

	// maxFilenameBytes caps the client's filename, which is stored, logged
	// and copied into the report but isn't counted toward maxBytes. 255 is
	// the usual filesystem limit for one path element.
	maxFilenameBytes = 255
)

// New builds a Server. maxBytes is PHISHCHECK_MAX_EMAIL_BYTES.
func New(st *store.Store, p *queue.Producer, maxBytes int64) *Server {
	return &Server{store: st, producer: p, maxBytes: maxBytes, uploadTimeout: defaultUploadTimeout}
}

// Compile-time proof that Server implements the gRPC service interface.
var _ pb.PhishCheckServiceServer = (*Server)(nil)

// SubmitEmail receives a raw .eml as a client stream, enforces the size cap
// while chunks arrive, stores it, and queues a job for the workers.
func (s *Server) SubmitEmail(stream pb.PhishCheckService_SubmitEmailServer) error {
	ctx := stream.Context()

	// Recv can't take a deadline, so it runs in its own goroutine and the
	// handler waits for it or for uploadTimeout, whichever comes first.
	// Returning from the handler ends the RPC and cancels the stream, which
	// makes a blocked Recv return, so the goroutine never outlives the RPC.
	got := make(chan upload, 1) // buffered: the goroutine can always send and exit
	go func() { got <- s.receive(stream) }()

	timer := time.NewTimer(s.uploadTimeout)
	defer timer.Stop()

	var u upload
	select {
	case u = <-got:
	case <-timer.C:
		slog.Warn("submission rejected: upload too slow", "timeout", s.uploadTimeout)
		return status.Errorf(codes.DeadlineExceeded, "upload not finished within %s", s.uploadTimeout)
	}
	if u.err != nil {
		return u.err
	}
	data, filename := u.data, u.filename

	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	jobID := uuid.NewString()

	// Write order: email, job state, then XADD.
	// XADD is last because it is what makes the job visible to workers.
	if err := s.store.PutEmail(ctx, jobID, data); err != nil {
		if cerr := canceledStatus(ctx); cerr != nil {
			return cerr
		}
		slog.Error("put email failed", "job_id", jobID, "err", err)
		return status.Error(codes.Internal, "could not store email")
	}

	if err := s.store.SetJobState(ctx, jobID, pb.JobState_JOB_STATE_QUEUED, store.JobFields{
		Filename: filename,
		SHA256:   sha,
	}); err != nil {
		if cerr := canceledStatus(ctx); cerr != nil {
			return cerr
		}
		slog.Error("set job state failed", "job_id", jobID, "err", err)
		return status.Error(codes.Internal, "could not record job")
	}

	streamID, err := s.producer.Enqueue(ctx, jobID)
	if err != nil {
		// Known gap: the job hash says QUEUED but nothing is on the stream.
		// It expires with the TTL. Listed in the README under Known limitations.
		if cerr := canceledStatus(ctx); cerr != nil {
			return cerr
		}
		slog.Error("enqueue failed", "job_id", jobID, "err", err)
		return status.Error(codes.Internal, "could not enqueue job")
	}

	slog.Info("email queued",
		"job_id", jobID,
		"stream_id", streamID,
		"filename", filename,
		"size_bytes", len(data),
		"sha256", sha)

	return stream.SendAndClose(&pb.SubmitEmailResponse{
		JobId:     jobID,
		Sha256:    sha,
		SizeBytes: int64(len(data)),
	})
}

// upload is what receive got from one SubmitEmail stream.
type upload struct {
	filename string
	data     []byte
	err      error // a gRPC status, or the stream's own error
}

// receive reads the client stream to the end, enforcing the filename and
// size caps while chunks arrive. It only touches its own buffer, so it is
// safe to abandon when SubmitEmail times out.
func (s *Server) receive(stream pb.PhishCheckService_SubmitEmailServer) upload {
	var (
		buf      bytes.Buffer
		filename string
		first    = true
	)

	for {
		req, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break // client finished sending
		}
		if err != nil {
			return upload{err: err} // client cancelled or the connection dropped
		}

		if first {
			// Untrusted: log and store it, never use it as a path. slog's JSON
			// escapes C0 controls in it, but not bidi overrides or C1 controls,
			// so raw `docker compose logs` output isn't terminal-safe either.
			filename = req.GetFilename()
			first = false
			if len(filename) > maxFilenameBytes {
				// Don't log the name itself: it's the oversized thing.
				slog.Warn("submission rejected: filename too long",
					"filename_bytes", len(filename), "max_bytes", maxFilenameBytes)
				return upload{err: status.Errorf(codes.InvalidArgument,
					"filename exceeds %d bytes", maxFilenameBytes)}
			}
		}

		chunk := req.GetData()

		// Check before writing so the buffer never grows past the cap.
		if int64(buf.Len())+int64(len(chunk)) > s.maxBytes {
			slog.Warn("submission rejected: over size cap",
				"filename", filename,
				"received_bytes", buf.Len(),
				"max_bytes", s.maxBytes)
			return upload{err: status.Errorf(codes.ResourceExhausted,
				"email exceeds %d byte limit", s.maxBytes)}
		}

		buf.Write(chunk)
	}

	if buf.Len() == 0 {
		slog.Warn("submission rejected: empty email", "filename", filename)
		return upload{err: status.Error(codes.InvalidArgument, "email is empty")}
	}
	return upload{filename: filename, data: buf.Bytes()}
}

// canceledStatus returns the gRPC status for a client that hung up or ran
// out of time, or nil if ctx is still live. Handlers check it before turning
// a store error into Internal, so a hang-up isn't logged as a server fault.
func canceledStatus(ctx context.Context) error {
	if ctx.Err() == nil {
		return nil
	}
	return status.FromContextError(ctx.Err()).Err()
}

// pollInterval is how often WatchReport re-reads the job hash.
// Polling is fine at this scale; pub/sub would be overkill (README, Known limitations).
const pollInterval = 500 * time.Millisecond

// normalizeJobID checks that id is a UUID and returns it in the lowercase,
// dashed form the API generates. uuid.Parse also accepts uppercase,
// {braces}, urn:uuid: and 32 bare hex digits. Normalizing means all of
// those find the job, and only the canonical form ever becomes part of a
// Redis key name.
func normalizeJobID(id string) (string, error) {
	u, err := uuid.Parse(id)
	if err != nil {
		return "", status.Error(codes.InvalidArgument, "job_id must be a UUID")
	}
	return u.String(), nil
}

// lookupJob validates the job ID and reads the job hash, turning store
// errors into gRPC status codes. Shared by GetReport and WatchReport.
func (s *Server) lookupJob(ctx context.Context, id string) (*store.Job, error) {
	id, err := normalizeJobID(id)
	if err != nil {
		return nil, err
	}

	job, err := s.store.GetJob(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "job %s not found or expired", id)
	}
	if err != nil {
		// Client hung up mid-read: report that, not a fake server error.
		if cerr := canceledStatus(ctx); cerr != nil {
			return nil, cerr
		}
		slog.Error("get job failed", "job_id", id, "err", err)
		return nil, status.Error(codes.Internal, "could not read job")
	}
	return job, nil
}

// toStatus converts the store's Job into the proto JobStatus.
func toStatus(j *store.Job) *pb.JobStatus {
	return &pb.JobStatus{
		JobId:       j.ID,
		State:       j.State,
		WorkerId:    j.WorkerID,
		Attempts:    j.Attempts,
		Error:       j.Error,
		SubmittedAt: timestamp(j.SubmittedAt),
		StartedAt:   timestamp(j.StartedAt),
		FinishedAt:  timestamp(j.FinishedAt),
	}
}

// timestamp leaves a zero Time unset (nil). timestamppb.New(time.Time{})
// would send year 1 instead of "not set", and the CLI couldn't tell a
// missing time from a real one.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// isTerminal reports whether a job will never change state again.
func isTerminal(s pb.JobState) bool {
	return s == pb.JobState_JOB_STATE_DONE || s == pb.JobState_JOB_STATE_FAILED
}

// GetReport returns the job's status, plus the report once the job is DONE.
func (s *Server) GetReport(ctx context.Context, req *pb.GetReportRequest) (*pb.GetReportResponse, error) {
	job, err := s.lookupJob(ctx, req.GetJobId())
	if err != nil {
		return nil, err // already a gRPC status
	}

	resp := &pb.GetReportResponse{Status: toStatus(job)}

	// QUEUED, RUNNING and FAILED are normal answers, not errors:
	// the client gets the status and decides what to do.
	if job.State != pb.JobState_JOB_STATE_DONE {
		return resp, nil
	}

	report, err := s.store.GetReport(ctx, job.ID)
	if errors.Is(err, store.ErrNotFound) {
		// The worker (§1.7) writes the report before marking DONE, so this only
		// happens if the report key expired just before the job hash did.
		slog.Warn("job done but report missing", "job_id", job.ID)
		return nil, status.Errorf(codes.NotFound, "report for job %s missing or expired", job.ID)
	}
	if err != nil {
		if cerr := canceledStatus(ctx); cerr != nil {
			return nil, cerr
		}
		slog.Error("get report failed", "job_id", job.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not read report")
	}

	resp.Report = report
	return resp, nil
}

// WatchReport streams a JobStatus on every state or attempt change and ends
// ends the stream when the job is DONE or FAILED.
func (s *Server) WatchReport(req *pb.WatchReportRequest, stream pb.PhishCheckService_WatchReportServer) error {
	ctx := stream.Context() // cancelled when the client hangs up or the server force-stops

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop() // a ticker that is never stopped leaks

	// No real job is ever UNSPECIFIED, so the first read always sends.
	last := pb.JobState_JOB_STATE_UNSPECIFIED
	lastAttempts := int32(0)

	for {
		job, err := s.lookupJob(ctx, req.GetJobId())
		if err != nil {
			return err // bad ID, job expired mid-watch, or Redis error
		}

		// Send on a state or attempt change, not every 500 ms. A reclaim keeps
		// the job RUNNING but bumps attempts, and the client should see it.
		if job.State != last || job.Attempts != lastAttempts {
			if err := stream.Send(&pb.WatchReportResponse{Status: toStatus(job)}); err != nil {
				return err // client went away
			}
			last, lastAttempts = job.State, job.Attempts
		}

		// Returning nil closes the stream cleanly: "nothing more is coming".
		if isTerminal(job.State) {
			return nil
		}

		// Wait for the next tick, but wake up immediately if the client cancels.
		select {
		case <-ctx.Done():
			return status.FromContextError(ctx.Err()).Err()
		case <-ticker.C:
		}
	}
}
