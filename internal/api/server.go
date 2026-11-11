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

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

// Server implements the PhishCheckServiceServer interface.
type Server struct {
	pb.UnimplementedPhishCheckServiceServer // by value: the generated code checks this

	store    *store.Store
	producer *queue.Producer
	maxBytes int64
}

// New builds a Server. maxBytes is PHISHCHECK_MAX_EMAIL_BYTES.
func New(st *store.Store, p *queue.Producer, maxBytes int64) *Server {
	return &Server{store: st, producer: p, maxBytes: maxBytes}
}

// Compile-time proof that Server implements the gRPC service interface.
var _ pb.PhishCheckServiceServer = (*Server)(nil)

// SubmitEmail receives a raw .eml as a client stream, enforces the size cap
// while chunks arrive, stores it, and queues a job for the workers.
func (s *Server) SubmitEmail(stream pb.PhishCheckService_SubmitEmailServer) error {
	ctx := stream.Context()

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
			return err // client cancelled or the connection dropped
		}

		if first {
			filename = req.GetFilename() // untrusted: log and store it, never use it as a path
			first = false
		}

		chunk := req.GetData()

		// Check before writing so the buffer never grows past the cap.
		if int64(buf.Len())+int64(len(chunk)) > s.maxBytes {
			slog.Warn("submission rejected: over size cap",
				"filename", filename,
				"received_bytes", buf.Len(),
				"max_bytes", s.maxBytes)
			return status.Errorf(codes.ResourceExhausted,
				"email exceeds %d byte limit", s.maxBytes)
		}

		buf.Write(chunk)
	}

	if buf.Len() == 0 {
		slog.Warn("submission rejected: empty email", "filename", filename)
		return status.Error(codes.InvalidArgument, "email is empty")
	}

	data := buf.Bytes()
	sum := sha256.Sum256(data)
	sha := hex.EncodeToString(sum[:])
	jobID := uuid.NewString()

	// Write order: email, job state, then XADD.
	// XADD is last because it is what makes the job visible to workers.
	if err := s.store.PutEmail(ctx, jobID, data); err != nil {
		slog.Error("put email failed", "job_id", jobID, "err", err)
		return status.Error(codes.Internal, "could not store email")
	}

	if err := s.store.SetJobState(ctx, jobID, pb.JobState_JOB_STATE_QUEUED, store.JobFields{
		Filename: filename,
		SHA256:   sha,
	}); err != nil {
		slog.Error("set job state failed", "job_id", jobID, "err", err)
		return status.Error(codes.Internal, "could not record job")
	}

	streamID, err := s.producer.Enqueue(ctx, jobID)
	if err != nil {
		// Known gap: the job hash says QUEUED but nothing is on the stream.
		// It expires with the TTL. Listed in the README as a limitation.
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

// pollInterval is how often WatchReport re-reads the job hash.
// Polling is fine at this scale; pub/sub would be overkill (README note).
const pollInterval = 500 * time.Millisecond

// lookupJob validates the job ID and reads the job hash, turning store
// errors into gRPC status codes. Shared by GetReport and WatchReport.
func (s *Server) lookupJob(ctx context.Context, id string) (*store.Job, error) {
	// Job IDs are UUIDs we generated. Rejecting anything else up front means
	// junk input never becomes part of a Redis key name.
	if _, err := uuid.Parse(id); err != nil {
		return nil, status.Error(codes.InvalidArgument, "job_id must be a UUID")
	}

	job, err := s.store.GetJob(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, status.Errorf(codes.NotFound, "job %s not found or expired", id)
	}
	if err != nil {
		// Client hung up mid-read: report that, not a fake server error.
		if ctx.Err() != nil {
			return nil, status.FromContextError(ctx.Err()).Err()
		}
		slog.Error("get job failed", "job_id", id, "err", err)
		return nil, status.Error(codes.Internal, "could not read job")
	}
	return job, nil
}

// toStatus converts the store's Job into the proto JobStatus.
// attempts and the timestamps get added on Day 2 (§2.2, §2.6).
func toStatus(j *store.Job) *pb.JobStatus {
	return &pb.JobStatus{
		JobId:    j.ID,
		State:    j.State,
		WorkerId: j.WorkerID,
		Error:    j.Error,
	}
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
		slog.Error("get report failed", "job_id", job.ID, "err", err)
		return nil, status.Error(codes.Internal, "could not read report")
	}

	resp.Report = report
	return resp, nil
}

// WatchReport streams a JobStatus every time the job's state changes and
// ends the stream when the job is DONE or FAILED.
func (s *Server) WatchReport(req *pb.WatchReportRequest, stream pb.PhishCheckService_WatchReportServer) error {
	ctx := stream.Context() // cancelled when the client hangs up or the server force-stops

	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop() // a ticker that is never stopped leaks

	// No real job is ever UNSPECIFIED, so the first read always sends.
	last := pb.JobState_JOB_STATE_UNSPECIFIED

	for {
		job, err := s.lookupJob(ctx, req.GetJobId())
		if err != nil {
			return err // bad ID, job expired mid-watch, or Redis error
		}

		// Only send on a change, so the client isn't flooded every 500 ms.
		if job.State != last {
			if err := stream.Send(&pb.WatchReportResponse{Status: toStatus(job)}); err != nil {
				return err // client went away
			}
			last = job.State
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
