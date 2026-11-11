// Package api implements the PhishCheck gRPC service.
package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"

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
