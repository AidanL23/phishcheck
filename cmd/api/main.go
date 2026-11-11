// Command api is the PhishCheck gRPC server.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/api"
	"github.com/AidanL23/phishcheck/internal/config"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

// shutdownTimeout is how long in-flight RPCs get to finish before we force-stop.
// Docker sends SIGKILL 10 s after SIGTERM by default, so stay under that.
const shutdownTimeout = 5 * time.Second

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	slog.Info("starting api", "config", cfg) // your LogValue redacts the password

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
	})

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	err = rdb.Ping(pingCtx).Err()
	cancel()
	if err != nil {
		slog.Error("redis unreachable", "addr", cfg.RedisAddr, "err", err)
		os.Exit(1)
	}

	st, err := store.New(rdb, cfg.TTL)
	if err != nil {
		slog.Error("store setup failed", "err", err)
		os.Exit(1)
	}

	lis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		slog.Error("listen failed", "addr", cfg.GRPCAddr, "err", err)
		os.Exit(1)
	}

	srv := grpc.NewServer()
	pb.RegisterPhishCheckServiceServer(srv, api.New(st, queue.NewProducer(rdb), cfg.MaxEmailBytes))

	// Reflection lets grpcurl discover the service without the .proto file.
	// It publishes the whole API schema to anyone who can connect: fine for a
	// local, unauthenticated dev server; gate it behind a flag before exposing this anywhere.
	reflection.Register(srv)

	// ctx is cancelled on Ctrl-C (SIGINT) or `docker stop` (SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Serve blocks, so run it in a goroutine and report back on a channel.
	// Buffered (size 1) so the goroutine can always exit, even if nobody reads.
	serveErr := make(chan error, 1)
	go func() {
		slog.Info("api listening", "addr", lis.Addr().String())
		serveErr <- srv.Serve(lis)
	}()

	select {
	case err := <-serveErr:
		// Serve only returns nil after Stop/GracefulStop, so getting here means a real failure.
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	case <-ctx.Done():
		stop() // restore default signal handling: a second Ctrl-C kills immediately
		slog.Info("shutdown signal received, draining")
	}

	// GracefulStop refuses new RPCs and waits for running ones to finish.
	// A WatchReport on a job that never finishes would make it wait forever,
	// so after shutdownTimeout we force it with Stop, which cancels every RPC's context.
	done := make(chan struct{})
	go func() {
		srv.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
		slog.Info("api stopped cleanly")
	case <-time.After(shutdownTimeout):
		slog.Warn("graceful stop timed out, forcing", "timeout", shutdownTimeout)
		srv.Stop()
		<-done // GracefulStop returns once Stop has closed everything
	}

	// Close Redis last, after no RPC can still be using it.
	if err := rdb.Close(); err != nil {
		slog.Warn("redis close failed", "err", err)
	}
}
