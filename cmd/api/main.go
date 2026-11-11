// Command api is the PhishCheck gRPC server.
package main

import (
	"context"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
	"google.golang.org/grpc"

	pb "github.com/AidanL23/phishcheck/gen/go/phishcheck/v1"
	"github.com/AidanL23/phishcheck/internal/api"
	"github.com/AidanL23/phishcheck/internal/config"
	"github.com/AidanL23/phishcheck/internal/queue"
	"github.com/AidanL23/phishcheck/internal/store"
)

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

	slog.Info("api listening", "addr", lis.Addr().String())
	if err := srv.Serve(lis); err != nil {
		slog.Error("serve failed", "err", err)
		os.Exit(1)
	}
}
