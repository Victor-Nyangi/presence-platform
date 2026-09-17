// Command deliver drains outbox_event and pushes signed events to the
// configured downstream consumer.
//
// A separate long-running process from cmd/gateway, on purpose: cmd/gateway
// says plainly that "attendance computation, notifications and the admin UI
// live in separate services — this one must stay boring and available."
// Delivery retries, backoff sleeps and a slow or down consumer belong in a
// process whose own hiccups can never affect device ingest.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/delivery"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	dsn := os.Getenv("PRESENCE_DATABASE_URL")
	if dsn == "" {
		return fmt.Errorf("PRESENCE_DATABASE_URL is required")
	}
	cfg, err := delivery.LoadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return err
	}

	w := delivery.NewWorker(pool, cfg, log)
	log.Info("delivery worker starting", "endpoint", cfg.Endpoint.String(), "poll_interval", cfg.PollInterval)
	return w.Run(ctx)
}
