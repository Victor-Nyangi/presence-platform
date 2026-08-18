// Command gateway is the device-facing HTTPS ingest service.
//
// It does one job: accept signed traffic from terminals, resolve it against
// the roster, and store it durably. Attendance computation, notifications and
// the admin UI live in separate services — this one must stay boring and
// available, because when it is down, terminals buffer and people still need
// to clock in.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/api"
	"presence/internal/auth"
	"presence/internal/config"
	"presence/internal/cryptobox"
	"presence/internal/store"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	keyring, err := cryptobox.NewKeyring(cfg.KEKPrimaryID, cfg.KEKs)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return err
	}
	poolCfg.MaxConns = 20
	poolCfg.MaxConnLifetime = time.Hour

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		return err
	}

	st := store.New(pool, keyring, cfg.TokenPepper)
	srv := api.NewServer(st, auth.NewMemoryNonceCache(), log)

	httpSrv := &http.Server{
		Addr:         cfg.Addr,
		Handler:      srv.Routes(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("gateway listening", "addr", cfg.Addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		// Graceful drain: a terminal mid-upload should finish its batch
		// rather than have to retry the whole thing.
		log.Info("shutting down", "grace", cfg.ShutdownGrace)
		shutCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownGrace)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}
