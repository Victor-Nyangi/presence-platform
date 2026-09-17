package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// batchSize caps how many outbox rows one poll claims. Volume here is
// modest — roughly a thousand events a day at a five-hundred-person site —
// so this is sized for "never starve the queue," not throughput.
const batchSize = 20

// Config is everything the worker needs beyond a database pool. Loaded by
// cmd/deliver, not internal/config: the emitter is optional infrastructure
// (not every presence-platform deployment has a downstream consumer yet),
// so its settings are required only for the binary whose entire job is
// delivering — the same reason cmd/recompute reads its own DSN directly
// rather than going through the gateway's shared, all-required Config.
type Config struct {
	Endpoint     *url.URL // validated by ValidateEndpoint before this is constructed
	Secret       []byte
	KeyID        string
	PollInterval time.Duration
	HTTPTimeout  time.Duration
}

type Worker struct {
	pool    *pgxpool.Pool
	http    *http.Client
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	backoff func(attempt int) time.Duration
}

func NewWorker(pool *pgxpool.Pool, cfg Config, log *slog.Logger) *Worker {
	return &Worker{
		pool: pool, cfg: cfg, log: log,
		http: NewHTTPClient(cfg.HTTPTimeout),
		now:  time.Now, backoff: backoffFor,
	}
}

// SetClock and SetHTTPClient are test-only overrides, matching the
// injectable-clock convention api.Server and attendance.Engine already use.
func (w *Worker) SetClock(f func() time.Time)  { w.now = f }
func (w *Worker) SetHTTPClient(c *http.Client) { w.http = c }

// Run polls until ctx is cancelled. Each tick claims a batch, delivers it,
// and sleeps for PollInterval — deliberately simple polling, not LISTEN/
// NOTIFY: at this volume the extra machinery buys latency nobody asked for
// and the task explicitly said not to over-engineer for throughput.
func (w *Worker) Run(ctx context.Context) error {
	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()
	for {
		if err := w.tick(ctx); err != nil && ctx.Err() == nil {
			w.log.Error("delivery tick", "err", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

type claimedRow struct {
	id        string
	eventType string
	payload   []byte
	attempts  int
}

func (w *Worker) tick(ctx context.Context) error {
	rows, err := w.claimBatch(ctx)
	if err != nil {
		return fmt.Errorf("claim batch: %w", err)
	}
	for _, r := range rows {
		w.deliverOne(ctx, r)
	}
	return nil
}

// claimBatch marks up to batchSize due rows as 'delivering' and returns
// them. FOR UPDATE SKIP LOCKED so a second worker process (a rolling
// deploy, an operator mistake running two) never double-claims a row
// instead of racing on it — cheap insurance even though this volume needs
// exactly one worker.
func (w *Worker) claimBatch(ctx context.Context) ([]claimedRow, error) {
	tx, err := w.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	rows, err := tx.Query(ctx, `
		SELECT id::text, event_type, payload, attempts
		FROM outbox_event
		WHERE status = 'pending' AND next_attempt_at <= $1
		ORDER BY created_at
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, w.now(), batchSize)
	if err != nil {
		return nil, err
	}
	var claimed []claimedRow
	for rows.Next() {
		var r claimedRow
		if err := rows.Scan(&r.id, &r.eventType, &r.payload, &r.attempts); err != nil {
			rows.Close()
			return nil, err
		}
		claimed = append(claimed, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(claimed) == 0 {
		return nil, tx.Commit(ctx)
	}

	ids := make([]string, len(claimed))
	for i, r := range claimed {
		ids[i] = r.id
	}
	if _, err := tx.Exec(ctx, `UPDATE outbox_event SET status = 'delivering' WHERE id = ANY($1::uuid[])`, ids); err != nil {
		return nil, err
	}
	return claimed, tx.Commit(ctx)
}

func (w *Worker) deliverOne(ctx context.Context, r claimedRow) {
	err := w.send(ctx, r)
	if err == nil {
		if _, dbErr := w.pool.Exec(ctx, `
			UPDATE outbox_event SET status = 'delivered', delivered_at = $2 WHERE id = $1`,
			r.id, w.now()); dbErr != nil {
			w.log.Error("mark delivered", "event_id", r.id, "err", dbErr)
		}
		w.log.Info("delivered", "event_id", r.id, "event_type", r.eventType)
		return
	}

	attempts := r.attempts + 1
	if attempts >= MaxAttempts {
		if _, dbErr := w.pool.Exec(ctx, `
			UPDATE outbox_event SET status = 'dead', attempts = $2, last_error = $3 WHERE id = $1`,
			r.id, attempts, errMsg(err)); dbErr != nil {
			w.log.Error("mark dead", "event_id", r.id, "err", dbErr)
		}
		w.log.Error("dead-lettered", "event_id", r.id, "event_type", r.eventType, "attempts", attempts, "err", err)
		return
	}

	next := w.now().Add(w.backoff(attempts))
	if _, dbErr := w.pool.Exec(ctx, `
		UPDATE outbox_event
		SET status = 'pending', attempts = $2, next_attempt_at = $3, last_error = $4
		WHERE id = $1`,
		r.id, attempts, next, errMsg(err)); dbErr != nil {
		w.log.Error("mark pending for retry", "event_id", r.id, "err", dbErr)
	}
	w.log.Warn("delivery failed, will retry", "event_id", r.id, "attempt", attempts, "next_attempt_at", next, "err", err)
}

// send does the actual HTTP delivery. A non-2xx status and a transport
// error are both ordinary delivery failures subject to the same
// retry/backoff — including a 3xx, since NewHTTPClient never follows
// redirects (see endpoint.go).
func (w *Worker) send(ctx context.Context, r claimedRow) error {
	ts := w.now().UnixMilli()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.Endpoint.String(), bytes.NewReader(r.payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderEventID, r.id)
	req.Header.Set(HeaderEventType, r.eventType)
	req.Header.Set(HeaderSignature, SignatureHeader(w.cfg.Secret, ts, r.payload))

	resp, err := w.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Drain and discard: a consumer's response body is not part of this
	// contract (payloads carry data already; nothing here expects an ack
	// body), but leaving it unread would leak the connection instead of
	// letting the transport reuse it.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("consumer returned %d", resp.StatusCode)
	}
	return nil
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	var s string
	if errors.Is(err, context.DeadlineExceeded) {
		s = "timeout"
	} else {
		s = err.Error()
	}
	// Truncate: last_error is for operator triage, not an unbounded log
	// sink, and a misbehaving endpoint could otherwise return an enormous
	// error string.
	if len(s) > 500 {
		s = s[:500]
	}
	return s
}
