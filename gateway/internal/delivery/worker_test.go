//go:build integration

package delivery

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const testOrgID = "11111111-1111-1111-1111-111111111111"

type fixture struct {
	pool *pgxpool.Pool
	w    *Worker
	now  time.Time
}

func setup(t *testing.T, endpoint *httptest.Server) *fixture {
	t.Helper()
	dsn := os.Getenv("PRESENCE_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("PRESENCE_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	for _, stmt := range []string{
		`TRUNCATE outbox_event, organization CASCADE`,
		`INSERT INTO organization (id, name, kind) VALUES ('` + testOrgID + `', 'Test Org', 'office')`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup: %v\n%s", err, stmt)
		}
	}
	t.Cleanup(func() { pool.Close() })

	u, err := url.Parse(endpoint.URL)
	if err != nil {
		t.Fatalf("bad test endpoint URL: %v", err)
	}
	cfg := Config{
		Endpoint: u, Secret: []byte("test-secret"), KeyID: "k1",
		PollInterval: 10 * time.Millisecond, HTTPTimeout: 2 * time.Second,
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	w := NewWorker(pool, cfg, log)
	now := time.Now()
	w.SetClock(func() time.Time { return now })

	return &fixture{pool: pool, w: w, now: now}
}

func (f *fixture) insertEvent(t *testing.T, eventType string) string {
	t.Helper()
	var id string
	// next_attempt_at is set explicitly in the past rather than left to
	// its now() default: the worker's clock in these tests is frozen at
	// fixture setup, strictly before this INSERT executes, so a
	// database-clock default would sometimes land after the frozen clock
	// and the row would look "not due yet" through no fault of the code
	// under test.
	err := f.pool.QueryRow(context.Background(), `
		INSERT INTO outbox_event (org_id, event_type, person_id, business_date, payload, next_attempt_at)
		VALUES ($1,$2,NULL,'2026-08-18','{"hello":"world"}','2000-01-01T00:00:00Z')
		RETURNING id::text`, testOrgID, eventType).Scan(&id)
	if err != nil {
		t.Fatalf("insert outbox event: %v", err)
	}
	return id
}

func (f *fixture) row(t *testing.T, id string) (status string, attempts int, nextAttemptAt time.Time, lastErr *string) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(), `
		SELECT status::text, attempts, next_attempt_at, last_error FROM outbox_event WHERE id = $1`, id).
		Scan(&status, &attempts, &nextAttemptAt, &lastErr)
	if err != nil {
		t.Fatalf("read row: %v", err)
	}
	return
}

func TestWorkerDeliversAndMarksDelivered(t *testing.T) {
	var gotBody []byte
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := setup(t, srv)
	id := f.insertEvent(t, "attendance_day.upserted")

	if err := f.w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	status, attempts, _, lastErr := f.row(t, id)
	if status != "delivered" {
		t.Errorf("status = %s, want delivered", status)
	}
	if attempts != 0 {
		t.Errorf("attempts = %d, want 0 (delivered on the first try)", attempts)
	}
	if lastErr != nil {
		t.Errorf("last_error = %v, want nil", lastErr)
	}
	// Compare parsed, not raw bytes: the payload round-trips through
	// Postgres jsonb, which re-serialises with its own text formatting
	// (spaces after ':' and ',') rather than preserving the exact bytes
	// that were inserted.
	var got, want map[string]any
	json.Unmarshal(gotBody, &got)
	json.Unmarshal([]byte(`{"hello":"world"}`), &want)
	if got["hello"] != want["hello"] {
		t.Errorf("consumer received body %q, want the stored payload", gotBody)
	}
	if gotHeaders.Get(HeaderEventID) != id {
		t.Errorf("X-Presence-Event-Id = %q, want %q", gotHeaders.Get(HeaderEventID), id)
	}
	if gotHeaders.Get(HeaderEventType) != "attendance_day.upserted" {
		t.Errorf("X-Presence-Event-Type = %q", gotHeaders.Get(HeaderEventType))
	}
	sig := gotHeaders.Get(HeaderSignature)
	if sig == "" || !VerifySignatureHeader([]byte("test-secret"), sig, gotBody) {
		t.Errorf("signature header %q did not verify against the body actually sent", sig)
	}
}

func TestWorkerRetriesOnFailureWithBackoff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := setup(t, srv)
	id := f.insertEvent(t, "attendance_day.upserted")

	if err := f.w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	status, attempts, next, lastErr := f.row(t, id)
	if status != "pending" {
		t.Errorf("status = %s, want pending (still under MaxAttempts)", status)
	}
	if attempts != 1 {
		t.Errorf("attempts = %d, want 1", attempts)
	}
	if lastErr == nil || *lastErr == "" {
		t.Error("last_error must be recorded")
	}
	// Within a millisecond, not exactly equal: timestamptz stores
	// microsecond precision, Go's time.Time carries nanoseconds, so an
	// exact comparison would fail on precision alone rather than on
	// anything the code under test got wrong.
	wantNext := f.now.Add(backoffFor(1))
	if d := next.Sub(wantNext); d < -time.Millisecond || d > time.Millisecond {
		t.Errorf("next_attempt_at = %v, want %v (now + backoffFor(1))", next, wantNext)
	}

	// A retry before next_attempt_at must not be picked up.
	if err := f.w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	_, attempts2, _, _ := f.row(t, id)
	if attempts2 != 1 {
		t.Errorf("attempts after an early tick = %d, want still 1 (not yet due)", attempts2)
	}
}

func TestWorkerDeadLettersAfterMaxAttempts(t *testing.T) {
	var calls int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	f := setup(t, srv)
	id := f.insertEvent(t, "attendance_day.upserted")

	// Fast-forward: after each failing tick, jump the clock past
	// next_attempt_at so the next tick picks it straight back up, rather
	// than sleeping through the real backoff schedule in a test.
	clock := f.now
	f.w.SetClock(func() time.Time { return clock })

	for i := 0; i < MaxAttempts; i++ {
		if err := f.w.tick(context.Background()); err != nil {
			t.Fatalf("tick %d: %v", i, err)
		}
		clock = clock.Add(6 * time.Minute)
		f.w.SetClock(func() time.Time { return clock })
	}

	status, attempts, _, lastErr := f.row(t, id)
	if status != "dead" {
		t.Errorf("status = %s, want dead after %d attempts", status, MaxAttempts)
	}
	if attempts != MaxAttempts {
		t.Errorf("attempts = %d, want %d", attempts, MaxAttempts)
	}
	if lastErr == nil {
		t.Error("a dead-lettered event must keep its last error for operator triage")
	}
	if int(atomic.LoadInt64(&calls)) != MaxAttempts {
		t.Errorf("consumer received %d requests, want exactly %d (no extra attempt after dead-lettering)", calls, MaxAttempts)
	}

	// Dead events are not retried by further ticks.
	if err := f.w.tick(context.Background()); err != nil {
		t.Fatalf("extra tick: %v", err)
	}
	if int(atomic.LoadInt64(&calls)) != MaxAttempts {
		t.Error("a dead event must not be picked up by a later tick")
	}
}

func TestWorkerTreatsRedirectAsFailureRatherThanFollowingIt(t *testing.T) {
	var followed int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&followed, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	f := setup(t, redirector)
	id := f.insertEvent(t, "attendance_day.upserted")

	if err := f.w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}

	if atomic.LoadInt64(&followed) != 0 {
		t.Error("the worker's HTTP client must never follow a redirect")
	}
	status, attempts, _, _ := f.row(t, id)
	if status != "pending" || attempts != 1 {
		t.Errorf("a 302 must be treated as an ordinary delivery failure, got status=%s attempts=%d", status, attempts)
	}
}
