//go:build integration

// End-to-end tests against a real PostgreSQL instance and the real HTTP
// stack. These assert the behaviours the whole design exists to guarantee,
// not the shape of individual functions.
//
//	PRESENCE_TEST_DATABASE_URL=postgres://... go test -tags integration ./...
package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/auth"
	"presence/internal/cryptobox"
	"presence/internal/model"
	"presence/internal/store"
)

const (
	orgID    = "11111111-1111-1111-1111-111111111111"
	siteID   = "22222222-2222-2222-2222-222222222222"
	ashaID   = "33333333-3333-3333-3333-333333333333"
	brianID  = "44444444-4444-4444-4444-444444444444"
	deviceID = "55555555-5555-5555-5555-555555555555"
	credA    = "66666666-6666-6666-6666-666666666666"
	credB    = "77777777-7777-7777-7777-777777777777"
)

var deviceSecret = []byte("0123456789abcdef0123456789abcdef")

type harness struct {
	srv    *httptest.Server
	pool   *pgxpool.Pool
	now    time.Time
	nonces int
}

func setup(t *testing.T, mode string) *harness {
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

	// Each test gets a clean slate. Order matters for FK constraints, and
	// punch_event is append-only so it needs the trigger disabled to clear.
	for _, stmt := range []string{
		`ALTER TABLE punch_event DISABLE TRIGGER punch_event_no_mutation`,
		`TRUNCATE punch_amendment, attendance_span, attendance_day, notification,
		          sync_batch, device_command, punch_event, device_slot, credential,
		          guardian_person, guardian, device, person, site, organization CASCADE`,
		`ALTER TABLE punch_event ENABLE TRIGGER punch_event_no_mutation`,
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("reset: %v", err)
		}
	}

	kek, _ := hex.DecodeString("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
	keyring, err := cryptobox.NewKeyring("k1", map[string][]byte{"k1": kek})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	encSecret, nonce, keyID, err := keyring.Seal(deviceSecret, []byte(deviceID))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	seed := []string{
		fmt.Sprintf(`INSERT INTO organization (id,name,kind) VALUES ('%s','Test School','school')`, orgID),
		fmt.Sprintf(`INSERT INTO site (id,org_id,name) VALUES ('%s','%s','Main Gate')`, siteID, orgID),
		fmt.Sprintf(`INSERT INTO person (id,org_id,kind,external_ref,full_name) VALUES
			('%s','%s','staff','EMP-001','Asha M.'), ('%s','%s','staff','EMP-002','Brian K.')`,
			ashaID, orgID, brianID, orgID),
		fmt.Sprintf(`INSERT INTO credential (id,org_id,person_id,kind,template_ciphertext,template_nonce,template_key_id,template_vendor)
			VALUES ('%s','%s','%s','fingerprint','\xdead','\x0102030405060708090a0b0c','k1','grow_r307'),
			       ('%s','%s','%s','fingerprint','\xbeef','\x0102030405060708090a0b0c','k1','grow_r307')`,
			credA, orgID, ashaID, credB, orgID, brianID),
	}
	for _, q := range seed {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v\n%s", err, q)
		}
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO device (id,org_id,site_id,label,serial,mode,state,secret_enc,secret_nonce,secret_key_id,key_version)
		VALUES ($1,$2,$3,'Gate 1','SN-0001',$4::device_mode,'active',$5,$6,$7,1)`,
		deviceID, orgID, siteID, mode, encSecret, nonce, keyID); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	st := store.New(pool, keyring, []byte("pepper"))
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	api := NewServer(st, auth.NewMemoryNonceCache(), log)

	h := &harness{pool: pool, now: time.Now().UTC().Truncate(time.Millisecond)}
	api.SetClock(func() time.Time { return h.now })
	h.srv = httptest.NewServer(api.Routes())
	t.Cleanup(func() { h.srv.Close(); pool.Close() })
	return h
}

// bindSlot gives a device slot to a person for a validity window.
func (h *harness) bindSlot(t *testing.T, slot int, credID, personID string, from time.Time, to *time.Time) {
	t.Helper()
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO device_slot (device_id, slot_no, credential_id, person_id, valid_from, valid_to)
		VALUES ($1,$2,$3,$4,$5,$6)`, deviceID, slot, credID, personID, from, to); err != nil {
		t.Fatalf("bind slot: %v", err)
	}
}

// do signs and sends a request exactly as the firmware would.
func (h *harness) do(t *testing.T, method, path string, body any, clockOffset time.Duration) (int, []byte) {
	t.Helper()
	var raw []byte
	if body != nil {
		var err error
		raw, err = json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
	}
	deviceClock := h.now.Add(clockOffset)
	h.nonces++
	nonce := "nonce-" + strconv.Itoa(h.nonces)

	req, err := http.NewRequest(method, h.srv.URL+path, bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set(auth.HeaderDeviceID, deviceID)
	req.Header.Set(auth.HeaderKeyVersion, "1")
	req.Header.Set(auth.HeaderTimestamp, strconv.FormatInt(deviceClock.UnixMilli(), 10))
	req.Header.Set(auth.HeaderNonce, nonce)
	// Note: the signature covers the path WITHOUT the query string.
	sigPath := path
	if i := bytes.IndexByte([]byte(path), '?'); i >= 0 {
		sigPath = path[:i]
	}
	req.Header.Set(auth.HeaderSignature,
		auth.Sign(deviceSecret, method, sigPath, deviceClock.UnixMilli(), nonce, raw))

	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, out
}

func (h *harness) postEvents(t *testing.T, req model.EventsRequest) model.EventsResponse {
	t.Helper()
	code, body := h.do(t, "POST", "/v1/device/events", req, 0)
	if code != http.StatusOK {
		t.Fatalf("events: status %d body %s", code, body)
	}
	var r model.EventsResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v (%s)", err, body)
	}
	return r
}

func ev(seq int64, slot int, at time.Time) model.PunchEvent {
	s := slot
	return model.PunchEvent{
		Seq:            seq,
		EventUUID:      fmt.Sprintf("00000000-0000-4000-8000-%012d", seq),
		CapturedAt:     at,
		TimeSource:     model.TimeRTCSynced,
		CredentialKind: model.CredFingerprint,
		SlotNo:         &s,
		DirectionHint:  model.DirUnknown,
	}
}

// ---------------------------------------------------------------------

func TestHappyPathPunchResolves(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	r := h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000001",
		Events:    []model.PunchEvent{ev(1, 42, h.now.Add(-time.Minute))},
	})
	if len(r.Accepted) != 1 || r.AckThrough != 1 {
		t.Fatalf("want 1 accepted and ack 1, got %+v", r)
	}

	var status, direction, person string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT status::text, direction::text, person_id::text FROM punch_event WHERE device_seq=1`).
		Scan(&status, &direction, &person); err != nil {
		t.Fatalf("query: %v", err)
	}
	if status != "resolved" || person != brianID {
		t.Errorf("status=%s person=%s", status, person)
	}
	if direction != "in" {
		t.Errorf("first punch of the day should be 'in', got %q", direction)
	}
}

// Replaying a batch whose ack was lost on the wire must not create a second
// attendance record.
func TestReplayIsIdempotent(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	batch := model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000002",
		Events:    []model.PunchEvent{ev(1, 42, h.now.Add(-time.Minute))},
	}
	first := h.postEvents(t, batch)
	second := h.postEvents(t, batch)

	if len(first.Accepted) != 1 {
		t.Fatalf("first: %+v", first)
	}
	if len(second.Duplicates) != 1 || len(second.Accepted) != 0 {
		t.Fatalf("second should be all duplicates, got %+v", second)
	}
	if second.AckThrough != 1 {
		t.Errorf("duplicates must still advance the ack, got %d", second.AckThrough)
	}

	var n int
	h.pool.QueryRow(context.Background(), `SELECT count(*) FROM punch_event`).Scan(&n)
	if n != 1 {
		t.Fatalf("want exactly 1 stored event, got %d", n)
	}
}

// The regression this whole ack design exists to prevent: an event the server
// cannot resolve must be stored, must be reported as rejected, and must NOT
// block the events queued behind it.
func TestPoisonEventDoesNotWedgeTheBuffer(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	r := h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000003",
		Events: []model.PunchEvent{
			ev(1, 42, h.now.Add(-3*time.Minute)),  // fine
			ev(2, 999, h.now.Add(-2*time.Minute)), // unknown slot
			ev(3, 42, h.now.Add(-1*time.Minute)),  // fine, queued behind the poison
		},
	})

	if len(r.Rejected) != 1 || r.Rejected[0].Seq != 2 || r.Rejected[0].Reason != model.ReasonUnknownSlot {
		t.Fatalf("want seq 2 rejected as unknown_slot, got %+v", r.Rejected)
	}
	if r.AckThrough != 3 {
		t.Fatalf("ack must advance past the poison event, got %d", r.AckThrough)
	}

	var total, unresolved int
	ctx := context.Background()
	h.pool.QueryRow(ctx, `SELECT count(*) FROM punch_event`).Scan(&total)
	h.pool.QueryRow(ctx, `SELECT count(*) FROM punch_event WHERE status='unresolved'`).Scan(&unresolved)
	if total != 3 {
		t.Errorf("rejected != discarded: want 3 rows stored, got %d", total)
	}
	if unresolved != 1 {
		t.Errorf("want 1 unresolved row retained for triage, got %d", unresolved)
	}
}

// A punch taken while the network was down keeps its original capture time,
// and is flagged as backfilled rather than stamped with the upload time.
func TestOfflineBackfillPreservesCaptureTime(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-48*time.Hour), nil)

	captured := h.now.Add(-6 * time.Hour).Truncate(time.Second)
	h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000004",
		Events:    []model.PunchEvent{ev(1, 42, captured)},
	})

	var effective time.Time
	var backfilled bool
	var conf string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT effective_at, is_backfilled, time_conf::text FROM punch_event WHERE device_seq=1`).
		Scan(&effective, &backfilled, &conf); err != nil {
		t.Fatalf("query: %v", err)
	}
	if !effective.UTC().Equal(captured.UTC()) {
		t.Errorf("effective_at = %v, want the original capture time %v", effective.UTC(), captured.UTC())
	}
	if !backfilled {
		t.Error("event uploaded 6h late should be flagged is_backfilled")
	}
	if conf != "high" {
		t.Errorf("rtc_synced should stay high confidence, got %q", conf)
	}
}

// With a dead RTC the device sends uptime instead. Wall time is reconstructed
// from the delta, and the row is marked low confidence for admin review.
func TestDeadRTCReconstructsTimeAtLowConfidence(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-48*time.Hour), nil)

	e := ev(1, 42, time.Time{})
	e.TimeSource = model.TimeUptimeOnly
	e.CapturedUptimeMS = 1_000_000
	e.CapturedAt = h.now.Add(-99 * time.Hour) // garbage the server must ignore

	h.postEvents(t, model.EventsRequest{
		RequestID:      "aaaaaaaa-0000-4000-8000-000000000005",
		DeviceUptimeMS: 1_600_000, // 600s later
		Events:         []model.PunchEvent{e},
	})

	var effective time.Time
	var conf, src string
	if err := h.pool.QueryRow(context.Background(),
		`SELECT effective_at, time_conf::text, src_time::text FROM punch_event WHERE device_seq=1`).
		Scan(&effective, &conf, &src); err != nil {
		t.Fatalf("query: %v", err)
	}
	want := h.now.Add(-600 * time.Second)
	if d := effective.UTC().Sub(want.UTC()); d > time.Second || d < -time.Second {
		t.Errorf("reconstructed time %v, want ~%v", effective.UTC(), want.UTC())
	}
	if conf != "low" || src != "uptime_only" {
		t.Errorf("conf=%s src=%s, want low/uptime_only", conf, src)
	}
}

// The invariant from the spec: a slot reused after staff turnover must not
// re-attribute the previous holder's history.
func TestSlotReuseDoesNotRewriteHistory(t *testing.T) {
	h := setup(t, "bidirectional")
	cut := h.now.Add(-30 * 24 * time.Hour)
	h.bindSlot(t, 42, credA, ashaID, h.now.Add(-365*24*time.Hour), &cut)
	h.bindSlot(t, 42, credB, brianID, cut, nil)

	h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000006",
		Events: []model.PunchEvent{
			ev(1, 42, h.now.Add(-90*24*time.Hour)), // Asha's era
			ev(2, 42, h.now.Add(-1*time.Hour)),     // Brian's era
		},
	})

	var oldPerson, newPerson string
	ctx := context.Background()
	h.pool.QueryRow(ctx, `SELECT person_id::text FROM punch_event WHERE device_seq=1`).Scan(&oldPerson)
	h.pool.QueryRow(ctx, `SELECT person_id::text FROM punch_event WHERE device_seq=2`).Scan(&newPerson)

	if oldPerson != ashaID {
		t.Errorf("historical punch resolved to %s, want the previous slot holder", oldPerson)
	}
	if newPerson != brianID {
		t.Errorf("recent punch resolved to %s, want the current slot holder", newPerson)
	}
}

// A bidirectional reader cannot know direction, so the server alternates from
// the person's prior state.
func TestDirectionAlternatesOnBidirectionalReader(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000007",
		Events: []model.PunchEvent{
			ev(1, 42, h.now.Add(-8*time.Hour)),
			ev(2, 42, h.now.Add(-4*time.Hour)),
			ev(3, 42, h.now.Add(-1*time.Hour)),
		},
	})

	rows, err := h.pool.Query(context.Background(),
		`SELECT direction::text FROM punch_event ORDER BY device_seq`)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var d string
		rows.Scan(&d)
		got = append(got, d)
	}
	want := []string{"in", "out", "in"}
	for i := range want {
		if i >= len(got) || got[i] != want[i] {
			t.Fatalf("directions = %v, want %v", got, want)
		}
	}
}

// An entry-mounted reader always means "in", regardless of prior state.
func TestEntryModeForcesDirectionIn(t *testing.T) {
	h := setup(t, "entry")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	h.postEvents(t, model.EventsRequest{
		RequestID: "aaaaaaaa-0000-4000-8000-000000000008",
		Events: []model.PunchEvent{
			ev(1, 42, h.now.Add(-2*time.Hour)),
			ev(2, 42, h.now.Add(-1*time.Hour)),
		},
	})
	rows, _ := h.pool.Query(context.Background(), `SELECT direction::text FROM punch_event ORDER BY device_seq`)
	defer rows.Close()
	for rows.Next() {
		var d string
		rows.Scan(&d)
		if d != "in" {
			t.Fatalf("entry-mode reader produced %q", d)
		}
	}
}

// A device whose clock is far off must get a recoverable, self-describing
// rejection rather than an opaque auth failure.
func TestClockSkewIsRecoverable(t *testing.T) {
	h := setup(t, "bidirectional")

	code, body := h.do(t, "POST", "/v1/device/heartbeat",
		model.HeartbeatRequest{FirmwareVersion: "1.0.0"}, 20*time.Minute)

	if code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d: %s", code, body)
	}
	var p model.Problem
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("decode problem: %v (%s)", err, body)
	}
	if p.Code != "clock_skew" {
		t.Errorf("code = %q, want clock_skew", p.Code)
	}
	if p.ServerTimeMS != h.now.UnixMilli() {
		t.Errorf("rejection must carry server time so the device can self-correct; got %d", p.ServerTimeMS)
	}
}

func TestTamperedBodyIsRejected(t *testing.T) {
	h := setup(t, "bidirectional")
	raw := []byte(`{"request_id":"x","events":[]}`)
	req, _ := http.NewRequest("POST", h.srv.URL+"/v1/device/events", bytes.NewReader([]byte(`{"request_id":"y","events":[]}`)))
	req.Header.Set(auth.HeaderDeviceID, deviceID)
	req.Header.Set(auth.HeaderKeyVersion, "1")
	req.Header.Set(auth.HeaderTimestamp, strconv.FormatInt(h.now.UnixMilli(), 10))
	req.Header.Set(auth.HeaderNonce, "tamper")
	req.Header.Set(auth.HeaderSignature, auth.Sign(deviceSecret, "POST", "/v1/device/events", h.now.UnixMilli(), "tamper", raw))

	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("swapped body should fail signature check, got %d", resp.StatusCode)
	}
}

func TestSuspendedDeviceIsRefused(t *testing.T) {
	h := setup(t, "bidirectional")
	if _, err := h.pool.Exec(context.Background(),
		`UPDATE device SET state='suspended' WHERE id=$1`, deviceID); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	code, _ := h.do(t, "POST", "/v1/device/heartbeat", model.HeartbeatRequest{FirmwareVersion: "1.0.0"}, 0)
	if code != http.StatusForbidden {
		t.Fatalf("want 403 for a suspended device, got %d", code)
	}
}

// The roster is what a stolen terminal would leak, so it must carry names and
// slots only.
func TestRosterLeaksNoIdentifiers(t *testing.T) {
	h := setup(t, "bidirectional")
	h.bindSlot(t, 42, credB, brianID, h.now.Add(-24*time.Hour), nil)

	code, body := h.do(t, "GET", "/v1/device/roster?since=0", nil, 0)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	if bytes.Contains(body, []byte("EMP-002")) {
		t.Error("roster must not expose external_ref (payroll/admission numbers)")
	}
	var r model.RosterResponse
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(r.Upserts) != 1 || r.Upserts[0].DisplayName != "Brian K." {
		t.Fatalf("roster = %+v", r.Upserts)
	}
}

func TestHeartbeatReportsPendingCommands(t *testing.T) {
	h := setup(t, "bidirectional")
	if _, err := h.pool.Exec(context.Background(), `
		INSERT INTO device_command (device_id, kind, payload)
		VALUES ($1,'reboot','{}'::jsonb)`, deviceID); err != nil {
		t.Fatalf("queue: %v", err)
	}

	code, body := h.do(t, "POST", "/v1/device/heartbeat", model.HeartbeatRequest{FirmwareVersion: "1.0.0"}, 0)
	if code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", code, body)
	}
	var hb model.HeartbeatResponse
	json.Unmarshal(body, &hb)
	if hb.CommandsPending != 1 {
		t.Errorf("commands_pending = %d, want 1", hb.CommandsPending)
	}

	code, body = h.do(t, "GET", "/v1/device/commands?limit=5", nil, 0)
	if code != http.StatusOK {
		t.Fatalf("commands: %d %s", code, body)
	}
	var cr model.CommandsResponse
	json.Unmarshal(body, &cr)
	if len(cr.Commands) != 1 || cr.Commands[0].Kind != "reboot" {
		t.Fatalf("commands = %+v", cr.Commands)
	}

	code, _ = h.do(t, "POST", "/v1/device/commands/"+cr.Commands[0].ID+"/result",
		model.CommandResult{Status: "succeeded"}, 0)
	if code != http.StatusNoContent {
		t.Fatalf("result: want 204, got %d", code)
	}
	var status string
	h.pool.QueryRow(context.Background(),
		`SELECT status::text FROM device_command WHERE id=$1::uuid`, cr.Commands[0].ID).Scan(&status)
	if status != "succeeded" {
		t.Errorf("command status = %q", status)
	}
}
