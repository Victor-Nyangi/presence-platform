//go:build integration

package attendance

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	orgID    = "11111111-1111-1111-1111-111111111111"
	siteID   = "22222222-2222-2222-2222-222222222222"
	ashaID   = "33333333-3333-3333-3333-333333333333"
	brianID  = "44444444-4444-4444-4444-444444444444"
	deviceID = "55555555-5555-5555-5555-555555555555"
)

type fixture struct {
	pool *pgxpool.Pool
	eng  *Engine
	loc  *time.Location
	seq  int64
}

func setup(t *testing.T) *fixture {
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
		`ALTER TABLE punch_event DISABLE TRIGGER punch_event_no_mutation`,
		`TRUNCATE punch_amendment, attendance_span, attendance_day, notification,
		          sync_batch, device_command, punch_event, device_slot, credential,
		          person_schedule, schedule, guardian_person, guardian, device,
		          person, site, organization CASCADE`,
		`ALTER TABLE punch_event ENABLE TRIGGER punch_event_no_mutation`,
		fmt.Sprintf(`INSERT INTO organization (id,name,kind,timezone)
		             VALUES ('%s','Test Hospital','hospital','Africa/Nairobi')`, orgID),
		fmt.Sprintf(`INSERT INTO site (id,org_id,name) VALUES ('%s','%s','Ward A')`, siteID, orgID),
		fmt.Sprintf(`INSERT INTO person (id,org_id,kind,external_ref,full_name) VALUES
		             ('%s','%s','staff','EMP-001','Asha M.'),
		             ('%s','%s','staff','EMP-002','Brian K.')`, ashaID, orgID, brianID, orgID),
		fmt.Sprintf(`INSERT INTO device (id,org_id,site_id,label,serial,state)
		             VALUES ('%s','%s','%s','Ward A Reader','SN-1','active')`, deviceID, orgID, siteID),
	} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
			t.Fatalf("setup: %v\n%s", err, stmt)
		}
	}
	loc, _ := time.LoadLocation("Africa/Nairobi")
	f := &fixture{pool: pool, eng: NewEngine(pool), loc: loc}
	t.Cleanup(func() { pool.Close() })
	return f
}

// punch inserts a resolved event directly, standing in for the gateway.
func (f *fixture) punch(t *testing.T, personID string, ts time.Time, dir Direction) int64 {
	t.Helper()
	f.seq++
	var id int64
	err := f.pool.QueryRow(context.Background(), `
		INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
		                         status, person_id, captured_at, effective_at, src_time,
		                         time_conf, direction_hint, direction)
		VALUES ($1,$2,$3,gen_random_uuid(),'fingerprint','resolved',$4,$5,$5,'rtc_synced',
		        'high','unknown',$6::punch_direction)
		RETURNING id`, orgID, deviceID, f.seq, personID, ts, string(dir)).Scan(&id)
	if err != nil {
		t.Fatalf("insert punch: %v", err)
	}
	return id
}

func (f *fixture) at(day, hour, min int) time.Time {
	return time.Date(2026, 8, day, hour, min, 0, 0, f.loc)
}

func (f *fixture) recompute(t *testing.T, fromDay, toDay int) Result {
	t.Helper()
	res, err := f.eng.Recompute(context.Background(), orgID, f.at(fromDay, 12, 0), f.at(toDay, 12, 0))
	if err != nil {
		t.Fatalf("recompute: %v", err)
	}
	return res
}

func (f *fixture) day(t *testing.T, personID string, day int) (totalS int, present, late, review bool, spans int) {
	t.Helper()
	err := f.pool.QueryRow(context.Background(), `
		SELECT total_s, is_present, is_late, needs_review, span_count
		FROM attendance_day WHERE person_id=$1 AND business_date=$2`,
		personID, f.at(day, 0, 0)).Scan(&totalS, &present, &late, &review, &spans)
	if err != nil {
		t.Fatalf("read day %d: %v", day, err)
	}
	return
}

// ---------------------------------------------------------------------

func TestRecomputeSimpleDay(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 17, 0), DirOut)

	res := f.recompute(t, 18, 18)
	if res.People != 1 || res.Days != 1 || res.Spans != 1 {
		t.Fatalf("result = %+v", res)
	}
	total, present, _, review, spans := f.day(t, ashaID, 18)
	if total != 9*3600 {
		t.Errorf("total_s = %d, want %d", total, 9*3600)
	}
	if !present || review || spans != 1 {
		t.Errorf("present=%v review=%v spans=%d", present, review, spans)
	}
}

// The whole reason punch_event is append-only: recomputation must be safe to
// run repeatedly and must converge on the same answer.
func TestRecomputeIsIdempotent(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 12, 0), DirOut)
	f.punch(t, ashaID, f.at(18, 13, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 17, 0), DirOut)

	first := f.recompute(t, 18, 18)
	second := f.recompute(t, 18, 18)
	third := f.recompute(t, 18, 18)

	if first != second || second != third {
		t.Fatalf("not idempotent: %+v / %+v / %+v", first, second, third)
	}
	var spanRows, dayRows int
	ctx := context.Background()
	f.pool.QueryRow(ctx, `SELECT count(*) FROM attendance_span`).Scan(&spanRows)
	f.pool.QueryRow(ctx, `SELECT count(*) FROM attendance_day`).Scan(&dayRows)
	if spanRows != 2 || dayRows != 1 {
		t.Fatalf("three runs left %d spans and %d days; want 2 and 1", spanRows, dayRows)
	}
}

// A night shift ending at 03:30 belongs wholly to the day it began.
func TestRecomputeNightShiftLandsOnOneDay(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(17, 19, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 3, 30), DirOut)

	f.recompute(t, 17, 18)

	total, present, _, review, _ := f.day(t, ashaID, 17)
	if total != 8*3600+30*60 {
		t.Errorf("day 17 total = %ds, want 30600s", total)
	}
	if !present || review {
		t.Errorf("a routine night shift should be clean: present=%v review=%v", present, review)
	}
	var exists bool
	f.pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM attendance_day WHERE person_id=$1 AND business_date=$2)`,
		ashaID, f.at(18, 0, 0)).Scan(&exists)
	if exists {
		t.Error("the shift must not also produce a row on day 18")
	}
}

// The window edge must not manufacture an orphan clock-out from a shift that
// started before the window. This is what lookbackDays exists for.
func TestRecomputeWindowEdgeDoesNotInventAnomalies(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(17, 20, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 6, 0), DirOut)

	// Ask only for day 18 — the clock-in is outside the requested window.
	f.recompute(t, 18, 18)

	var rows int
	f.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM attendance_span WHERE business_date=$1`, f.at(18, 0, 0)).Scan(&rows)
	if rows != 0 {
		t.Errorf("the span belongs to day 17 and must not be written into day 18; got %d rows", rows)
	}
	var missingIn bool
	f.pool.QueryRow(context.Background(),
		`SELECT EXISTS(SELECT 1 FROM attendance_span WHERE 'missing_in' = ANY(anomalies))`).Scan(&missingIn)
	if missingIn {
		t.Error("padding should have paired the clock-in; no orphan out should exist")
	}
}

func TestRecomputeMissingClockOutFlagsReviewAndAccruesNoTime(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn) // never clocked out

	f.recompute(t, 18, 18)

	total, present, _, review, _ := f.day(t, ashaID, 18)
	if total != 0 {
		t.Errorf("an open span must accrue no time, got %ds", total)
	}
	if !present {
		t.Error("they were still present")
	}
	if !review {
		t.Error("a missing clock-out must reach a human")
	}
}

// Amendments are additive rows, and the engine must honour them without the
// raw event ever being mutated.
func TestAmendmentCorrectsDirection(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	badID := f.punch(t, ashaID, f.at(18, 17, 0), DirIn) // reader mis-set, should be 'out'

	f.recompute(t, 18, 18)
	if _, _, _, review, _ := f.day(t, ashaID, 18); !review {
		t.Fatal("two ins should flag for review before the correction")
	}

	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO punch_amendment (punch_event_id, new_direction, reason)
		VALUES ($1,'out','reader was mounted at the exit')`, badID); err != nil {
		t.Fatalf("amend: %v", err)
	}

	f.recompute(t, 18, 18)
	total, _, _, review, spans := f.day(t, ashaID, 18)
	if total != 9*3600 {
		t.Errorf("after correction total = %ds, want 32400s", total)
	}
	if review {
		t.Error("the corrected day should no longer need review")
	}
	if spans != 1 {
		t.Errorf("span count = %d, want 1", spans)
	}

	// And the raw event is untouched.
	var rawDir string
	f.pool.QueryRow(context.Background(),
		`SELECT direction::text FROM punch_event WHERE id=$1`, badID).Scan(&rawDir)
	if rawDir != "in" {
		t.Errorf("raw event was mutated: direction is now %q", rawDir)
	}
}

func TestAmendmentVoidsAnEvent(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	ghost := f.punch(t, ashaID, f.at(18, 10, 0), DirIn) // someone else's finger
	f.punch(t, ashaID, f.at(18, 17, 0), DirOut)

	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO punch_amendment (punch_event_id, voided, reason)
		VALUES ($1,true,'mis-identified')`, ghost); err != nil {
		t.Fatalf("void: %v", err)
	}
	f.recompute(t, 18, 18)

	total, _, _, review, spans := f.day(t, ashaID, 18)
	if spans != 1 || total != 9*3600 {
		t.Errorf("voided event should vanish from the rollup: spans=%d total=%ds", spans, total)
	}
	if review {
		t.Error("no anomaly should remain")
	}
}

// Later amendment wins, per field.
func TestLatestAmendmentWins(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	id := f.punch(t, ashaID, f.at(18, 17, 0), DirOut)

	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO punch_amendment (punch_event_id, new_effective_at, reason, created_at)
		VALUES ($1,$2,'first guess', now() - interval '2 hours')`,
		id, f.at(18, 16, 0)); err != nil {
		t.Fatalf("amend 1: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO punch_amendment (punch_event_id, new_effective_at, reason, created_at)
		VALUES ($1,$2,'guard confirmed', now())`,
		id, f.at(18, 18, 0)); err != nil {
		t.Fatalf("amend 2: %v", err)
	}

	f.recompute(t, 18, 18)
	total, _, _, _, _ := f.day(t, ashaID, 18)
	if total != 10*3600 {
		t.Errorf("total = %ds, want 36000s (the later amendment should win)", total)
	}
}

// Changing the day boundary must be a re-run, not a migration.
func TestChangingDayBoundaryReattributesOnRecompute(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(17, 20, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 2, 0), DirOut)

	ctx := context.Background()
	// Default boundary (04:00): the shift reports on day 17.
	f.recompute(t, 16, 19)
	var d17 bool
	f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM attendance_day WHERE business_date=$1)`,
		f.at(17, 0, 0)).Scan(&d17)
	if !d17 {
		t.Fatal("with a 04:00 boundary the shift belongs to day 17")
	}

	// Customer switches to calendar days.
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO schedule (org_id, name, expected_in, expected_out, day_boundary)
		VALUES ($1,'calendar','08:00','17:00','00:00')`, orgID); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	f.recompute(t, 16, 19)

	// A span is always attributed to the day it STARTED, so the shift stays
	// on day 17 — what changes is that it is now flagged as crossing a
	// reporting day.
	//
	// This is a deliberate product decision, not a limitation: hours are
	// never split across two days. It keeps one shift as one auditable unit
	// and stops a night nurse's pay appearing as two half-days. If a payroll
	// integration ever needs proportional splitting, it should do that at
	// export time from the span's start and end, leaving these tables alone.
	var d18 bool
	f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM attendance_day WHERE business_date=$1)`,
		f.at(18, 0, 0)).Scan(&d18)
	if d18 {
		t.Error("hours must not be split across days; the shift belongs to day 17")
	}

	total, _, _, review, _ := f.day(t, ashaID, 17)
	if total != 6*3600 {
		t.Errorf("day 17 total = %ds, want 21600s — the full shift, undivided", total)
	}
	var overnight bool
	f.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM attendance_span WHERE 'overnight' = ANY(anomalies))`).Scan(&overnight)
	if !overnight {
		t.Error("crossing a calendar day should now be flagged overnight")
	}
	if !review {
		t.Error("and that flag should put the day in front of a human")
	}
}

func TestLatenessUsesTheSchedule(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var schedID string
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO schedule (org_id, name, weekdays, expected_in, expected_out, grace_minutes, day_boundary)
		VALUES ($1,'day shift','{1,2,3,4,5}','08:00','17:00',10,'04:00') RETURNING id::text`,
		orgID).Scan(&schedID); err != nil {
		t.Fatalf("schedule: %v", err)
	}
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO person_schedule (person_id, schedule_id, effective_from)
		VALUES ($1,$2::uuid,'2026-01-01'),($3,$2::uuid,'2026-01-01')`,
		ashaID, schedID, brianID); err != nil {
		t.Fatalf("assign: %v", err)
	}

	f.punch(t, ashaID, f.at(18, 8, 5), DirIn) // within grace
	f.punch(t, ashaID, f.at(18, 17, 0), DirOut)
	f.punch(t, brianID, f.at(18, 8, 40), DirIn) // late
	f.punch(t, brianID, f.at(18, 17, 0), DirOut)

	f.recompute(t, 18, 18)

	if _, _, late, _, _ := f.day(t, ashaID, 18); late {
		t.Error("08:05 with a 10-minute grace is not late")
	}
	if _, _, late, _, _ := f.day(t, brianID, 18); !late {
		t.Error("08:40 is late")
	}
}

func TestReviewQueueSurfacesProblemDays(t *testing.T) {
	f := setup(t)
	f.punch(t, ashaID, f.at(18, 8, 0), DirIn)
	f.punch(t, ashaID, f.at(18, 17, 0), DirOut) // clean
	f.punch(t, brianID, f.at(18, 8, 0), DirIn)  // never clocked out

	f.recompute(t, 18, 18)

	items, err := f.eng.ReviewQueue(context.Background(), orgID, f.at(18, 0, 0), f.at(18, 0, 0), 50)
	if err != nil {
		t.Fatalf("review queue: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want exactly the one problem day, got %d: %+v", len(items), items)
	}
	if items[0].PersonID != brianID {
		t.Errorf("wrong person surfaced: %s", items[0].FullName)
	}
	found := false
	for _, a := range items[0].Anomalies {
		if a == AnomalyMissingOut {
			found = true
		}
	}
	if !found {
		t.Errorf("anomalies = %v, want missing_out", items[0].Anomalies)
	}
}

// Unresolved events are stored for triage but are not attendance.
func TestUnresolvedEventsAreNotCounted(t *testing.T) {
	f := setup(t)
	f.seq++
	if _, err := f.pool.Exec(context.Background(), `
		INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
		                         status, unresolved_reason, captured_at, effective_at,
		                         src_time, direction_hint, direction)
		VALUES ($1,$2,$3,gen_random_uuid(),'fingerprint','unresolved','unknown_slot',
		        $4,$4,'rtc_synced','unknown','in')`,
		orgID, deviceID, f.seq, f.at(18, 8, 0)); err != nil {
		t.Fatalf("insert: %v", err)
	}

	res := f.recompute(t, 18, 18)
	if res.Spans != 0 || res.Days != 0 {
		t.Errorf("unresolved events must not become attendance, got %+v", res)
	}
}
