package attendance

import (
	"encoding/json"
	"testing"
	"time"
)

func seqIDs(prefix string) func() string {
	n := 0
	return func() string {
		n++
		return prefix + string(rune('0'+n))
	}
}

func t1(hm string) time.Time {
	tm, err := time.Parse("2006-01-02T15:04", "2026-08-18T"+hm)
	if err != nil {
		panic(err)
	}
	return tm
}

func day(d string) time.Time {
	tm, err := time.Parse("2006-01-02", d)
	if err != nil {
		panic(err)
	}
	return tm
}

func i64(n int64) *int64 { return &n }

// A re-run of the same window with identical output must emit nothing. This
// is the property that stops a routine cron re-run from re-sending an event
// for every span and day every time it runs.
func TestDiffSpansNoOpWhenUnchanged(t *testing.T) {
	snap := SpanSnapshot{
		PersonID: "p1", InEventID: i64(1), OutEventID: i64(2),
		BusinessDate: day("2026-08-18"), StartedAt: t1("08:00"), EndedAt: ptrTime(t1("17:00")),
	}
	before := map[SpanKey]SpanSnapshot{snap.Key(): snap}
	after := map[SpanKey]SpanSnapshot{snap.Key(): snap}

	got := DiffSpans("org1", before, after, time.Now(), seqIDs("ev"))
	if len(got) != 0 {
		t.Fatalf("expected no events for an unchanged span, got %d: %+v", len(got), got)
	}
}

func TestDiffSpansEmitsUpsertOnNewSpan(t *testing.T) {
	snap := SpanSnapshot{
		PersonID: "p1", InEventID: i64(1), OutEventID: i64(2),
		BusinessDate: day("2026-08-18"), StartedAt: t1("08:00"), EndedAt: ptrTime(t1("17:00")),
	}
	after := map[SpanKey]SpanSnapshot{snap.Key(): snap}

	got := DiffSpans("org1", nil, after, time.Now(), seqIDs("ev"))
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].EventType != EventSpanUpserted {
		t.Errorf("event type = %s, want %s", got[0].EventType, EventSpanUpserted)
	}
	var payload spanEventPayload
	if err := json.Unmarshal(got[0].Payload, &payload); err != nil {
		t.Fatalf("payload did not unmarshal: %v", err)
	}
	if payload.Data == nil {
		t.Fatal("upsert payload must carry data")
	}
	if payload.Data.DurationSeconds != 9*3600 {
		t.Errorf("duration = %d, want %d", payload.Data.DurationSeconds, 9*3600)
	}
	if payload.EventID != got[0].EventID {
		t.Error("payload.event_id must match the outbox row's EventID (the idempotency key)")
	}
}

func TestDiffSpansEmitsUpsertWhenContentChanges(t *testing.T) {
	before := map[SpanKey]SpanSnapshot{}
	oldSpan := SpanSnapshot{PersonID: "p1", InEventID: i64(1), BusinessDate: day("2026-08-18"), StartedAt: t1("08:00")}
	before[oldSpan.Key()] = oldSpan

	// Same key (in_event_id=1), but now closed — an amendment or a later
	// punch arriving changed its content.
	after := map[SpanKey]SpanSnapshot{}
	newSpan := oldSpan
	newSpan.EndedAt = ptrTime(t1("17:00"))
	after[newSpan.Key()] = newSpan

	got := DiffSpans("org1", before, after, time.Now(), seqIDs("ev"))
	if len(got) != 1 || got[0].EventType != EventSpanUpserted {
		t.Fatalf("want 1 upsert event, got %+v", got)
	}
}

func TestDiffSpansEmitsRemovedWhenSpanDisappears(t *testing.T) {
	snap := SpanSnapshot{PersonID: "p1", InEventID: i64(1), BusinessDate: day("2026-08-18"), StartedAt: t1("08:00")}
	before := map[SpanKey]SpanSnapshot{snap.Key(): snap}

	// e.g. an amendment voided the anchoring punch entirely.
	got := DiffSpans("org1", before, map[SpanKey]SpanSnapshot{}, time.Now(), seqIDs("ev"))
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	if got[0].EventType != EventSpanRemoved {
		t.Errorf("event type = %s, want %s", got[0].EventType, EventSpanRemoved)
	}
	var payload spanEventPayload
	if err := json.Unmarshal(got[0].Payload, &payload); err != nil {
		t.Fatalf("payload did not unmarshal: %v", err)
	}
	if payload.Data != nil {
		t.Error("a removed event must not carry data")
	}
}

// Two spans anchored on different in_event_ids must never be conflated, even
// if everything else about them matches (same person, same day).
func TestDiffSpansDistinctKeysDoNotCollide(t *testing.T) {
	s1 := SpanSnapshot{PersonID: "p1", InEventID: i64(1), BusinessDate: day("2026-08-18"), StartedAt: t1("08:00")}
	s2 := SpanSnapshot{PersonID: "p1", InEventID: i64(2), BusinessDate: day("2026-08-18"), StartedAt: t1("13:00")}
	after := map[SpanKey]SpanSnapshot{s1.Key(): s1, s2.Key(): s2}

	got := DiffSpans("org1", nil, after, time.Now(), seqIDs("ev"))
	if len(got) != 2 {
		t.Fatalf("want 2 events, got %d", len(got))
	}
}

// A missing_in marker span has no in_event_id; its out_event_id must still
// give it a stable, distinct identity.
func TestDiffSpansMissingInUsesOutEventKey(t *testing.T) {
	snap := SpanSnapshot{PersonID: "p1", OutEventID: i64(9), BusinessDate: day("2026-08-18"),
		StartedAt: t1("08:00"), EndedAt: ptrTime(t1("08:00")), Anomalies: []string{"missing_in"}}
	after := map[SpanKey]SpanSnapshot{snap.Key(): snap}

	got := DiffSpans("org1", nil, after, time.Now(), seqIDs("ev"))
	if len(got) != 1 {
		t.Fatalf("want 1 event, got %d", len(got))
	}
	var payload spanEventPayload
	json.Unmarshal(got[0].Payload, &payload)
	if payload.Subject.InEventID != nil {
		t.Error("a missing_in marker has no in_event_id and must not fabricate one")
	}
	if payload.Subject.OutEventID == nil || *payload.Subject.OutEventID != 9 {
		t.Error("subject must carry the out_event_id as the stable key")
	}
}

// Anomaly order must not cause a false "changed" diagnosis — the flagging
// logic in rules.go doesn't guarantee any particular append order across
// runs that reach the same set via different code paths.
func TestDiffSpansAnomalyOrderDoesNotCountAsAChange(t *testing.T) {
	before := SpanSnapshot{PersonID: "p1", InEventID: i64(1), BusinessDate: day("2026-08-18"),
		StartedAt: t1("08:00"), EndedAt: ptrTime(t1("17:00")), Anomalies: []string{"overnight", "low_time_conf"}}
	after := before
	after.Anomalies = []string{"low_time_conf", "overnight"}

	got := DiffSpans("org1", map[SpanKey]SpanSnapshot{before.Key(): before},
		map[SpanKey]SpanSnapshot{after.Key(): after}, time.Now(), seqIDs("ev"))
	if len(got) != 0 {
		t.Fatalf("reordered anomalies must not count as a change, got %d events", len(got))
	}
}

func TestDiffDaysNoOpWhenUnchanged(t *testing.T) {
	d := DaySnapshot{PersonID: "p1", BusinessDate: day("2026-08-18"), TotalSeconds: 30600, IsPresent: true}
	before := map[DayKey]DaySnapshot{d.Key(): d}
	after := map[DayKey]DaySnapshot{d.Key(): d}

	got := DiffDays("org1", before, after, time.Now(), seqIDs("ev"))
	if len(got) != 0 {
		t.Fatalf("expected no events for an unchanged day, got %d", len(got))
	}
}

func TestDiffDaysEmitsUpsertWhenTotalsChange(t *testing.T) {
	before := DaySnapshot{PersonID: "p1", BusinessDate: day("2026-08-18"), TotalSeconds: 30600, IsPresent: true}
	after := before
	after.TotalSeconds = 32400 // an amendment shifted a punch time

	got := DiffDays("org1", map[DayKey]DaySnapshot{before.Key(): before},
		map[DayKey]DaySnapshot{after.Key(): after}, time.Now(), seqIDs("ev"))
	if len(got) != 1 || got[0].EventType != EventDayUpserted {
		t.Fatalf("want 1 upsert event, got %+v", got)
	}
	var payload dayEventPayload
	json.Unmarshal(got[0].Payload, &payload)
	if payload.Data.TotalSeconds != 32400 {
		t.Errorf("total_seconds = %d, want 32400", payload.Data.TotalSeconds)
	}
	if payload.Subject.BusinessDate != "2026-08-18" {
		t.Errorf("business_date = %q, want 2026-08-18", payload.Subject.BusinessDate)
	}
}

// This is the whole point of a full-snapshot (not delta) payload design: a
// consumer that missed the day's history can still reconstruct correct
// current state from the single most recent event, and out-of-order or
// duplicate delivery cannot corrupt its view as long as it compares
// emitted_at before applying.
func TestDayPayloadCarriesFullSnapshotNotADelta(t *testing.T) {
	d := DaySnapshot{
		PersonID: "p1", BusinessDate: day("2026-08-18"),
		FirstInAt: ptrTime(t1("08:00")), LastOutAt: ptrTime(t1("17:00")),
		TotalSeconds: 32400, SpanCount: 1, IsPresent: true, IsLate: false, NeedsReview: false,
	}
	got := DiffDays("org1", nil, map[DayKey]DaySnapshot{d.Key(): d}, time.Now(), seqIDs("ev"))
	var payload dayEventPayload
	json.Unmarshal(got[0].Payload, &payload)
	if payload.Data.SpanCount != 1 || payload.Data.TotalSeconds != 32400 || !payload.Data.IsPresent {
		t.Errorf("payload must carry the full rollup, got %+v", payload.Data)
	}
}

func TestDiffDaysEmitsRemovedWhenDayDisappears(t *testing.T) {
	d := DaySnapshot{PersonID: "p1", BusinessDate: day("2026-08-18"), IsPresent: true}
	got := DiffDays("org1", map[DayKey]DaySnapshot{d.Key(): d}, map[DayKey]DaySnapshot{}, time.Now(), seqIDs("ev"))
	if len(got) != 1 || got[0].EventType != EventDayRemoved {
		t.Fatalf("want 1 removed event, got %+v", got)
	}
	if got[0].BusinessDate == nil || !got[0].BusinessDate.Equal(day("2026-08-18")) {
		t.Error("removed event must still carry the subject's business_date for routing")
	}
}

func TestNewEventIDIsUniqueAndV4(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewEventID()
		if seen[id] {
			t.Fatalf("collision on iteration %d: %s", i, id)
		}
		seen[id] = true
		if len(id) != 36 || id[14] != '4' {
			t.Fatalf("id %q is not a well-formed UUIDv4", id)
		}
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
