// Projector logic: turns a recompute's before/after attendance state into
// the outbound events a consumer would care about.
//
// PURE, like rules.go: no database, no clock as an ambient dependency
// (emittedAt is passed in), no I/O. The engine calls in here with snapshots
// it already has in memory from the same transaction, diffs them, and
// writes the result to outbox_event alongside the attendance_span/day rows
// it derived them from. Keeping the diff pure means the "did this actually
// change" logic — the part most likely to be subtly wrong — can be
// exercised exhaustively without Postgres.
package attendance

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// NewEventID returns a random UUIDv4, used both as outbox_event's primary
// key and as the event_id embedded in the payload and later sent as the
// X-Presence-Event-Id header — the idempotency key a consumer de-duplicates
// on. Generated in Go rather than left to Postgres's gen_random_uuid()
// default so the same value can be embedded in the payload at construction
// time instead of requiring a round trip to read it back.
func NewEventID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the OS entropy source is broken, which
		// is a fatal environment problem, not something to fall back from
		// silently into a weaker generator.
		panic("attendance: crypto/rand unavailable: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Event types. Two derived tables, two event families — deliberately no
// third "occupancy" family: that would need a device-to-room/department
// mapping this schema does not have (devices map to a site, nothing finer),
// and inventing one is out of scope for the projector.
const (
	EventSpanUpserted = "attendance_span.upserted"
	EventSpanRemoved  = "attendance_span.removed"
	EventDayUpserted  = "attendance_day.upserted"
	EventDayRemoved   = "attendance_day.removed"
)

// SpanSnapshot is one attendance_span row, keyed by the punch_event id(s)
// that anchor it rather than attendance_span.id.
//
// attendance_span.id is a bigserial that churns on every recompute — the
// engine deletes and re-inserts the whole window unconditionally, so a span
// with identical content gets a new id each run. punch_event rows are
// append-only and never deleted (invariant #2), so in_event_id/out_event_id
// are the only identifiers here that are actually stable across recomputes.
// A consumer that keyed off attendance_span.id (as an earlier integration
// sketch assumed) would see its "identity" churn on every recompute even
// when nothing changed.
type SpanSnapshot struct {
	PersonID     string
	InEventID    *int64
	OutEventID   *int64
	BusinessDate time.Time
	StartedAt    time.Time
	EndedAt      *time.Time
	Anomalies    []string
}

// SpanKey identifies a span independent of attendance_span.id. The schema's
// own attendance_span_in_event_idx (unique on in_event_id) guarantees at
// most one span per in_event_id, so this is collision-free for spans that
// have an in event; a missing_in marker (no in event) falls back to its
// out event, which Pair() likewise attaches to at most one span.
//
// Deliberately plain int64, not *int64: a map key built from a pointer
// compares pointer identity, not the pointed-to value, so two snapshots of
// the identical span loaded from different places (a fresh DB scan versus a
// freshly computed Pair() result) would silently never compare equal and
// every recompute would look like every span got deleted and recreated. 0
// is a safe "absent" sentinel — punch_event is a bigserial starting at 1.
type SpanKey struct {
	InEventID  int64
	OutEventID int64
}

func (s SpanSnapshot) Key() SpanKey {
	return SpanKey{InEventID: deref(s.InEventID), OutEventID: deref(s.OutEventID)}
}

func deref(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

func (s SpanSnapshot) equal(o SpanSnapshot) bool {
	if !s.StartedAt.Equal(o.StartedAt) {
		return false
	}
	if (s.EndedAt == nil) != (o.EndedAt == nil) {
		return false
	}
	if s.EndedAt != nil && !s.EndedAt.Equal(*o.EndedAt) {
		return false
	}
	return sameStrings(s.Anomalies, o.Anomalies)
}

// DaySnapshot is one attendance_day row, keyed by (person_id, business_date)
// — the same key the table itself already uses as its primary key.
type DaySnapshot struct {
	PersonID     string
	BusinessDate time.Time
	FirstInAt    *time.Time
	LastOutAt    *time.Time
	TotalSeconds int
	SpanCount    int
	IsPresent    bool
	IsLate       bool
	NeedsReview  bool
}

// BusinessDate is a string ("2006-01-02"), not time.Time: the same date
// scanned back from Postgres and computed fresh in Go can carry different
// *time.Location pointers or monotonic readings, which makes time.Time an
// unsafe map-key field for "are these the same date" — struct equality
// compares those internals, not the instant. A canonical string sidesteps
// it entirely, and a business date has no meaningful sub-day precision to
// lose.
type DayKey struct {
	PersonID     string
	BusinessDate string
}

func (d DaySnapshot) Key() DayKey {
	return DayKey{PersonID: d.PersonID, BusinessDate: d.BusinessDate.Format("2006-01-02")}
}

func (d DaySnapshot) equal(o DaySnapshot) bool {
	if d.TotalSeconds != o.TotalSeconds || d.SpanCount != o.SpanCount ||
		d.IsPresent != o.IsPresent || d.IsLate != o.IsLate || d.NeedsReview != o.NeedsReview {
		return false
	}
	if (d.FirstInAt == nil) != (o.FirstInAt == nil) || (d.FirstInAt != nil && !d.FirstInAt.Equal(*o.FirstInAt)) {
		return false
	}
	if (d.LastOutAt == nil) != (o.LastOutAt == nil) || (d.LastOutAt != nil && !d.LastOutAt.Equal(*o.LastOutAt)) {
		return false
	}
	return true
}

// OutboxRow is what the engine inserts into outbox_event. Payload is
// pre-marshalled JSON here so the diff functions stay pure (no dependency
// on how the engine happens to serialise) while still producing exactly
// what gets written.
type OutboxRow struct {
	EventID      string // == outbox_event.id and payload.event_id
	EventType    string
	PersonID     string
	BusinessDate *time.Time // set for day events
	InEventID    *int64     // set for span events
	OutEventID   *int64     // set for span events
	Payload      []byte
}

// spanEventPayload / dayEventPayload are the wire shape of a payload, kept
// generic — presence vocabulary only (people, punch events, spans, days),
// nothing that names a consumer or a clinical concept.
type spanEventPayload struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	OrgID     string    `json:"org_id"`
	EmittedAt time.Time `json:"emitted_at"`
	Subject   spanSubj  `json:"subject"`
	Data      *spanData `json:"data,omitempty"`
}

type spanSubj struct {
	PersonID   string `json:"person_id"`
	InEventID  *int64 `json:"in_event_id,omitempty"`
	OutEventID *int64 `json:"out_event_id,omitempty"`
}

type spanData struct {
	BusinessDate    string     `json:"business_date"`
	StartedAt       time.Time  `json:"started_at"`
	EndedAt         *time.Time `json:"ended_at,omitempty"`
	DurationSeconds int        `json:"duration_seconds"`
	Open            bool       `json:"open"`
	Anomalies       []string   `json:"anomalies"`
}

type dayEventPayload struct {
	EventID   string    `json:"event_id"`
	EventType string    `json:"event_type"`
	OrgID     string    `json:"org_id"`
	EmittedAt time.Time `json:"emitted_at"`
	Subject   daySubj   `json:"subject"`
	Data      *dayData  `json:"data,omitempty"`
}

type daySubj struct {
	PersonID     string `json:"person_id"`
	BusinessDate string `json:"business_date"`
}

type dayData struct {
	FirstInAt    *time.Time `json:"first_in_at,omitempty"`
	LastOutAt    *time.Time `json:"last_out_at,omitempty"`
	TotalSeconds int        `json:"total_seconds"`
	SpanCount    int        `json:"span_count"`
	IsPresent    bool       `json:"is_present"`
	IsLate       bool       `json:"is_late"`
	NeedsReview  bool       `json:"needs_review"`
}

// DiffSpans compares the spans that existed before this recompute to the
// spans it just produced (both scoped to the same window) and returns one
// OutboxRow per subject whose state actually changed — nothing for a span
// that recomputed identically, which is what stops a routine cron re-run
// from re-emitting events for every span in the window every time it runs.
func DiffSpans(orgID string, before, after map[SpanKey]SpanSnapshot, emittedAt time.Time, newID func() string) []OutboxRow {
	var rows []OutboxRow

	for key, next := range after {
		prev, existed := before[key]
		if existed && prev.equal(next) {
			continue
		}
		rows = append(rows, spanRow(orgID, EventSpanUpserted, next, emittedAt, newID()))
	}
	for key, prev := range before {
		if _, stillThere := after[key]; stillThere {
			continue
		}
		rows = append(rows, spanRow(orgID, EventSpanRemoved, prev, emittedAt, newID()))
	}
	return rows
}

func spanRow(orgID, eventType string, s SpanSnapshot, emittedAt time.Time, eventID string) OutboxRow {
	p := spanEventPayload{
		EventID:   eventID,
		EventType: eventType,
		OrgID:     orgID,
		EmittedAt: emittedAt,
		Subject:   spanSubj{PersonID: s.PersonID, InEventID: s.InEventID, OutEventID: s.OutEventID},
	}
	if eventType == EventSpanUpserted {
		p.Data = &spanData{
			BusinessDate:    s.BusinessDate.Format("2006-01-02"),
			StartedAt:       s.StartedAt,
			EndedAt:         s.EndedAt,
			DurationSeconds: spanDurationSeconds(s),
			Open:            s.EndedAt == nil,
			Anomalies:       anomalyArray(s.Anomalies),
		}
	}
	payload, _ := json.Marshal(p) // fixed shape; marshal error is a programmer error, not a runtime one
	return OutboxRow{
		EventID:    eventID,
		EventType:  eventType,
		PersonID:   s.PersonID,
		InEventID:  s.InEventID,
		OutEventID: s.OutEventID,
		Payload:    payload,
	}
}

func spanDurationSeconds(s SpanSnapshot) int {
	if s.EndedAt == nil {
		return 0
	}
	return int(s.EndedAt.Sub(s.StartedAt).Seconds())
}

// DiffDays is DiffSpans's counterpart for attendance_day rollups.
func DiffDays(orgID string, before, after map[DayKey]DaySnapshot, emittedAt time.Time, newID func() string) []OutboxRow {
	var rows []OutboxRow

	for key, next := range after {
		prev, existed := before[key]
		if existed && prev.equal(next) {
			continue
		}
		rows = append(rows, dayRow(orgID, EventDayUpserted, next, emittedAt, newID()))
	}
	for key, prev := range before {
		if _, stillThere := after[key]; stillThere {
			continue
		}
		rows = append(rows, dayRow(orgID, EventDayRemoved, prev, emittedAt, newID()))
	}
	return rows
}

func dayRow(orgID, eventType string, d DaySnapshot, emittedAt time.Time, eventID string) OutboxRow {
	p := dayEventPayload{
		EventID:   eventID,
		EventType: eventType,
		OrgID:     orgID,
		EmittedAt: emittedAt,
		Subject:   daySubj{PersonID: d.PersonID, BusinessDate: d.BusinessDate.Format("2006-01-02")},
	}
	if eventType == EventDayUpserted {
		p.Data = &dayData{
			FirstInAt:    d.FirstInAt,
			LastOutAt:    d.LastOutAt,
			TotalSeconds: d.TotalSeconds,
			SpanCount:    d.SpanCount,
			IsPresent:    d.IsPresent,
			IsLate:       d.IsLate,
			NeedsReview:  d.NeedsReview,
		}
	}
	payload, _ := json.Marshal(p)
	date := d.BusinessDate
	return OutboxRow{
		EventID:      eventID,
		EventType:    eventType,
		PersonID:     d.PersonID,
		BusinessDate: &date,
		Payload:      payload,
	}
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sa, sb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(sa)
	sort.Strings(sb)
	for i := range sa {
		if sa[i] != sb[i] {
			return false
		}
	}
	return true
}
