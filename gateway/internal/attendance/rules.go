// Package attendance turns raw punches into attendance.
//
// Everything in this file is PURE: no database, no clock, no I/O. That split
// is deliberate. The hard parts of attendance are not queries, they are rules
// — which business day a 02:00 punch belongs to, what to do when someone
// forgets to clock out, whether two taps three seconds apart are one arrival
// or two. Those need to be exercised exhaustively, and they can only be
// exercised exhaustively if they don't need Postgres.
//
// The engine in engine.go reads rows, calls into here, and writes rows back.
package attendance

import (
	"sort"
	"time"

	// Embedded tzdata. The gateway ships on distroless, which has no
	// /usr/share/zoneinfo — without this, LoadLocation("Africa/Nairobi")
	// fails in production and silently succeeds on every developer laptop.
	_ "time/tzdata"
)

type Direction string

const (
	DirIn  Direction = "in"
	DirOut Direction = "out"
)

// Anomalies. These are not errors — they are facts about the day that a human
// may need to look at. Attendance data that hides its own uncertainty is
// worse than attendance data that admits it.
const (
	AnomalyMissingOut    = "missing_out" // clocked in, never out
	AnomalyMissingIn     = "missing_in"  // clocked out with no matching in
	AnomalyOvernight     = "overnight"   // span crosses the day boundary
	AnomalyDuplicate     = "duplicate_suppressed"
	AnomalyLowConfidence = "low_time_conf"    // reconstructed or untrusted timestamp
	AnomalyImplausible   = "implausible_span" // longer than any real shift
)

// Punch is one resolved event, after amendments have been applied.
type Punch struct {
	EventID    int64
	At         time.Time
	Direction  Direction
	Confidence string // high | medium | low
}

// Span is one continuous period of presence.
type Span struct {
	InEventID  *int64
	OutEventID *int64
	StartedAt  time.Time
	EndedAt    *time.Time // nil when the person never clocked out
	Anomalies  []string
}

// Duration is zero for an open span. An unclosed span must never accrue time:
// a forgotten clock-out would otherwise quietly bill hundreds of hours.
func (s Span) Duration() time.Duration {
	if s.EndedAt == nil {
		return 0
	}
	return s.EndedAt.Sub(s.StartedAt)
}

func (s Span) Open() bool { return s.EndedAt == nil }

func (s *Span) flag(a string) {
	for _, existing := range s.Anomalies {
		if existing == a {
			return
		}
	}
	s.Anomalies = append(s.Anomalies, a)
}

// Rules is the per-organisation configuration the pairing depends on.
type Rules struct {
	Location *time.Location

	// DayBoundary is the time of day at which a new business day starts.
	// It defaults to 04:00, NOT midnight: a nurse clocking out at 02:00
	// belongs to the shift that began the previous evening. Using midnight
	// here is the single most common attendance bug there is.
	DayBoundary time.Duration

	// DuplicateWindow: two punches in the same direction inside this window
	// are one action — a second tap because the first beep was missed. The
	// device already suppresses same-slot bounce over ~5s; this catches the
	// slower human version.
	DuplicateWindow time.Duration

	// MaxPlausibleSpan flags, but does not truncate, absurd durations. The
	// raw events stay authoritative; a human decides.
	MaxPlausibleSpan time.Duration
}

func DefaultRules(loc *time.Location) Rules {
	return Rules{
		Location:         loc,
		DayBoundary:      4 * time.Hour,
		DuplicateWindow:  90 * time.Second,
		MaxPlausibleSpan: 16 * time.Hour,
	}
}

// BusinessDate maps an instant to the day attendance should be reported
// against.
//
// Shifting back by the boundary before truncating does the whole job: with a
// 04:00 boundary, 02:00 on the 18th shifts to 22:00 on the 17th and reports
// as the 17th, while 05:00 on the 18th stays on the 18th.
func BusinessDate(t time.Time, r Rules) time.Time {
	local := t.In(r.Location).Add(-r.DayBoundary)
	return time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, r.Location)
}

// Pair walks a person's punches in time order and produces spans.
//
// The awkward cases are the normal cases. People forget to clock out, tap
// twice, and clock out on a reader they never clocked in on. Each of those
// produces a span with an anomaly rather than being dropped, because the
// alternative — silently discarding a punch someone actually made — is how
// attendance systems lose the trust of the people they measure.
func Pair(punches []Punch, r Rules) []Span {
	if len(punches) == 0 {
		return nil
	}
	ordered := append([]Punch(nil), punches...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].At.Equal(ordered[j].At) {
			return ordered[i].EventID < ordered[j].EventID
		}
		return ordered[i].At.Before(ordered[j].At)
	})

	var (
		spans    []Span
		open     *Span
		lastDir  Direction
		lastAt   time.Time
		havePrev bool
	)

	lowConf := func(p Punch, s *Span) {
		if p.Confidence == "low" {
			s.flag(AnomalyLowConfidence)
		}
	}

	closeSpan := func(s *Span) {
		spans = append(spans, *s)
	}

	for _, p := range ordered {
		// Same direction twice inside the window: one action, not two.
		if havePrev && p.Direction == lastDir && p.At.Sub(lastAt) <= r.DuplicateWindow {
			if open != nil {
				open.flag(AnomalyDuplicate)
			} else if n := len(spans); n > 0 {
				spans[n-1].flag(AnomalyDuplicate)
			}
			lastAt = p.At
			continue
		}

		switch p.Direction {
		case DirIn:
			if open != nil {
				// Two ins with no out between them. The first period is real
				// but unterminated; do not merge them, or a forgotten
				// clock-out silently becomes a longer shift.
				open.flag(AnomalyMissingOut)
				closeSpan(open)
				open = nil
			}
			id := p.EventID
			s := Span{InEventID: &id, StartedAt: p.At}
			lowConf(p, &s)
			open = &s

		case DirOut:
			id := p.EventID
			if open == nil {
				// Clocked out without a matching in. Recorded as a
				// zero-length marker so the event is visible to whoever
				// reconciles the day, rather than vanishing.
				s := Span{OutEventID: &id, StartedAt: p.At, EndedAt: &p.At}
				s.flag(AnomalyMissingIn)
				lowConf(p, &s)
				closeSpan(&s)
				break
			}
			at := p.At
			open.OutEventID = &id
			open.EndedAt = &at
			lowConf(p, open)
			if open.Duration() > r.MaxPlausibleSpan {
				open.flag(AnomalyImplausible)
			}
			if !BusinessDate(open.StartedAt, r).Equal(BusinessDate(at, r)) {
				open.flag(AnomalyOvernight)
			}
			closeSpan(open)
			open = nil
		}

		lastDir, lastAt, havePrev = p.Direction, p.At, true
	}

	// Still clocked in at the end of the window.
	if open != nil {
		open.flag(AnomalyMissingOut)
		closeSpan(open)
	}
	return spans
}

// Schedule is the expectation a person is measured against.
type Schedule struct {
	Weekdays     map[time.Weekday]bool
	ExpectedIn   time.Duration // from local midnight
	ExpectedOut  time.Duration
	GraceMinutes int
}

func (s Schedule) AppliesOn(date time.Time) bool {
	if len(s.Weekdays) == 0 {
		return true
	}
	return s.Weekdays[date.Weekday()]
}

// Day is the rolled-up result for one person on one business date.
type Day struct {
	BusinessDate time.Time
	FirstInAt    *time.Time
	LastOutAt    *time.Time
	Total        time.Duration
	SpanCount    int
	IsPresent    bool
	IsLate       bool
	NeedsReview  bool
}

// Rollup summarises the spans belonging to one business date.
//
// NeedsReview is the important output. It is what puts a day in front of a
// human before it reaches payroll, and it is set by any anomaly, any open
// span, or any timestamp the gateway could not vouch for.
func Rollup(date time.Time, spans []Span, sched *Schedule, r Rules) Day {
	d := Day{BusinessDate: date, SpanCount: len(spans)}

	for i := range spans {
		s := spans[i]

		// A missing_in marker is evidence of presence, but its "start" is
		// really an exit time and must not count as an arrival.
		isOrphanOut := s.InEventID == nil && s.OutEventID != nil

		if !isOrphanOut {
			d.IsPresent = true
			if d.FirstInAt == nil || s.StartedAt.Before(*d.FirstInAt) {
				at := s.StartedAt
				d.FirstInAt = &at
			}
		}
		if s.EndedAt != nil && (d.LastOutAt == nil || s.EndedAt.After(*d.LastOutAt)) {
			at := *s.EndedAt
			d.LastOutAt = &at
		}
		d.Total += s.Duration()
		if len(s.Anomalies) > 0 || s.Open() {
			d.NeedsReview = true
		}
	}

	if sched != nil && d.FirstInAt != nil && sched.AppliesOn(date) {
		local := d.FirstInAt.In(r.Location)
		sinceMidnight := time.Duration(local.Hour())*time.Hour +
			time.Duration(local.Minute())*time.Minute +
			time.Duration(local.Second())*time.Second
		grace := time.Duration(sched.GraceMinutes) * time.Minute
		d.IsLate = sinceMidnight > sched.ExpectedIn+grace
	}
	return d
}

// GroupByBusinessDate buckets spans by the day they should report against.
//
// A span is attributed to the day it STARTED, so an overnight shift lands
// wholly on the day it began rather than being split across two days with
// half the hours on each.
func GroupByBusinessDate(spans []Span, r Rules) map[time.Time][]Span {
	out := make(map[time.Time][]Span)
	for _, s := range spans {
		d := BusinessDate(s.StartedAt, r)
		out[d] = append(out[d], s)
	}
	return out
}
