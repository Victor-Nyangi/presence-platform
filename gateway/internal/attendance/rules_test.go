package attendance

import (
	"testing"
	"time"
)

func nairobi(t *testing.T) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation("Africa/Nairobi")
	if err != nil {
		t.Fatalf("tzdata missing — the embedded time/tzdata import is what makes this work on distroless: %v", err)
	}
	return loc
}

func rules(t *testing.T) Rules { return DefaultRules(nairobi(t)) }

// at builds a local time on 2026-08-18 (a Tuesday) unless a day offset is given.
func at(t *testing.T, day int, hour, min int) time.Time {
	t.Helper()
	return time.Date(2026, 8, day, hour, min, 0, 0, nairobi(t))
}

func punch(id int64, ts time.Time, dir Direction) Punch {
	return Punch{EventID: id, At: ts, Direction: dir, Confidence: "high"}
}

func hasAnomaly(s Span, want string) bool {
	for _, a := range s.Anomalies {
		if a == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------
// Business date
// ---------------------------------------------------------------------

// The bug this prevents: a nurse clocking out at 02:00 being reported on the
// wrong day, splitting one night shift across two days' totals.
func TestBusinessDateBeforeBoundaryBelongsToPreviousDay(t *testing.T) {
	r := rules(t)
	cases := []struct {
		name    string
		in      time.Time
		wantDay int
	}{
		{"just after midnight", at(t, 18, 0, 30), 17},
		{"02:00 night shift exit", at(t, 18, 2, 0), 17},
		{"03:59, one minute before the boundary", at(t, 18, 3, 59), 17},
		{"04:00, exactly the boundary", at(t, 18, 4, 0), 18},
		{"morning arrival", at(t, 18, 7, 30), 18},
		{"late evening", at(t, 18, 23, 45), 18},
	}
	for _, c := range cases {
		got := BusinessDate(c.in, r)
		if got.Day() != c.wantDay {
			t.Errorf("%s: %v → day %d, want %d", c.name, c.in, got.Day(), c.wantDay)
		}
	}
}

func TestBusinessDateIsMidnightLocal(t *testing.T) {
	r := rules(t)
	d := BusinessDate(at(t, 18, 14, 22), r)
	if d.Hour() != 0 || d.Minute() != 0 || d.Second() != 0 {
		t.Errorf("business date should be local midnight, got %v", d)
	}
	if d.Location().String() != "Africa/Nairobi" {
		t.Errorf("location = %v, want Africa/Nairobi", d.Location())
	}
}

// A midnight boundary must still work, for customers who want calendar days.
func TestBusinessDateWithMidnightBoundary(t *testing.T) {
	r := rules(t)
	r.DayBoundary = 0
	if got := BusinessDate(at(t, 18, 2, 0), r); got.Day() != 18 {
		t.Errorf("with a midnight boundary, 02:00 belongs to the same day, got %d", got.Day())
	}
}

// ---------------------------------------------------------------------
// Pairing — the happy path and then everything people actually do
// ---------------------------------------------------------------------

func TestPairSimpleInOut(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 17, 0), DirOut),
	}, r)

	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	if spans[0].Duration() != 9*time.Hour {
		t.Errorf("duration = %v, want 9h", spans[0].Duration())
	}
	if len(spans[0].Anomalies) != 0 {
		t.Errorf("clean day should have no anomalies, got %v", spans[0].Anomalies)
	}
}

func TestPairSplitShiftProducesTwoSpans(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 12, 0), DirOut),
		punch(3, at(t, 18, 13, 0), DirIn),
		punch(4, at(t, 18, 17, 0), DirOut),
	}, r)

	if len(spans) != 2 {
		t.Fatalf("want 2 spans, got %d", len(spans))
	}
	total := spans[0].Duration() + spans[1].Duration()
	if total != 8*time.Hour {
		t.Errorf("total = %v, want 8h (lunch excluded)", total)
	}
}

// Forgetting to clock out must not silently extend the shift into the next
// clock-in. That would turn a mistake into paid hours.
func TestPairTwoInsDoesNotMergeIntoOneLongShift(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 14, 0), DirIn), // forgot to clock out at lunch
		punch(3, at(t, 18, 17, 0), DirOut),
	}, r)

	if len(spans) != 2 {
		t.Fatalf("want 2 spans, got %d", len(spans))
	}
	if !hasAnomaly(spans[0], AnomalyMissingOut) {
		t.Errorf("first span should be flagged missing_out, got %v", spans[0].Anomalies)
	}
	if !spans[0].Open() {
		t.Error("an unterminated span must stay open")
	}
	if spans[0].Duration() != 0 {
		t.Errorf("an open span must accrue zero time, got %v", spans[0].Duration())
	}
	if spans[1].Duration() != 3*time.Hour {
		t.Errorf("second span = %v, want 3h", spans[1].Duration())
	}
}

func TestPairTrailingInStaysOpen(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{punch(1, at(t, 18, 8, 0), DirIn)}, r)

	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	if !spans[0].Open() || !hasAnomaly(spans[0], AnomalyMissingOut) {
		t.Errorf("still-clocked-in span should be open and flagged, got %+v", spans[0])
	}
}

// Someone clocks out on a reader they never clocked in on. The punch is real
// and must remain visible rather than being dropped.
func TestPairOrphanOutIsRecordedNotDiscarded(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{punch(1, at(t, 18, 17, 0), DirOut)}, r)

	if len(spans) != 1 {
		t.Fatalf("orphan out must still produce a record, got %d spans", len(spans))
	}
	if !hasAnomaly(spans[0], AnomalyMissingIn) {
		t.Errorf("want missing_in, got %v", spans[0].Anomalies)
	}
	if spans[0].InEventID != nil {
		t.Error("orphan out must not invent an in event")
	}
	if spans[0].Duration() != 0 {
		t.Errorf("orphan out must contribute no time, got %v", spans[0].Duration())
	}
}

func TestPairDuplicateTapIsSuppressed(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 8, 0).Add(20*time.Second), DirIn), // tapped again, missed the beep
		punch(3, at(t, 18, 17, 0), DirOut),
	}, r)

	if len(spans) != 1 {
		t.Fatalf("a double tap is one arrival, got %d spans", len(spans))
	}
	if !hasAnomaly(spans[0], AnomalyDuplicate) {
		t.Errorf("suppression should still be recorded, got %v", spans[0].Anomalies)
	}
	if spans[0].Duration() != 9*time.Hour {
		t.Errorf("duration = %v, want 9h", spans[0].Duration())
	}
}

// Outside the window it is a real second action, not a mis-tap.
func TestPairRepeatOutsideWindowIsNotADuplicate(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 8, 10), DirIn), // ten minutes later
		punch(3, at(t, 18, 17, 0), DirOut),
	}, r)

	if len(spans) != 2 {
		t.Fatalf("want 2 spans, got %d", len(spans))
	}
}

func TestPairOvernightShiftIsFlaggedAndNotSplit(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 17, 20, 0), DirIn),
		punch(2, at(t, 18, 6, 0), DirOut),
	}, r)

	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	if spans[0].Duration() != 10*time.Hour {
		t.Errorf("duration = %v, want 10h", spans[0].Duration())
	}
	if !hasAnomaly(spans[0], AnomalyOvernight) {
		t.Errorf("want overnight flag, got %v", spans[0].Anomalies)
	}
	// The whole shift reports against the day it began.
	grouped := GroupByBusinessDate(spans, r)
	if len(grouped) != 1 {
		t.Fatalf("overnight shift must not be split across days, got %d days", len(grouped))
	}
	for d := range grouped {
		if d.Day() != 17 {
			t.Errorf("shift attributed to day %d, want 17 (the day it started)", d.Day())
		}
	}
}

func TestPairImplausibleDurationIsFlaggedNotTruncated(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 17, 8, 0), DirIn),
		punch(2, at(t, 18, 20, 0), DirOut), // 36 hours
	}, r)

	if !hasAnomaly(spans[0], AnomalyImplausible) {
		t.Errorf("want implausible flag, got %v", spans[0].Anomalies)
	}
	if spans[0].Duration() != 36*time.Hour {
		t.Errorf("duration must not be silently truncated, got %v", spans[0].Duration())
	}
}

func TestPairPropagatesLowConfidence(t *testing.T) {
	r := rules(t)
	p := punch(1, at(t, 18, 8, 0), DirIn)
	p.Confidence = "low" // reconstructed from uptime after a dead RTC
	spans := Pair([]Punch{p, punch(2, at(t, 18, 17, 0), DirOut)}, r)

	if !hasAnomaly(spans[0], AnomalyLowConfidence) {
		t.Errorf("a reconstructed timestamp must be visible downstream, got %v", spans[0].Anomalies)
	}
}

func TestPairSortsUnorderedInput(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(2, at(t, 18, 17, 0), DirOut),
		punch(1, at(t, 18, 8, 0), DirIn),
	}, r)

	if len(spans) != 1 || spans[0].Duration() != 9*time.Hour {
		t.Fatalf("backfilled events arriving out of order must still pair: %+v", spans)
	}
}

func TestPairEmptyInput(t *testing.T) {
	if got := Pair(nil, rules(t)); got != nil {
		t.Errorf("want nil for no punches, got %v", got)
	}
}

// ---------------------------------------------------------------------
// Rollup
// ---------------------------------------------------------------------

func schedule() *Schedule {
	return &Schedule{
		Weekdays: map[time.Weekday]bool{
			time.Monday: true, time.Tuesday: true, time.Wednesday: true,
			time.Thursday: true, time.Friday: true,
		},
		ExpectedIn:   8 * time.Hour,
		ExpectedOut:  17 * time.Hour,
		GraceMinutes: 10,
	}
}

func TestRollupCleanDay(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 7, 55), DirIn),
		punch(2, at(t, 18, 17, 5), DirOut),
	}, r)
	d := Rollup(BusinessDate(at(t, 18, 7, 55), r), spans, schedule(), r)

	if !d.IsPresent {
		t.Error("want present")
	}
	if d.IsLate {
		t.Error("arriving at 07:55 is not late")
	}
	if d.NeedsReview {
		t.Error("a clean day should not need review")
	}
	if d.Total != 9*time.Hour+10*time.Minute {
		t.Errorf("total = %v", d.Total)
	}
}

func TestRollupGracePeriod(t *testing.T) {
	r := rules(t)
	for _, c := range []struct {
		name     string
		arrival  time.Time
		wantLate bool
	}{
		{"on time", at(t, 18, 8, 0), false},
		{"within grace", at(t, 18, 8, 9), false},
		{"exactly at grace", at(t, 18, 8, 10), false},
		{"one minute past grace", at(t, 18, 8, 11), true},
	} {
		spans := Pair([]Punch{
			punch(1, c.arrival, DirIn),
			punch(2, at(t, 18, 17, 0), DirOut),
		}, r)
		d := Rollup(BusinessDate(c.arrival, r), spans, schedule(), r)
		if d.IsLate != c.wantLate {
			t.Errorf("%s (%v): late = %v, want %v", c.name, c.arrival, d.IsLate, c.wantLate)
		}
	}
}

// Saturday is not a working day on this schedule, so nobody is late on it.
func TestRollupNotLateOnANonScheduledDay(t *testing.T) {
	r := rules(t)
	saturday := at(t, 22, 11, 0) // 2026-08-22
	if saturday.Weekday() != time.Saturday {
		t.Fatalf("fixture wrong: %v is %v", saturday, saturday.Weekday())
	}
	spans := Pair([]Punch{
		punch(1, saturday, DirIn),
		punch(2, at(t, 22, 15, 0), DirOut),
	}, r)
	d := Rollup(BusinessDate(saturday, r), spans, schedule(), r)

	if d.IsLate {
		t.Error("weekend work should not be marked late against a weekday schedule")
	}
	if !d.IsPresent {
		t.Error("but it is still presence")
	}
}

func TestRollupAnyAnomalyForcesReview(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{punch(1, at(t, 18, 8, 0), DirIn)}, r) // never clocked out
	d := Rollup(BusinessDate(at(t, 18, 8, 0), r), spans, schedule(), r)

	if !d.NeedsReview {
		t.Error("a missing clock-out must reach a human before payroll")
	}
	if d.Total != 0 {
		t.Errorf("an open span must contribute no hours, got %v", d.Total)
	}
	if !d.IsPresent {
		t.Error("they were still present")
	}
}

// An orphan clock-out is evidence of presence, but its timestamp is an exit,
// not an arrival — using it as first_in would report a wildly late arrival.
func TestRollupOrphanOutIsNotTreatedAsArrival(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{punch(1, at(t, 18, 17, 0), DirOut)}, r)
	d := Rollup(BusinessDate(at(t, 18, 17, 0), r), spans, schedule(), r)

	if d.FirstInAt != nil {
		t.Errorf("orphan out must not become first_in, got %v", d.FirstInAt)
	}
	if d.IsLate {
		t.Error("no arrival means no lateness verdict")
	}
	if !d.NeedsReview {
		t.Error("want review")
	}
}

func TestRollupUsesEarliestInAndLatestOut(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 8, 0), DirIn),
		punch(2, at(t, 18, 12, 0), DirOut),
		punch(3, at(t, 18, 13, 0), DirIn),
		punch(4, at(t, 18, 17, 30), DirOut),
	}, r)
	d := Rollup(BusinessDate(at(t, 18, 8, 0), r), spans, schedule(), r)

	if d.FirstInAt.Hour() != 8 {
		t.Errorf("first_in = %v, want 08:00", d.FirstInAt)
	}
	if d.LastOutAt.Hour() != 17 || d.LastOutAt.Minute() != 30 {
		t.Errorf("last_out = %v, want 17:30", d.LastOutAt)
	}
	if d.SpanCount != 2 {
		t.Errorf("span count = %d, want 2", d.SpanCount)
	}
}

func TestRollupEmptyDay(t *testing.T) {
	r := rules(t)
	d := Rollup(BusinessDate(at(t, 18, 8, 0), r), nil, schedule(), r)
	if d.IsPresent || d.NeedsReview || d.Total != 0 || d.SpanCount != 0 {
		t.Errorf("absent day should be inert, got %+v", d)
	}
}

func TestRollupWithoutScheduleNeverMarksLate(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 18, 11, 0), DirIn),
		punch(2, at(t, 18, 17, 0), DirOut),
	}, r)
	d := Rollup(BusinessDate(at(t, 18, 11, 0), r), spans, nil, r)

	if d.IsLate {
		t.Error("no schedule means no expectation to be late against")
	}
}

// The night-shift end-to-end case, where the day boundary, the overnight
// flag and grouping all have to agree.
//
// The point of a 04:00 boundary is that an ordinary night shift is NOT an
// anomaly. 19:00 → 03:30 crosses midnight but stays inside one business day,
// so it should roll up clean and never reach a reviewer. If this day were
// flagged, every night nurse would generate a review item every shift and the
// queue would be useless within a week.
func TestOrdinaryNightShiftIsNotAnAnomaly(t *testing.T) {
	r := rules(t)
	spans := Pair([]Punch{
		punch(1, at(t, 17, 19, 0), DirIn),  // Monday evening
		punch(2, at(t, 18, 3, 30), DirOut), // Tuesday, before the 04:00 boundary
	}, r)

	if hasAnomaly(spans[0], AnomalyOvernight) {
		t.Error("a shift inside one business day must not be flagged overnight")
	}

	grouped := GroupByBusinessDate(spans, r)
	if len(grouped) != 1 {
		t.Fatalf("one shift, one business day; got %d", len(grouped))
	}
	for date, s := range grouped {
		if date.Day() != 17 {
			t.Errorf("reported against day %d, want 17", date.Day())
		}
		d := Rollup(date, s, nil, r)
		if d.Total != 8*time.Hour+30*time.Minute {
			t.Errorf("total = %v, want 8h30m", d.Total)
		}
		if d.NeedsReview {
			t.Error("a routine night shift should roll up clean, not queue for review")
		}
	}
}

// The flag means "crossed a business day", not "crossed midnight". Only a
// shift running past the 04:00 boundary genuinely spans two reporting days.
func TestOvernightFlagTracksBusinessDaysNotMidnight(t *testing.T) {
	r := rules(t)
	for _, c := range []struct {
		name     string
		in, out  time.Time
		wantFlag bool
	}{
		{"ends before the boundary", at(t, 17, 19, 0), at(t, 18, 3, 30), false},
		{"ends exactly at the boundary", at(t, 17, 19, 0), at(t, 18, 4, 0), true},
		{"ends after the boundary", at(t, 17, 20, 0), at(t, 18, 6, 0), true},
		{"never crosses midnight", at(t, 18, 8, 0), at(t, 18, 17, 0), false},
	} {
		spans := Pair([]Punch{punch(1, c.in, DirIn), punch(2, c.out, DirOut)}, r)
		if got := hasAnomaly(spans[0], AnomalyOvernight); got != c.wantFlag {
			t.Errorf("%s: overnight = %v, want %v", c.name, got, c.wantFlag)
		}
	}
}
