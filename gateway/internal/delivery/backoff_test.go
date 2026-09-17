package delivery

import (
	"testing"
	"time"
)

func TestBackoffScheduleDoublesThenCaps(t *testing.T) {
	want := []time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second,
		256 * time.Second, 300 * time.Second, 300 * time.Second,
	}
	for i, w := range want {
		attempt := i + 1
		if got := backoffFor(attempt); got != w {
			t.Errorf("backoffFor(%d) = %v, want %v", attempt, got, w)
		}
	}
}

func TestBackoffScheduleTotalIsAboutNineteenMinutes(t *testing.T) {
	var total time.Duration
	for attempt := 1; attempt <= MaxAttempts-1; attempt++ {
		total += backoffFor(attempt)
	}
	// 1+2+4+...+256 + 300+300 = 1111s ~= 18m31s. Pinned loosely (a minute
	// either side) so the schedule can't silently drift into "a subscriber
	// down for an hour gets an hour of retries" without a test noticing.
	if total < 18*time.Minute || total > 19*time.Minute {
		t.Errorf("total backoff before dead-letter = %v, want ~18-19 minutes", total)
	}
}

func TestBackoffPastScheduleEndStaysCapped(t *testing.T) {
	if got := backoffFor(50); got != 300*time.Second {
		t.Errorf("backoffFor(50) = %v, want the 300s cap", got)
	}
}

func TestBackoffBelowOneIsTreatedAsFirst(t *testing.T) {
	if got := backoffFor(0); got != 1*time.Second {
		t.Errorf("backoffFor(0) = %v, want 1s", got)
	}
}
