package delivery

import "time"

// MaxAttempts is the number of delivery attempts before an event is
// dead-lettered. Same shape as fhir-facade's own Subscription delivery
// worker (internal/subscription/backoff.go there): 1s doubling to a 5-minute
// cap, ~12 attempts, ~19 minutes total from first attempt to dead-letter.
// That number is not copied for its own sake — it is a deliberately chosen
// point: long enough that a subscriber's brief restart or deploy doesn't
// dead-letter every event in flight, short enough that a genuinely down
// subscriber doesn't sit at the head of the queue for hours while newer
// events for the same subject pile up behind it.
const MaxAttempts = 12

// backoffFor returns the delay before retry number `attempt` (1-indexed: the
// delay before the SECOND overall attempt, since the first is not a retry).
// Pure and unit-tested directly — the schedule is the one part of the
// worker worth pinning exactly, the same way rules.go pins attendance
// pairing logic independent of any database.
func backoffFor(attempt int) time.Duration {
	schedule := [...]time.Duration{
		1 * time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, 32 * time.Second, 64 * time.Second, 128 * time.Second,
		256 * time.Second, 300 * time.Second, 300 * time.Second,
	}
	if attempt < 1 {
		return schedule[0]
	}
	if attempt > len(schedule) {
		return schedule[len(schedule)-1]
	}
	return schedule[attempt-1]
}
