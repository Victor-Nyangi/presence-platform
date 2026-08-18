package attendance

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// lookbackDays is how far outside the requested window events are fetched.
//
// Pairing needs the surrounding sequence, not just the window. Someone who
// clocked in at 22:00 on the day before the window and out at 06:00 inside it
// would otherwise look like an orphan clock-out. Two days is comfortably more
// than the longest plausible shift, so the padding never changes a result —
// it only prevents the window edge from inventing anomalies.
const lookbackDays = 2

type Engine struct {
	pool *pgxpool.Pool
}

func NewEngine(pool *pgxpool.Pool) *Engine { return &Engine{pool: pool} }

type Result struct {
	People      int
	Days        int
	Spans       int
	NeedsReview int
}

// Recompute rebuilds derived attendance for an organisation over a date range.
//
// This is destructive-and-rebuild by design, and safe to run as often as you
// like: attendance_span and attendance_day hold NOTHING that cannot be
// regenerated from punch_event plus punch_amendment. That is the whole reason
// the event log is append-only. When a customer changes their grace period or
// day boundary six months in, you re-run this; you do not discover that
// ingest-time computation quietly destroyed the history.
func (e *Engine) Recompute(ctx context.Context, orgID string, from, to time.Time) (Result, error) {
	var res Result

	rules, err := e.orgRules(ctx, orgID)
	if err != nil {
		return res, err
	}

	fetchFrom := from.AddDate(0, 0, -lookbackDays)
	fetchTo := to.AddDate(0, 0, lookbackDays+1)

	byPerson, err := e.loadPunches(ctx, orgID, fetchFrom, fetchTo, rules)
	if err != nil {
		return res, err
	}

	schedules, err := e.loadSchedules(ctx, orgID)
	if err != nil {
		return res, err
	}

	windowStart := BusinessDate(from, rules)
	windowEnd := BusinessDate(to, rules)

	tx, err := e.pool.Begin(ctx)
	if err != nil {
		return res, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Clear the window first. Spans carry a unique index on in_event_id, so a
	// re-run would otherwise collide with its own previous output.
	if _, err := tx.Exec(ctx, `
		DELETE FROM attendance_span
		WHERE org_id = $1 AND business_date BETWEEN $2 AND $3`,
		orgID, windowStart, windowEnd); err != nil {
		return res, fmt.Errorf("clear spans: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		DELETE FROM attendance_day
		WHERE org_id = $1 AND business_date BETWEEN $2 AND $3`,
		orgID, windowStart, windowEnd); err != nil {
		return res, fmt.Errorf("clear days: %w", err)
	}

	for personID, punches := range byPerson {
		spans := Pair(punches, rules)
		grouped := GroupByBusinessDate(spans, rules)

		wrote := false
		for date, daySpans := range grouped {
			// Padding fetched extra days; only the requested window is written.
			if date.Before(windowStart) || date.After(windowEnd) {
				continue
			}
			wrote = true

			for _, s := range daySpans {
				if _, err := tx.Exec(ctx, `
					INSERT INTO attendance_span
						(org_id, person_id, site_id, business_date, in_event_id,
						 out_event_id, started_at, ended_at, anomalies)
					VALUES ($1,$2,NULL,$3,$4,$5,$6,$7,$8)`,
					orgID, personID, date, s.InEventID, s.OutEventID,
					s.StartedAt, s.EndedAt, anomalyArray(s.Anomalies),
				); err != nil {
					return res, fmt.Errorf("insert span: %w", err)
				}
				res.Spans++
			}

			day := Rollup(date, daySpans, schedules.forPerson(personID, date), rules)
			if _, err := tx.Exec(ctx, `
				INSERT INTO attendance_day
					(org_id, person_id, business_date, first_in_at, last_out_at,
					 total_s, span_count, is_present, is_late, needs_review)
				VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
				orgID, personID, date, day.FirstInAt, day.LastOutAt,
				int(day.Total.Seconds()), day.SpanCount,
				day.IsPresent, day.IsLate, day.NeedsReview,
			); err != nil {
				return res, fmt.Errorf("insert day: %w", err)
			}
			res.Days++
			if day.NeedsReview {
				res.NeedsReview++
			}
		}
		if wrote {
			res.People++
		}
	}

	return res, tx.Commit(ctx)
}

// anomalyArray keeps a nil slice out of a NOT NULL text[] column.
func anomalyArray(a []string) []string {
	if a == nil {
		return []string{}
	}
	return a
}

func (e *Engine) orgRules(ctx context.Context, orgID string) (Rules, error) {
	var tz string
	var boundary time.Time
	err := e.pool.QueryRow(ctx, `
		SELECT o.timezone,
		       COALESCE(
		         (SELECT s.day_boundary FROM schedule s WHERE s.org_id = o.id ORDER BY s.name LIMIT 1),
		         TIME '04:00'
		       )
		FROM organization o WHERE o.id = $1`, orgID).Scan(&tz, &boundary)
	if err != nil {
		return Rules{}, fmt.Errorf("load org rules: %w", err)
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		// Falling back to UTC would silently shift every reported day. Fail
		// loudly instead — a bad timezone is a data problem, not a runtime
		// condition to paper over.
		return Rules{}, fmt.Errorf("organization %s has unusable timezone %q: %w", orgID, tz, err)
	}
	r := DefaultRules(loc)
	r.DayBoundary = time.Duration(boundary.Hour())*time.Hour + time.Duration(boundary.Minute())*time.Minute
	return r, nil
}

// loadPunches reads resolved events and folds amendments over them.
//
// Amendments are additive rows rather than edits, because punch_event is
// immutable. Applying them here — rather than in SQL — keeps the precedence
// rule ("later amendment wins, per field") in one readable place.
func (e *Engine) loadPunches(ctx context.Context, orgID string, from, to time.Time, r Rules) (map[string][]Punch, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT pe.id, pe.person_id::text, pe.effective_at, pe.direction::text, pe.time_conf::text,
		       COALESCE(a.voided, false),
		       a.new_direction::text, a.new_effective_at, a.new_person_id::text
		FROM punch_event pe
		LEFT JOIN LATERAL (
			-- Latest amendment per event; a correction to a correction wins.
			SELECT bool_or(am.voided) AS voided,
			       (array_agg(am.new_direction    ORDER BY am.created_at DESC) FILTER (WHERE am.new_direction    IS NOT NULL))[1] AS new_direction,
			       (array_agg(am.new_effective_at ORDER BY am.created_at DESC) FILTER (WHERE am.new_effective_at IS NOT NULL))[1] AS new_effective_at,
			       (array_agg(am.new_person_id    ORDER BY am.created_at DESC) FILTER (WHERE am.new_person_id    IS NOT NULL))[1] AS new_person_id
			FROM punch_amendment am WHERE am.punch_event_id = pe.id
		) a ON true
		WHERE pe.org_id = $1
		  AND pe.status = 'resolved'
		  AND pe.person_id IS NOT NULL
		  AND pe.effective_at >= $2 AND pe.effective_at < $3
		ORDER BY pe.effective_at`, orgID, from, to)
	if err != nil {
		return nil, fmt.Errorf("load punches: %w", err)
	}
	defer rows.Close()

	out := map[string][]Punch{}
	for rows.Next() {
		var (
			id          int64
			personID    string
			effectiveAt time.Time
			direction   string
			conf        string
			voided      bool
			newDir      *string
			newAt       *time.Time
			newPerson   *string
		)
		if err := rows.Scan(&id, &personID, &effectiveAt, &direction, &conf,
			&voided, &newDir, &newAt, &newPerson); err != nil {
			return nil, err
		}
		if voided {
			continue // amended away; the raw event still exists in punch_event
		}
		if newDir != nil {
			direction = *newDir
		}
		if newAt != nil {
			effectiveAt = *newAt
		}
		if newPerson != nil {
			personID = *newPerson
		}
		// Directionless events cannot be paired. They are still in the raw
		// log and still visible in triage; they just cannot form a span.
		if direction != string(DirIn) && direction != string(DirOut) {
			continue
		}
		out[personID] = append(out[personID], Punch{
			EventID:    id,
			At:         effectiveAt.In(r.Location),
			Direction:  Direction(direction),
			Confidence: conf,
		})
	}
	return out, rows.Err()
}

type scheduleSet struct {
	byPerson map[string][]datedSchedule
}

type datedSchedule struct {
	from, to *time.Time
	sched    Schedule
}

func (s scheduleSet) forPerson(personID string, date time.Time) *Schedule {
	for _, ds := range s.byPerson[personID] {
		if ds.from != nil && date.Before(*ds.from) {
			continue
		}
		if ds.to != nil && date.After(*ds.to) {
			continue
		}
		sched := ds.sched
		return &sched
	}
	return nil
}

func (e *Engine) loadSchedules(ctx context.Context, orgID string) (scheduleSet, error) {
	set := scheduleSet{byPerson: map[string][]datedSchedule{}}
	rows, err := e.pool.Query(ctx, `
		SELECT ps.person_id::text, ps.effective_from, ps.effective_to,
		       s.weekdays, s.expected_in, s.expected_out, s.grace_minutes
		FROM person_schedule ps
		JOIN schedule s ON s.id = ps.schedule_id
		WHERE s.org_id = $1
		ORDER BY ps.effective_from DESC`, orgID)
	if err != nil {
		return set, fmt.Errorf("load schedules: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var (
			personID      string
			from          time.Time
			to            *time.Time
			weekdays      []int16
			expIn, expOut time.Time
			grace         int
		)
		if err := rows.Scan(&personID, &from, &to, &weekdays, &expIn, &expOut, &grace); err != nil {
			return set, err
		}
		days := map[time.Weekday]bool{}
		for _, w := range weekdays {
			// Postgres rows use ISO weekday numbers (1 = Monday, 7 = Sunday);
			// Go's time.Weekday is 0 = Sunday. Off-by-one here would mark the
			// wrong people late on the wrong days.
			days[time.Weekday(int(w)%7)] = true
		}
		set.byPerson[personID] = append(set.byPerson[personID], datedSchedule{
			from: &from,
			to:   to,
			sched: Schedule{
				Weekdays:     days,
				ExpectedIn:   clockDuration(expIn),
				ExpectedOut:  clockDuration(expOut),
				GraceMinutes: grace,
			},
		})
	}
	return set, rows.Err()
}

func clockDuration(t time.Time) time.Duration {
	return time.Duration(t.Hour())*time.Hour +
		time.Duration(t.Minute())*time.Minute +
		time.Duration(t.Second())*time.Second
}

// ReviewQueue returns the days a human should look at before this data is
// trusted for payroll.
func (e *Engine) ReviewQueue(ctx context.Context, orgID string, from, to time.Time, limit int) ([]ReviewItem, error) {
	rows, err := e.pool.Query(ctx, `
		SELECT ad.person_id::text, p.full_name, ad.business_date, ad.total_s,
		       ad.span_count, ad.is_present,
		       COALESCE((SELECT array_agg(DISTINCT x) FROM attendance_span s,
		                 unnest(s.anomalies) x
		                 WHERE s.person_id = ad.person_id
		                   AND s.business_date = ad.business_date), '{}') AS anomalies
		FROM attendance_day ad
		JOIN person p ON p.id = ad.person_id
		WHERE ad.org_id = $1 AND ad.needs_review
		  AND ad.business_date BETWEEN $2 AND $3
		ORDER BY ad.business_date DESC, p.full_name
		LIMIT $4`, orgID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ReviewItem
	for rows.Next() {
		var it ReviewItem
		if err := rows.Scan(&it.PersonID, &it.FullName, &it.BusinessDate,
			&it.TotalSeconds, &it.SpanCount, &it.IsPresent, &it.Anomalies); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

type ReviewItem struct {
	PersonID     string    `json:"person_id"`
	FullName     string    `json:"full_name"`
	BusinessDate time.Time `json:"business_date"`
	TotalSeconds int       `json:"total_seconds"`
	SpanCount    int       `json:"span_count"`
	IsPresent    bool      `json:"is_present"`
	Anomalies    []string  `json:"anomalies"`
}
