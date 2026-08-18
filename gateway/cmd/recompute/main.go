// Command recompute rebuilds derived attendance from the raw event log.
//
// Run it after changing a schedule, a grace period, or a day boundary; after
// entering corrections as amendments; or on a nightly cron to close out the
// previous day. It is safe to run repeatedly and safe to run over a window
// that has already been computed — attendance_span and attendance_day hold
// nothing that cannot be rebuilt from punch_event plus punch_amendment.
//
//	recompute -org <uuid> -from 2026-08-01 -to 2026-08-31
//	recompute -org <uuid> -days 7          # the last week
//	recompute -org <uuid> -days 1 -review  # and print what needs a human
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/attendance"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		orgID   = flag.String("org", "", "organisation UUID (required)")
		fromStr = flag.String("from", "", "start date, YYYY-MM-DD")
		toStr   = flag.String("to", "", "end date, YYYY-MM-DD (inclusive)")
		days    = flag.Int("days", 0, "recompute the last N days instead of -from/-to")
		review  = flag.Bool("review", false, "print the review queue afterwards")
		dsn     = flag.String("db", os.Getenv("PRESENCE_DATABASE_URL"), "database URL")
	)
	flag.Parse()

	if *orgID == "" {
		return fmt.Errorf("-org is required")
	}
	if *dsn == "" {
		return fmt.Errorf("set -db or PRESENCE_DATABASE_URL")
	}

	from, to, err := window(*fromStr, *toStr, *days)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, *dsn)
	if err != nil {
		return err
	}
	defer pool.Close()

	eng := attendance.NewEngine(pool)

	started := time.Now()
	res, err := eng.Recompute(ctx, *orgID, from, to)
	if err != nil {
		return err
	}
	fmt.Printf("recomputed %s → %s in %s\n",
		from.Format("2006-01-02"), to.Format("2006-01-02"), time.Since(started).Round(time.Millisecond))
	fmt.Printf("  %d people, %d days, %d spans, %d flagged for review\n",
		res.People, res.Days, res.Spans, res.NeedsReview)

	if res.NeedsReview > 0 && !*review {
		fmt.Printf("  (re-run with -review to list them)\n")
	}
	if !*review {
		return nil
	}

	items, err := eng.ReviewQueue(ctx, *orgID, from, to, 200)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		fmt.Println("\nnothing needs review")
		return nil
	}

	fmt.Println("\nneeds review:")
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "  DATE\tPERSON\tHOURS\tSPANS\tWHY")
	for _, it := range items {
		fmt.Fprintf(w, "  %s\t%s\t%.2f\t%d\t%v\n",
			it.BusinessDate.Format("2006-01-02"), it.FullName,
			float64(it.TotalSeconds)/3600, it.SpanCount, it.Anomalies)
	}
	return w.Flush()
}

func window(fromStr, toStr string, days int) (time.Time, time.Time, error) {
	if days > 0 {
		// Anchored at midday so the window is unambiguous regardless of the
		// organisation's day boundary — the engine derives business dates
		// itself and pads the fetch either side.
		now := time.Now()
		to := time.Date(now.Year(), now.Month(), now.Day(), 12, 0, 0, 0, time.UTC)
		return to.AddDate(0, 0, -(days - 1)), to, nil
	}
	if fromStr == "" || toStr == "" {
		return time.Time{}, time.Time{}, fmt.Errorf("give either -days or both -from and -to")
	}
	from, err := time.Parse("2006-01-02", fromStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bad -from: %w", err)
	}
	to, err := time.Parse("2006-01-02", toStr)
	if err != nil {
		return time.Time{}, time.Time{}, fmt.Errorf("bad -to: %w", err)
	}
	if to.Before(from) {
		return time.Time{}, time.Time{}, fmt.Errorf("-to is before -from")
	}
	return from.Add(12 * time.Hour), to.Add(12 * time.Hour), nil
}
