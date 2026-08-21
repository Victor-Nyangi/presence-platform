// Command seed creates the bench fixture: one organisation, one site, two
// people with fingerprint credentials, and one active device holding a
// sealed HMAC secret, with both slots bound.
//
// It exists because POST /v1/device/provision is deliberately a 501 until the
// installer flow is built, and a terminal cannot talk to the gateway without
// a secret. This is the smallest thing that unblocks a real device on a desk.
//
//	seed                    # seed the fixture, print the device secret
//	seed -reset             # tear the fixture down first (SEE BELOW)
//	seed -secret <hex64>    # pin the secret so it survives a re-seed
//
// -reset deletes this device's punch history. punch_event is append-only by
// trigger, so the teardown has to disable that trigger to do it. That is
// acceptable for a bench fixture and unacceptable anywhere else, which is why
// it is opt-in rather than the default.
//
// This is a development tool. It writes fixed UUIDs and it is not something
// to point at an environment holding real attendance data.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/config"
	"presence/internal/cryptobox"
)

// The same fixed identifiers the integration suites use, so a database seeded
// here is one you can also reason about from those tests.
const (
	orgID    = "11111111-1111-1111-1111-111111111111"
	siteID   = "22222222-2222-2222-2222-222222222222"
	ashaID   = "33333333-3333-3333-3333-333333333333"
	brianID  = "44444444-4444-4444-4444-444444444444"
	deviceID = "55555555-5555-5555-5555-555555555555"
	credA    = "66666666-6666-6666-6666-666666666666"
	credB    = "77777777-7777-7777-7777-777777777777"

	ashaSlot  = 42
	brianSlot = 43
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		dsn       = flag.String("db", "", "database URL (default: PRESENCE_DATABASE_URL)")
		mode      = flag.String("mode", "bidirectional", "device mode: entry, exit or bidirectional")
		secretHex = flag.String("secret", "", "pin the device secret (64 hex chars) instead of generating one")
		reset     = flag.Bool("reset", false, "tear down an existing fixture first, including this device's punch history")
	)
	flag.Parse()

	switch *mode {
	case "entry", "exit", "bidirectional":
	default:
		return fmt.Errorf("-mode must be entry, exit or bidirectional, got %q", *mode)
	}

	// Loading the gateway's own config means a successful seed also proves
	// the environment the gateway is about to boot with is well-formed.
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("%w\n(seed reads the same environment as the gateway; see .env.example)", err)
	}
	if *dsn != "" {
		cfg.DatabaseURL = *dsn
	}

	keyring, err := cryptobox.NewKeyring(cfg.KEKPrimaryID, cfg.KEKs)
	if err != nil {
		return err
	}

	secret, err := deviceSecret(*secretHex)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()

	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	exists, err := fixtureExists(ctx, pool)
	if err != nil {
		return err
	}
	if exists && !*reset {
		return errors.New("fixture already present; re-run with -reset to replace it " +
			"(this deletes the fixture device's punch history)")
	}

	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if *reset {
		if err := teardown(ctx, tx); err != nil {
			return err
		}
	}
	if err := seed(ctx, tx, keyring, secret, *mode); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}

	report(cfg.DatabaseURL, *mode, secret)
	return nil
}

func deviceSecret(pinned string) ([]byte, error) {
	if pinned == "" {
		secret, _, err := cryptobox.NewSecret()
		return secret, err
	}
	secret, err := hex.DecodeString(pinned)
	if err != nil {
		return nil, fmt.Errorf("-secret is not hex: %w", err)
	}
	if len(secret) != 32 {
		return nil, fmt.Errorf("-secret must be 32 bytes (64 hex chars), got %d", len(secret))
	}
	return secret, nil
}

func fixtureExists(ctx context.Context, pool *pgxpool.Pool) (bool, error) {
	var n int
	err := pool.QueryRow(ctx,
		`SELECT count(*) FROM organization WHERE id = $1`, orgID).Scan(&n)
	return n > 0, err
}

// teardown removes the fixture in foreign-key order.
//
// punch_event is append-only, enforced by a trigger rather than by
// convention, so the only way to clear the fixture device's history is to
// disable that trigger for the duration of the delete. Doing so inside the
// transaction keeps the window as narrow as it can be. Nothing outside this
// development tool should ever do this.
func teardown(ctx context.Context, tx pgx.Tx) error {
	stmts := []struct {
		what string
		sql  string
		args []any
	}{
		{"disable append-only trigger", `ALTER TABLE punch_event DISABLE TRIGGER punch_event_no_mutation`, nil},
		{"delete punch amendments", `DELETE FROM punch_amendment WHERE punch_event_id IN (SELECT id FROM punch_event WHERE device_id = $1)`, []any{deviceID}},
		{"delete attendance spans", `DELETE FROM attendance_span WHERE org_id = $1`, []any{orgID}},
		{"delete attendance days", `DELETE FROM attendance_day WHERE org_id = $1`, []any{orgID}},
		{"delete punch events", `DELETE FROM punch_event WHERE org_id = $1`, []any{orgID}},
		{"enable append-only trigger", `ALTER TABLE punch_event ENABLE TRIGGER punch_event_no_mutation`, nil},
		{"delete sync batches", `DELETE FROM sync_batch WHERE device_id = $1`, []any{deviceID}},
		{"delete device commands", `DELETE FROM device_command WHERE device_id = $1`, []any{deviceID}},
		{"delete notifications", `DELETE FROM notification WHERE org_id = $1`, []any{orgID}},
		{"delete slot bindings", `DELETE FROM device_slot WHERE device_id = $1`, []any{deviceID}},
		{"delete credentials", `DELETE FROM credential WHERE org_id = $1`, []any{orgID}},
		{"delete guardian links", `DELETE FROM guardian_person WHERE person_id IN (SELECT id FROM person WHERE org_id = $1)`, []any{orgID}},
		{"delete guardians", `DELETE FROM guardian WHERE org_id = $1`, []any{orgID}},
		{"delete person schedules", `DELETE FROM person_schedule WHERE person_id IN (SELECT id FROM person WHERE org_id = $1)`, []any{orgID}},
		{"delete schedules", `DELETE FROM schedule WHERE org_id = $1`, []any{orgID}},
		{"delete device", `DELETE FROM device WHERE org_id = $1`, []any{orgID}},
		{"delete people", `DELETE FROM person WHERE org_id = $1`, []any{orgID}},
		{"delete sites", `DELETE FROM site WHERE org_id = $1`, []any{orgID}},
		{"delete organization", `DELETE FROM organization WHERE id = $1`, []any{orgID}},
	}
	for _, s := range stmts {
		if _, err := tx.Exec(ctx, s.sql, s.args...); err != nil {
			return fmt.Errorf("teardown (%s): %w", s.what, err)
		}
	}
	return nil
}

func seed(ctx context.Context, tx pgx.Tx, keyring *cryptobox.Keyring, secret []byte, mode string) error {
	// AAD is the device id, exactly as store.LoadDevice expects when it
	// opens this ciphertext. A secret sealed without it will decrypt-fail at
	// the gateway rather than at seed time, which is a confusing place to
	// find out.
	encSecret, nonce, keyID, err := keyring.Seal(secret, []byte(deviceID))
	if err != nil {
		return fmt.Errorf("seal device secret: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO organization (id, name, kind, timezone)
		VALUES ($1, 'Rift Valley Academy', 'school', 'Africa/Nairobi')`, orgID); err != nil {
		return fmt.Errorf("insert organization: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO site (id, org_id, name) VALUES ($1, $2, 'Main Gate')`,
		siteID, orgID); err != nil {
		return fmt.Errorf("insert site: %w", err)
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO person (id, org_id, kind, external_ref, full_name) VALUES
			($1, $3, 'staff', 'EMP-001', 'Asha M.'),
			($2, $3, 'staff', 'EMP-002', 'Brian K.')`,
		ashaID, brianID, orgID); err != nil {
		return fmt.Errorf("insert people: %w", err)
	}

	// Placeholder template bytes. A real template arrives through the enroll
	// command; these exist only so device_slot has a credential to point at.
	if _, err := tx.Exec(ctx, `
		INSERT INTO credential
			(id, org_id, person_id, kind, template_ciphertext, template_nonce, template_key_id, template_vendor)
		VALUES
			($1, $3, $4, 'fingerprint', '\xdead', '\x0102030405060708090a0b0c', $6, 'grow_r307'),
			($2, $3, $5, 'fingerprint', '\xbeef', '\x0102030405060708090a0b0c', $6, 'grow_r307')`,
		credA, credB, orgID, ashaID, brianID, keyID); err != nil {
		return fmt.Errorf("insert credentials: %w", err)
	}

	if _, err := tx.Exec(ctx, `
		INSERT INTO device
			(id, org_id, site_id, label, serial, mode, state,
			 secret_enc, secret_nonce, secret_key_id, key_version)
		VALUES ($1, $2, $3, 'Gate Terminal 1', 'SN-0001', $4::device_mode, 'active',
		        $5, $6, $7, 1)`,
		deviceID, orgID, siteID, mode, encSecret, nonce, keyID); err != nil {
		return fmt.Errorf("insert device: %w", err)
	}

	// Open-ended bindings (valid_to NULL). Without these every punch resolves
	// as unknown_slot, which looks like a signing failure but is not.
	//
	// valid_from is backdated a year rather than set to now(). Bindings are
	// time-bounded and resolution happens AS OF the event's effective time,
	// so a binding that starts at this instant refuses every punch older than
	// this instant — including every event whose time was reconstructed from
	// an uptime delta, which is always in the past, and every event a device
	// uploads from a buffer filled before you ran seed. On a bench that
	// presents as unknown_slot and reads like a signing fault.
	if _, err := tx.Exec(ctx, `
		INSERT INTO device_slot (device_id, slot_no, credential_id, person_id, valid_from, valid_to)
		VALUES ($1, $2, $4, $6, now() - interval '1 year', NULL),
		       ($1, $3, $5, $7, now() - interval '1 year', NULL)`,
		deviceID, ashaSlot, brianSlot, credA, credB, ashaID, brianID); err != nil {
		return fmt.Errorf("bind slots: %w", err)
	}
	return nil
}

func report(dsn, mode string, secret []byte) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "org\t%s\tRift Valley Academy\n", orgID)
	fmt.Fprintf(w, "site\t%s\tMain Gate\n", siteID)
	fmt.Fprintf(w, "person\t%s\tAsha M.  slot %d\n", ashaID, ashaSlot)
	fmt.Fprintf(w, "person\t%s\tBrian K. slot %d\n", brianID, brianSlot)
	fmt.Fprintf(w, "device\t%s\tSN-0001 (%s, active)\n", deviceID, mode)
	_ = w.Flush()

	fmt.Printf("\nDEVICE_SECRET  %s\n", hex.EncodeToString(secret))
	fmt.Printf("key_version    1\n")
	fmt.Printf("\nThe secret is not stored in recoverable form anywhere else — the row holds\n")
	fmt.Printf("only ciphertext. Re-run with -reset to issue a new one.\n")
}
