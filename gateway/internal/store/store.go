// Package store holds all SQL. Handlers do no query building; if you need a
// new query it goes here, so the data-access rules stay in one file.
package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"presence/internal/cryptobox"
	"presence/internal/model"
)

var (
	ErrDeviceUnknown   = errors.New("store: device not found")
	ErrDeviceSuspended = errors.New("store: device suspended")
	ErrTokenInvalid    = errors.New("store: provisioning token invalid or consumed")
)

type Store struct {
	pool   *pgxpool.Pool
	keys   *cryptobox.Keyring
	pepper []byte
}

func New(pool *pgxpool.Pool, keys *cryptobox.Keyring, pepper []byte) *Store {
	return &Store{pool: pool, keys: keys, pepper: pepper}
}

func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// Device is the authenticated device context carried through a request.
type Device struct {
	ID            string
	OrgID         string
	SiteID        string
	State         string
	Mode          string
	Secrets       map[int][]byte // key_version -> raw HMAC secret
	LastAckSeq    int64
	ConfigVersion int
	RosterVersion int64
}

// LoadDevice fetches signing material. Both the current and previous device
// key are returned so an in-flight rotation cannot lock a terminal out.
func (s *Store) LoadDevice(ctx context.Context, id string) (*Device, error) {
	const q = `
		SELECT d.id::text, d.org_id::text, d.site_id::text, d.state::text, d.mode::text,
		       d.key_version, d.secret_enc, d.secret_nonce, d.secret_key_id,
		       d.prev_key_version, d.prev_secret_enc, d.prev_secret_nonce, d.prev_secret_key_id,
		       d.last_ack_seq, d.config_version, d.roster_version
		FROM device d WHERE d.id = $1`

	var (
		d                  Device
		keyVersion         int
		secEnc, secNonce   []byte
		secKeyID           *string
		prevVersion        *int
		prevEnc, prevNonce []byte
		prevKeyID          *string
	)
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&d.ID, &d.OrgID, &d.SiteID, &d.State, &d.Mode,
		&keyVersion, &secEnc, &secNonce, &secKeyID,
		&prevVersion, &prevEnc, &prevNonce, &prevKeyID,
		&d.LastAckSeq, &d.ConfigVersion, &d.RosterVersion,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrDeviceUnknown
	}
	if err != nil {
		return nil, err
	}
	if d.State == "suspended" || d.State == "retired" {
		return nil, ErrDeviceSuspended
	}

	d.Secrets = make(map[int][]byte, 2)
	// AAD binds each ciphertext to its device row, so a secret lifted from
	// one device's row cannot be replayed into another's.
	if len(secEnc) > 0 && secKeyID != nil {
		raw, err := s.keys.Open(secEnc, secNonce, *secKeyID, []byte(d.ID))
		if err != nil {
			return nil, fmt.Errorf("decrypt device secret: %w", err)
		}
		d.Secrets[keyVersion] = raw
	}
	if len(prevEnc) > 0 && prevKeyID != nil && prevVersion != nil {
		raw, err := s.keys.Open(prevEnc, prevNonce, *prevKeyID, []byte(d.ID))
		if err == nil {
			d.Secrets[*prevVersion] = raw
		}
	}
	if len(d.Secrets) == 0 {
		return nil, ErrDeviceUnknown
	}
	return &d, nil
}

// ---------------------------------------------------------------------
// Event ingest
// ---------------------------------------------------------------------

// IngestBatch stores a batch of punches idempotently and returns what the
// device may truncate.
//
// Ack semantics: ack_through is the highest sequence in THIS BATCH such that
// every batch sequence at or below it was durably stored. It is deliberately
// not a contiguity check against server-side history — a device that commits
// a sequence number to NVS and then loses power before using it leaves a
// permanent hole, and history-based contiguity would stall that device's
// buffer forever. The device sends from its buffer head in ascending order,
// so batch-relative contiguity is both sufficient and gap-tolerant.
//
// Rejected events still count as stored, and so still advance the ack. That
// is the point: otherwise one unresolvable event wedges the buffer and every
// punch behind it is stuck.
func (s *Store) IngestBatch(ctx context.Context, dev *Device, req model.EventsRequest, now time.Time) (model.EventsResponse, error) {
	resp := model.EventsResponse{
		Accepted:     []int64{},
		Duplicates:   []int64{},
		Rejected:     []model.Rejection{},
		AckThrough:   dev.LastAckSeq,
		ServerTimeMS: now.UnixMilli(),
	}

	events := append([]model.PunchEvent(nil), req.Events...)
	sort.Slice(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return resp, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	stored := make(map[int64]bool, len(events))

	for _, ev := range events {
		effective, conf := effectiveTime(ev, req.DeviceUptimeMS, now)

		status, reason, personID, credID := "unresolved", "", (*string)(nil), (*string)(nil)

		switch {
		case ev.Seq <= 0 || ev.EventUUID == "":
			reason = model.ReasonMalformed
		case effective.After(now.Add(5 * time.Minute)):
			// A timestamp from the future means a badly set clock. Keep the
			// event, clamp the effective time, flag it for review.
			reason = model.ReasonFutureTimestamp
			effective, conf = now, model.ConfLow
		default:
			status, reason, personID, credID, err = s.resolve(ctx, tx, dev, ev, effective)
			if err != nil {
				return resp, err
			}
		}

		direction := model.DirUnknown
		if status == "resolved" && personID != nil {
			direction, err = s.deriveDirection(ctx, tx, dev, *personID, effective)
			if err != nil {
				return resp, err
			}
		}

		inserted, err := s.insertEvent(ctx, tx, dev, ev, effective, conf, status, reason, personID, credID, direction, now)
		if err != nil {
			return resp, err
		}
		stored[ev.Seq] = true

		switch {
		case !inserted:
			resp.Duplicates = append(resp.Duplicates, ev.Seq)
		case status == "resolved":
			resp.Accepted = append(resp.Accepted, ev.Seq)
		default:
			resp.Rejected = append(resp.Rejected, model.Rejection{Seq: ev.Seq, Reason: reason})
		}
	}

	// Walk the batch in order; stop at the first sequence that did not store.
	ack := dev.LastAckSeq
	for _, ev := range events {
		if !stored[ev.Seq] {
			break
		}
		if ev.Seq > ack {
			ack = ev.Seq
		}
	}
	resp.AckThrough = ack

	if len(events) > 0 {
		if _, err := tx.Exec(ctx, `
			INSERT INTO sync_batch (device_id, seq_start, seq_end, accepted, duplicates, rejected, request_id)
			VALUES ($1,$2,$3,$4,$5,$6, NULLIF($7,'')::uuid)`,
			dev.ID, events[0].Seq, events[len(events)-1].Seq,
			len(resp.Accepted), len(resp.Duplicates), len(resp.Rejected), req.RequestID,
		); err != nil {
			return resp, err
		}
	}

	// GREATEST guards against an ack going backwards if batches race.
	if _, err := tx.Exec(ctx, `
		UPDATE device SET last_ack_seq = GREATEST(last_ack_seq, $2),
		                  last_buffer_depth = $3,
		                  last_seen_at = now()
		WHERE id = $1`, dev.ID, resp.AckThrough, req.BufferDepth); err != nil {
		return resp, err
	}

	if err := tx.Commit(ctx); err != nil {
		return resp, err
	}
	dev.LastAckSeq = resp.AckThrough
	return resp, nil
}

// effectiveTime turns what the device believed into what the platform will
// report on, and says how much to trust it.
func effectiveTime(ev model.PunchEvent, deviceUptimeMS int64, receivedAt time.Time) (time.Time, model.Confidence) {
	switch ev.TimeSource {
	case model.TimeRTCSynced:
		return ev.CapturedAt, model.ConfHigh
	case model.TimeRTCUnsynced:
		return ev.CapturedAt, model.ConfMedium
	case model.TimeUptimeOnly:
		// The RTC was never set. Reconstruct wall time by walking backwards
		// from the upload using the difference in device uptime.
		if deviceUptimeMS > 0 && ev.CapturedUptimeMS > 0 && deviceUptimeMS >= ev.CapturedUptimeMS {
			back := time.Duration(deviceUptimeMS-ev.CapturedUptimeMS) * time.Millisecond
			return receivedAt.Add(-back), model.ConfLow
		}
		return receivedAt, model.ConfLow
	default:
		return receivedAt, model.ConfLow
	}
}

// resolve maps what the reader saw to a person, AS OF the event's effective
// time — not as of now. That is what keeps history stable when a fingerprint
// slot is reassigned to a new member of staff.
func (s *Store) resolve(ctx context.Context, tx pgx.Tx, dev *Device, ev model.PunchEvent, effective time.Time) (status, reason string, personID, credID *string, err error) {
	if ev.CredentialKind == model.CredFingerprint {
		if ev.SlotNo == nil {
			return "unresolved", model.ReasonMalformed, nil, nil, nil
		}
		const q = `
			SELECT ds.person_id::text, ds.credential_id::text,
			       (c.revoked_at IS NOT NULL) AS revoked,
			       (p.active_to IS NOT NULL AND p.active_to < $3::date) AS inactive
			FROM device_slot ds
			JOIN credential c ON c.id = ds.credential_id
			JOIN person     p ON p.id = ds.person_id
			WHERE ds.device_id = $1 AND ds.slot_no = $2
			  AND ds.valid_from <= $4
			  AND (ds.valid_to IS NULL OR ds.valid_to > $4)
			LIMIT 1`
		var pid, cid string
		var revoked, inactive bool
		err := tx.QueryRow(ctx, q, dev.ID, *ev.SlotNo, effective, effective).Scan(&pid, &cid, &revoked, &inactive)
		if errors.Is(err, pgx.ErrNoRows) {
			return "unresolved", model.ReasonUnknownSlot, nil, nil, nil
		}
		if err != nil {
			return "", "", nil, nil, err
		}
		// Revoked or departed: keep the person link for the audit trail, but
		// do not let it count as a valid presence record.
		if revoked {
			return "unresolved", model.ReasonCredentialRevoked, &pid, &cid, nil
		}
		if inactive {
			return "unresolved", model.ReasonPersonInactive, &pid, &cid, nil
		}
		return "resolved", "", &pid, &cid, nil
	}

	// Card, tag, PIN, QR: the device sends an already-hashed reference so the
	// raw UID never travels or lands in a log.
	if ev.CredentialRef == "" {
		return "unresolved", model.ReasonMalformed, nil, nil, nil
	}
	raw, decErr := base64.StdEncoding.DecodeString(ev.CredentialRef)
	if decErr != nil {
		return "unresolved", model.ReasonMalformed, nil, nil, nil
	}
	const q = `
		SELECT c.person_id::text, c.id::text,
		       (p.active_to IS NOT NULL AND p.active_to < $3::date) AS inactive
		FROM credential c JOIN person p ON p.id = c.person_id
		WHERE c.org_id = $1 AND c.secret_hash = $2 AND c.revoked_at IS NULL
		LIMIT 1`
	var pid, cid string
	var inactive bool
	err = tx.QueryRow(ctx, q, dev.OrgID, raw, effective).Scan(&pid, &cid, &inactive)
	if errors.Is(err, pgx.ErrNoRows) {
		return "unresolved", model.ReasonUnknownSlot, nil, nil, nil
	}
	if err != nil {
		return "", "", nil, nil, err
	}
	if inactive {
		return "unresolved", model.ReasonPersonInactive, &pid, &cid, nil
	}
	return "resolved", "", &pid, &cid, nil
}

// deriveDirection computes canonical direction server-side. A device only
// ever offers a hint: a reader mounted at an entrance says "in", one at an
// exit says "out", and a bidirectional reader genuinely cannot tell — so for
// those we flip from the person's last known state.
func (s *Store) deriveDirection(ctx context.Context, tx pgx.Tx, dev *Device, personID string, effective time.Time) (model.Direction, error) {
	switch dev.Mode {
	case "entry":
		return model.DirIn, nil
	case "exit":
		return model.DirOut, nil
	}
	var last string
	err := tx.QueryRow(ctx, `
		SELECT direction::text FROM punch_event
		WHERE person_id = $1 AND effective_at < $2 AND status = 'resolved'
		ORDER BY effective_at DESC LIMIT 1`, personID, effective).Scan(&last)
	if errors.Is(err, pgx.ErrNoRows) {
		return model.DirIn, nil
	}
	if err != nil {
		return model.DirUnknown, err
	}
	if last == string(model.DirIn) {
		return model.DirOut, nil
	}
	return model.DirIn, nil
}

// insertEvent returns false when the row already existed, which is the
// idempotency path: the device retried a batch whose ack was lost.
func (s *Store) insertEvent(ctx context.Context, tx pgx.Tx, dev *Device, ev model.PunchEvent,
	effective time.Time, conf model.Confidence, status, reason string,
	personID, credID *string, direction model.Direction, now time.Time) (bool, error) {

	hint := ev.DirectionHint
	if hint == "" {
		hint = model.DirUnknown
	}
	var reasonPtr *string
	if reason != "" {
		reasonPtr = &reason
	}
	captured := ev.CapturedAt
	if captured.IsZero() {
		captured = effective
	}
	skew := now.Sub(captured).Milliseconds()
	backfilled := now.Sub(effective) > 2*time.Minute

	const q = `
		INSERT INTO punch_event (
			org_id, device_id, device_seq, event_uuid, credential_kind, slot_no,
			credential_ref, match_score, status, person_id, credential_id,
			unresolved_reason, captured_at, captured_uptime_ms, received_at,
			effective_at, src_time, time_conf, clock_skew_ms, is_backfilled,
			direction_hint, direction, raw)
		VALUES ($1,$2,$3,$4::uuid,$5::credential_kind,$6,$7,$8,$9::event_status,
		        $10::uuid,$11::uuid,$12,$13,$14,$15,$16,$17::time_source,
		        $18::time_confidence,$19,$20,$21::punch_direction,$22::punch_direction,$23)
		ON CONFLICT (device_id, device_seq) DO NOTHING
		RETURNING id`

	var id int64
	err := tx.QueryRow(ctx, q,
		dev.OrgID, dev.ID, ev.Seq, ev.EventUUID, string(ev.CredentialKind), ev.SlotNo,
		nullIfEmpty(ev.CredentialRef), ev.MatchScore, status, personID, credID,
		reasonPtr, captured, nullIfZero(ev.CapturedUptimeMS), now,
		effective, string(ev.TimeSource), string(conf), skew, backfilled,
		string(hint), string(direction), map[string]any{"device_mode": ev.DeviceMode},
	).Scan(&id)

	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // duplicate
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

func nullIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func nullIfZero(v int64) *int64 {
	if v == 0 {
		return nil
	}
	return &v
}

// ---------------------------------------------------------------------
// Heartbeat, commands, roster
// ---------------------------------------------------------------------

func (s *Store) Heartbeat(ctx context.Context, dev *Device, req model.HeartbeatRequest, now time.Time) (model.HeartbeatResponse, error) {
	var pending int
	if err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM device_command
		WHERE device_id = $1 AND status IN ('queued','delivered') AND expires_at > now()`,
		dev.ID).Scan(&pending); err != nil {
		return model.HeartbeatResponse{}, err
	}

	if _, err := s.pool.Exec(ctx, `
		UPDATE device SET last_seen_at = $2, last_buffer_depth = $3,
		                  last_rssi = $4, firmware_version = COALESCE(NULLIF($5,''), firmware_version)
		WHERE id = $1`,
		dev.ID, now, req.BufferDepth, req.RSSI, req.FirmwareVersion); err != nil {
		return model.HeartbeatResponse{}, err
	}

	return model.HeartbeatResponse{
		ServerTimeMS:    now.UnixMilli(),
		ConfigVersion:   dev.ConfigVersion,
		RosterVersion:   dev.RosterVersion,
		CommandsPending: pending,
		AckThrough:      dev.LastAckSeq,
	}, nil
}

func (s *Store) PendingCommands(ctx context.Context, dev *Device, limit int) ([]model.Command, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE device_command SET status = 'delivered', delivered_at = now(), attempts = attempts + 1
		WHERE id IN (
			SELECT id FROM device_command
			WHERE device_id = $1 AND status IN ('queued','delivered') AND expires_at > now()
			ORDER BY created_at LIMIT $2
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id::text, kind::text, payload, expires_at`, dev.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []model.Command{}
	for rows.Next() {
		var c model.Command
		var exp time.Time
		if err := rows.Scan(&c.ID, &c.Kind, &c.Payload, &exp); err != nil {
			return nil, err
		}
		c.ExpiresAt = &exp
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) RecordCommandResult(ctx context.Context, dev *Device, commandID string, res model.CommandResult) error {
	status := "failed"
	if res.Status == "succeeded" {
		status = "succeeded"
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE device_command
		SET status = $3::command_status, result = $4, error = NULLIF($5,''), completed_at = now()
		WHERE id = $1::uuid AND device_id = $2`,
		commandID, dev.ID, status, res.Result, res.Error)
	return err
}

// RosterDelta returns slot -> display name changes since the given version.
// Display names are truncated to what a small OLED can show, and nothing
// identifying beyond a name is ever sent to a terminal.
func (s *Store) RosterDelta(ctx context.Context, dev *Device, since int64) (model.RosterResponse, error) {
	resp := model.RosterResponse{
		RosterVersion: dev.RosterVersion,
		Upserts:       []model.RosterEntry{},
		Removals:      []int{},
		FullResync:    since <= 0,
	}
	rows, err := s.pool.Query(ctx, `
		SELECT ds.slot_no, left(p.full_name, 24), p.id::text, (ds.valid_to IS NOT NULL) AS removed
		FROM device_slot ds JOIN person p ON p.id = ds.person_id
		WHERE ds.device_id = $1
		ORDER BY ds.slot_no`, dev.ID)
	if err != nil {
		return resp, err
	}
	defer rows.Close()

	seen := map[int]bool{}
	for rows.Next() {
		var e model.RosterEntry
		var removed bool
		if err := rows.Scan(&e.SlotNo, &e.DisplayName, &e.PersonRef, &removed); err != nil {
			return resp, err
		}
		if removed {
			if !seen[e.SlotNo] {
				resp.Removals = append(resp.Removals, e.SlotNo)
			}
			continue
		}
		seen[e.SlotNo] = true
		resp.Upserts = append(resp.Upserts, e)
	}
	return resp, rows.Err()
}
