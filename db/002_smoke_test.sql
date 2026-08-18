-- Smoke test: exercises the invariants the schema is supposed to guarantee.
-- Run against a database that has had schema.sql applied.
\set ON_ERROR_STOP on

BEGIN;

INSERT INTO organization (id, name, kind) VALUES
    ('11111111-1111-1111-1111-111111111111', 'Rift Valley Academy', 'school');
INSERT INTO site (id, org_id, name) VALUES
    ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111', 'Main Gate');
INSERT INTO person (id, org_id, kind, external_ref, full_name) VALUES
    ('33333333-3333-3333-3333-333333333333', '11111111-1111-1111-1111-111111111111', 'staff', 'EMP-001', 'Asha M.'),
    ('44444444-4444-4444-4444-444444444444', '11111111-1111-1111-1111-111111111111', 'staff', 'EMP-002', 'Brian K.');
INSERT INTO device (id, org_id, site_id, label, serial, mode, state) VALUES
    ('55555555-5555-5555-5555-555555555555', '11111111-1111-1111-1111-111111111111',
     '22222222-2222-2222-2222-222222222222', 'Gate Terminal 1', 'SN-0001', 'bidirectional', 'active');
INSERT INTO credential (id, org_id, person_id, kind, template_ciphertext, template_nonce, template_key_id, template_vendor) VALUES
    ('66666666-6666-6666-6666-666666666666', '11111111-1111-1111-1111-111111111111',
     '33333333-3333-3333-3333-333333333333', 'fingerprint', '\xdeadbeef', '\x0102030405060708090a0b0c', 'k1', 'grow_r307'),
    ('77777777-7777-7777-7777-777777777777', '11111111-1111-1111-1111-111111111111',
     '44444444-4444-4444-4444-444444444444', 'fingerprint', '\xcafebabe', '\x0102030405060708090a0b0c', 'k1', 'grow_r307');

-- TEST 1 -------------------------------------------------------------
-- Slot 42 is held by Asha until Jun 30, then reassigned to Brian.
INSERT INTO device_slot (device_id, slot_no, credential_id, person_id, valid_from, valid_to) VALUES
    ('55555555-5555-5555-5555-555555555555', 42, '66666666-6666-6666-6666-666666666666',
     '33333333-3333-3333-3333-333333333333', '2026-01-01T00:00:00Z', '2026-06-30T00:00:00Z'),
    ('55555555-5555-5555-5555-555555555555', 42, '77777777-7777-7777-7777-777777777777',
     '44444444-4444-4444-4444-444444444444', '2026-07-01T00:00:00Z', NULL);

-- Historical resolution: a March punch on slot 42 must resolve to Asha,
-- an August punch on slot 42 must resolve to Brian.
DO $$
DECLARE march_person uuid; august_person uuid;
BEGIN
    SELECT person_id INTO march_person FROM device_slot
      WHERE device_id = '55555555-5555-5555-5555-555555555555' AND slot_no = 42
        AND valid_from <= '2026-03-15T08:00:00Z'
        AND (valid_to IS NULL OR valid_to > '2026-03-15T08:00:00Z');
    SELECT person_id INTO august_person FROM device_slot
      WHERE device_id = '55555555-5555-5555-5555-555555555555' AND slot_no = 42
        AND valid_from <= '2026-08-15T08:00:00Z'
        AND (valid_to IS NULL OR valid_to > '2026-08-15T08:00:00Z');
    ASSERT march_person = '33333333-3333-3333-3333-333333333333', 'March punch misresolved';
    ASSERT august_person = '44444444-4444-4444-4444-444444444444', 'August punch misresolved';
    RAISE NOTICE 'TEST 1 slot history resolution: PASS';
END $$;

-- TEST 2 -------------------------------------------------------------
-- Two live rows for the same physical slot must be impossible.
DO $$
BEGIN
    INSERT INTO device_slot (device_id, slot_no, credential_id, person_id) VALUES
        ('55555555-5555-5555-5555-555555555555', 42, '66666666-6666-6666-6666-666666666666',
         '33333333-3333-3333-3333-333333333333');
    RAISE EXCEPTION 'TEST 2 FAILED: duplicate live slot was accepted';
EXCEPTION WHEN unique_violation THEN
    RAISE NOTICE 'TEST 2 one live occupant per slot: PASS';
END $$;

-- TEST 3 -------------------------------------------------------------
-- Idempotent ingest: replaying the same (device_id, device_seq) is a no-op.
INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
                         slot_no, status, person_id, credential_id,
                         captured_at, effective_at, src_time, direction_hint, direction)
VALUES ('11111111-1111-1111-1111-111111111111', '55555555-5555-5555-5555-555555555555',
        1001, '88888888-8888-8888-8888-888888888888', 'fingerprint', 42, 'resolved',
        '44444444-4444-4444-4444-444444444444', '77777777-7777-7777-7777-777777777777',
        '2026-08-18T07:31:04Z', '2026-08-18T07:31:04Z', 'rtc_synced', 'in', 'in')
ON CONFLICT (device_id, device_seq) DO NOTHING;

INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
                         slot_no, status, person_id, credential_id,
                         captured_at, effective_at, src_time, direction_hint, direction)
VALUES ('11111111-1111-1111-1111-111111111111', '55555555-5555-5555-5555-555555555555',
        1001, '99999999-9999-9999-9999-999999999999', 'fingerprint', 42, 'resolved',
        '44444444-4444-4444-4444-444444444444', '77777777-7777-7777-7777-777777777777',
        '2026-08-18T07:31:04Z', '2026-08-18T07:31:04Z', 'rtc_synced', 'in', 'in')
ON CONFLICT (device_id, device_seq) DO NOTHING;

DO $$
DECLARE n integer;
BEGIN
    SELECT count(*) INTO n FROM punch_event WHERE device_seq = 1001;
    ASSERT n = 1, format('TEST 3 FAILED: expected 1 row, got %s', n);
    RAISE NOTICE 'TEST 3 replay idempotency: PASS';
END $$;

-- TEST 4 -------------------------------------------------------------
-- An unresolved event is still stored (rejected != discarded), but it may
-- not claim resolved status without a person.
INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
                         slot_no, status, unresolved_reason,
                         captured_at, effective_at, src_time, time_conf, is_backfilled)
VALUES ('11111111-1111-1111-1111-111111111111', '55555555-5555-5555-5555-555555555555',
        1002, gen_random_uuid(), 'fingerprint', 999, 'unresolved', 'unknown_slot',
        '2026-08-18T07:32:00Z', '2026-08-18T07:32:00Z', 'uptime_only', 'low', true);

DO $$
BEGIN
    INSERT INTO punch_event (org_id, device_id, device_seq, event_uuid, credential_kind,
                             status, captured_at, effective_at, src_time)
    VALUES ('11111111-1111-1111-1111-111111111111', '55555555-5555-5555-5555-555555555555',
            1003, gen_random_uuid(), 'fingerprint', 'resolved',
            now(), now(), 'rtc_synced');
    RAISE EXCEPTION 'TEST 4 FAILED: resolved event without person was accepted';
EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'TEST 4 unresolved retained / resolved requires person: PASS';
END $$;

-- TEST 5 -------------------------------------------------------------
-- punch_event is append-only at the database level.
DO $$
BEGIN
    UPDATE punch_event SET direction = 'out' WHERE device_seq = 1001;
    RAISE EXCEPTION 'TEST 5 FAILED: UPDATE on punch_event succeeded';
EXCEPTION WHEN raise_exception THEN
    IF SQLERRM LIKE 'TEST 5 FAILED%' THEN RAISE; END IF;
    RAISE NOTICE 'TEST 5a UPDATE blocked: PASS (%)', SQLERRM;
END $$;

DO $$
BEGIN
    DELETE FROM punch_event WHERE device_seq = 1001;
    RAISE EXCEPTION 'TEST 5 FAILED: DELETE on punch_event succeeded';
EXCEPTION WHEN raise_exception THEN
    IF SQLERRM LIKE 'TEST 5 FAILED%' THEN RAISE; END IF;
    RAISE NOTICE 'TEST 5b DELETE blocked: PASS (%)', SQLERRM;
END $$;

-- Corrections go in as amendments instead.
INSERT INTO punch_amendment (punch_event_id, new_direction, reason)
SELECT id, 'out', 'gate guard confirmed exit' FROM punch_event WHERE device_seq = 1001;

-- TEST 6 -------------------------------------------------------------
-- Guardian notification dedupe: one arrival SMS per child per day.
INSERT INTO guardian (id, org_id, full_name, msisdn) VALUES
    ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa', '11111111-1111-1111-1111-111111111111', 'Parent A', '+254700000001');

INSERT INTO notification (org_id, guardian_id, channel, destination, body, dedupe_key)
VALUES ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
        'sms', '+254700000001', 'Your child arrived at 07:31.',
        'arrival:44444444-4444-4444-4444-444444444444:2026-08-18');

DO $$
BEGIN
    INSERT INTO notification (org_id, guardian_id, channel, destination, body, dedupe_key)
    VALUES ('11111111-1111-1111-1111-111111111111', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
            'sms', '+254700000001', 'Your child arrived at 07:31.',
            'arrival:44444444-4444-4444-4444-444444444444:2026-08-18');
    RAISE EXCEPTION 'TEST 6 FAILED: duplicate arrival SMS was queued';
EXCEPTION WHEN unique_violation THEN
    RAISE NOTICE 'TEST 6 notification dedupe: PASS';
END $$;

-- TEST 7 -------------------------------------------------------------
-- Derived span duration is computed, and a bad E.164 number is refused.
INSERT INTO attendance_span (org_id, person_id, business_date, started_at, ended_at)
VALUES ('11111111-1111-1111-1111-111111111111', '44444444-4444-4444-4444-444444444444',
        '2026-08-18', '2026-08-18T07:31:04Z', '2026-08-18T16:02:04Z');

DO $$
DECLARE d integer;
BEGIN
    SELECT duration_s INTO d FROM attendance_span WHERE business_date = '2026-08-18';
    ASSERT d = 30660, format('TEST 7 FAILED: duration_s was %s', d);
    RAISE NOTICE 'TEST 7a generated duration column: PASS (% s)', d;
END $$;

DO $$
BEGIN
    INSERT INTO guardian (org_id, full_name, msisdn)
    VALUES ('11111111-1111-1111-1111-111111111111', 'Parent B', '0700000002');
    RAISE EXCEPTION 'TEST 7 FAILED: non-E.164 msisdn accepted';
EXCEPTION WHEN check_violation THEN
    RAISE NOTICE 'TEST 7b E.164 validation: PASS';
END $$;

ROLLBACK;
