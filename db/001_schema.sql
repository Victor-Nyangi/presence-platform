-- =====================================================================
-- Presence / Attendance Platform — Postgres schema (v1)
--
-- Design rules this schema enforces:
--   1. Credentials are polymorphic. Nothing assumes "fingerprint".
--   2. punch_event is IMMUTABLE and APPEND-ONLY. All attendance is derived.
--   3. Every raw event is retained, including ones the server could not
--      resolve to a person. Rejected != discarded.
--   4. Device slot -> person mapping is time-bounded, so historical events
--      resolve to the person who held the slot AT THE TIME.
--   5. Biometric templates are stored as ciphertext only.
--
-- Target: PostgreSQL 14+
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- ---------------------------------------------------------------------
-- Enums
-- ---------------------------------------------------------------------

CREATE TYPE org_kind          AS ENUM ('office', 'hospital', 'school', 'other');
CREATE TYPE person_kind       AS ENUM ('staff', 'student', 'contractor', 'visitor');
CREATE TYPE credential_kind   AS ENUM ('fingerprint', 'rfid_card', 'nfc_tag', 'pin', 'qr');
CREATE TYPE punch_direction   AS ENUM ('in', 'out', 'unknown');
CREATE TYPE time_source       AS ENUM ('rtc_synced', 'rtc_unsynced', 'uptime_only', 'server_assigned');
CREATE TYPE time_confidence   AS ENUM ('high', 'medium', 'low');
CREATE TYPE event_status      AS ENUM ('resolved', 'unresolved', 'quarantined');
CREATE TYPE device_mode       AS ENUM ('entry', 'exit', 'bidirectional');
CREATE TYPE device_state      AS ENUM ('provisioning', 'active', 'suspended', 'retired');
CREATE TYPE command_kind      AS ENUM (
    'enroll_credential', 'delete_slot', 'sync_roster', 'reboot',
    'firmware_update', 'set_config', 'wipe_templates', 'revoke'
);
CREATE TYPE command_status    AS ENUM ('queued', 'delivered', 'succeeded', 'failed', 'expired');
CREATE TYPE notify_channel    AS ENUM ('sms', 'whatsapp', 'email', 'push');
CREATE TYPE notify_status     AS ENUM ('pending', 'sent', 'delivered', 'failed', 'suppressed');

-- ---------------------------------------------------------------------
-- Tenancy
-- ---------------------------------------------------------------------

CREATE TABLE organization (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name            text NOT NULL,
    kind            org_kind NOT NULL,
    timezone        text NOT NULL DEFAULT 'Africa/Nairobi',
    -- Data-protection posture is per-tenant: who the controller is, what
    -- lawful basis was recorded, when the DPIA was last reviewed.
    dpa_controller  text,
    dpa_reviewed_at date,
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT organization_name_not_blank CHECK (length(btrim(name)) > 0)
);

CREATE TABLE site (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name            text NOT NULL,
    timezone        text,          -- NULL = inherit from organization
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, name)
);

-- ---------------------------------------------------------------------
-- People
-- ---------------------------------------------------------------------

CREATE TABLE person (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    kind            person_kind NOT NULL,
    -- external_ref is the join key into the customer's HR system / school
    -- portal (payroll number, admission number). Keep it opaque.
    external_ref    text,
    full_name       text NOT NULL,
    default_site_id uuid REFERENCES site(id) ON DELETE SET NULL,
    active_from     date NOT NULL DEFAULT CURRENT_DATE,
    active_to       date,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, external_ref),
    CONSTRAINT person_active_range CHECK (active_to IS NULL OR active_to >= active_from)
);

CREATE INDEX person_org_kind_idx ON person (org_id, kind) WHERE active_to IS NULL;

CREATE TABLE guardian (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    full_name       text NOT NULL,
    msisdn          text,           -- E.164
    email           citext,
    locale          text NOT NULL DEFAULT 'en',
    created_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT guardian_has_a_channel CHECK (msisdn IS NOT NULL OR email IS NOT NULL),
    CONSTRAINT guardian_msisdn_e164 CHECK (msisdn IS NULL OR msisdn ~ '^\+[1-9][0-9]{7,14}$')
);

CREATE TABLE guardian_person (
    guardian_id     uuid NOT NULL REFERENCES guardian(id) ON DELETE CASCADE,
    person_id       uuid NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    relationship    text,
    -- Per-link notification preferences; a parent may want arrival only.
    notify_on_in    boolean NOT NULL DEFAULT true,
    notify_on_out   boolean NOT NULL DEFAULT true,
    channel         notify_channel NOT NULL DEFAULT 'sms',
    quiet_from      time,
    quiet_to        time,
    PRIMARY KEY (guardian_id, person_id)
);

CREATE INDEX guardian_person_person_idx ON guardian_person (person_id);

-- ---------------------------------------------------------------------
-- Devices
-- ---------------------------------------------------------------------

CREATE TABLE device (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    site_id             uuid NOT NULL REFERENCES site(id) ON DELETE RESTRICT,
    label               text NOT NULL,
    serial              text NOT NULL,
    mode                device_mode NOT NULL DEFAULT 'bidirectional',
    state               device_state NOT NULL DEFAULT 'provisioning',

    -- HMAC shared secret, AES-256-GCM ciphertext.
    --
    -- NOT a hash. Verifying an HMAC requires the server to hold the raw key,
    -- so this must be reversible. It is encrypted under a KEK held outside
    -- the database (env or KMS), so a dump of Postgres alone does not yield
    -- forgeable device credentials.
    --
    -- Two independent version counters, do not conflate them:
    --   key_version    - the DEVICE secret generation (rotated per device)
    --   secret_key_id  - the KEK generation (rotated platform-wide)
    -- Keeping prev_* lets the server accept vN and vN+1 simultaneously, so a
    -- terminal 200km away is never bricked by a roll it has not picked up.
    secret_enc          bytea,
    secret_nonce        bytea,
    secret_key_id       text,
    key_version         integer NOT NULL DEFAULT 1,
    prev_secret_enc     bytea,
    prev_secret_nonce   bytea,
    prev_secret_key_id  text,
    prev_key_version    integer,
    secret_rotated_at   timestamptz,

    -- One-time provisioning token (hashed), consumed on first contact.
    provision_token_hash bytea,
    provisioned_at      timestamptz,

    firmware_version    text,
    config_version      integer NOT NULL DEFAULT 1,
    roster_version      bigint  NOT NULL DEFAULT 0,
    slot_capacity       integer NOT NULL DEFAULT 1000,

    -- Last-seen telemetry, overwritten each heartbeat.
    last_seen_at        timestamptz,
    last_ack_seq        bigint NOT NULL DEFAULT 0,
    last_buffer_depth   integer,
    last_rssi           integer,
    last_clock_skew_ms  bigint,

    created_at          timestamptz NOT NULL DEFAULT now(),
    UNIQUE (org_id, serial),
    CONSTRAINT device_slot_capacity_positive CHECK (slot_capacity > 0)
);

CREATE INDEX device_org_state_idx ON device (org_id, state);

-- ---------------------------------------------------------------------
-- Credentials
--
-- A credential is "a thing that identifies a person at a reader". The
-- fingerprint case is just one variant. Nothing downstream branches on it.
-- ---------------------------------------------------------------------

CREATE TABLE credential (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id              uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    person_id           uuid NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    kind                credential_kind NOT NULL,
    label               text,             -- 'right index', 'blue card'

    -- Card/tag/PIN/QR: store a keyed hash, never the raw value, so a DB
    -- leak does not hand out working credentials.
    secret_hash         bytea,

    -- Biometric: proprietary template blob, AES-256-GCM ciphertext.
    -- The plaintext template never lands in Postgres and never leaves
    -- the device unencrypted. Raw images are never stored at all.
    template_ciphertext bytea,
    template_nonce      bytea,
    template_key_id     text,
    template_vendor     text,             -- 'grow_r307' — templates are NOT portable
    template_quality    smallint,

    enrolled_at         timestamptz NOT NULL DEFAULT now(),
    enrolled_by         uuid REFERENCES person(id) ON DELETE SET NULL,
    revoked_at          timestamptz,
    revoke_reason       text,

    CONSTRAINT credential_payload_present CHECK (
        (kind = 'fingerprint' AND template_ciphertext IS NOT NULL)
        OR (kind <> 'fingerprint' AND secret_hash IS NOT NULL)
    ),
    CONSTRAINT credential_template_needs_nonce CHECK (
        template_ciphertext IS NULL OR (template_nonce IS NOT NULL AND template_key_id IS NOT NULL)
    ),
    CONSTRAINT credential_quality_range CHECK (
        template_quality IS NULL OR template_quality BETWEEN 0 AND 255
    )
);

CREATE INDEX credential_person_idx ON credential (person_id) WHERE revoked_at IS NULL;
CREATE UNIQUE INDEX credential_secret_unique
    ON credential (org_id, kind, secret_hash)
    WHERE secret_hash IS NOT NULL AND revoked_at IS NULL;

-- ---------------------------------------------------------------------
-- Device slot bindings
--
-- Fingerprint modules address templates by a small integer slot (1..N)
-- in on-module flash. Slots get reused when staff leave. Without validity
-- ranges, last year's punches would silently re-attribute to whoever
-- holds slot 42 today. This table is what makes history stable.
-- ---------------------------------------------------------------------

CREATE TABLE device_slot (
    id              bigserial PRIMARY KEY,
    device_id       uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    slot_no         integer NOT NULL,
    credential_id   uuid NOT NULL REFERENCES credential(id) ON DELETE RESTRICT,
    person_id       uuid NOT NULL REFERENCES person(id) ON DELETE RESTRICT,
    valid_from      timestamptz NOT NULL DEFAULT now(),
    valid_to        timestamptz,
    CONSTRAINT device_slot_no_positive CHECK (slot_no > 0),
    CONSTRAINT device_slot_range CHECK (valid_to IS NULL OR valid_to > valid_from)
);

-- Only one live occupant per physical slot.
CREATE UNIQUE INDEX device_slot_live_unique
    ON device_slot (device_id, slot_no)
    WHERE valid_to IS NULL;

-- Historical resolution lookup.
CREATE INDEX device_slot_resolve_idx ON device_slot (device_id, slot_no, valid_from DESC);

-- ---------------------------------------------------------------------
-- Raw events — APPEND ONLY. Never UPDATE, never DELETE.
--
-- (device_id, device_seq) is the idempotency key. The device assigns a
-- strictly monotonic sequence per boot-persistent counter; the server
-- upserts with ON CONFLICT DO NOTHING. At-least-once delivery from the
-- device plus this constraint gives effectively-once semantics.
-- ---------------------------------------------------------------------

CREATE TABLE punch_event (
    id                  bigserial PRIMARY KEY,
    org_id              uuid NOT NULL REFERENCES organization(id) ON DELETE RESTRICT,
    device_id           uuid NOT NULL REFERENCES device(id) ON DELETE RESTRICT,
    device_seq          bigint NOT NULL,
    event_uuid          uuid NOT NULL,

    -- What the reader actually saw.
    credential_kind     credential_kind NOT NULL,
    slot_no             integer,
    credential_ref      text,             -- hashed card UID for non-biometric
    match_score         smallint,

    -- Resolution result. person_id is snapshotted at ingest so a later
    -- slot reassignment cannot rewrite history.
    status              event_status NOT NULL DEFAULT 'unresolved',
    person_id           uuid REFERENCES person(id) ON DELETE RESTRICT,
    credential_id       uuid REFERENCES credential(id) ON DELETE RESTRICT,
    unresolved_reason   text,

    -- Time. Three separate facts, never collapsed into one column:
    --   captured_at  - what the device's RTC believed
    --   received_at  - when the server got it
    --   effective_at - what the platform will actually bill/report on
    captured_at         timestamptz NOT NULL,
    captured_uptime_ms  bigint,
    received_at         timestamptz NOT NULL DEFAULT now(),
    effective_at        timestamptz NOT NULL,
    src_time            time_source NOT NULL,
    time_conf           time_confidence NOT NULL DEFAULT 'high',
    clock_skew_ms       bigint,
    is_backfilled       boolean NOT NULL DEFAULT false,

    -- Direction. The device only ever offers a hint (from its mounting
    -- position or a button). The canonical value is computed server-side
    -- from the person's prior state, because devices are wrong a lot.
    direction_hint      punch_direction NOT NULL DEFAULT 'unknown',
    direction           punch_direction NOT NULL DEFAULT 'unknown',

    raw                 jsonb NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT punch_event_seq_positive CHECK (device_seq > 0),
    CONSTRAINT punch_event_resolved_has_person CHECK (
        status <> 'resolved' OR person_id IS NOT NULL
    )
);

CREATE UNIQUE INDEX punch_event_idem_idx ON punch_event (device_id, device_seq);
CREATE UNIQUE INDEX punch_event_uuid_idx ON punch_event (event_uuid);
CREATE INDEX punch_event_person_time_idx ON punch_event (person_id, effective_at DESC);
CREATE INDEX punch_event_org_time_idx ON punch_event (org_id, effective_at DESC);
CREATE INDEX punch_event_triage_idx ON punch_event (org_id, received_at DESC)
    WHERE status <> 'resolved';

-- Enforce append-only at the database, not just in application code.
CREATE OR REPLACE FUNCTION punch_event_is_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- NEW is unassigned on DELETE, so branch rather than COALESCE.
    RAISE EXCEPTION 'punch_event is append-only (attempted % on id %)',
        TG_OP, OLD.id;
END;
$$;

CREATE TRIGGER punch_event_no_mutation
    BEFORE UPDATE OR DELETE ON punch_event
    FOR EACH ROW EXECUTE FUNCTION punch_event_is_immutable();

-- Late corrections are additive: an amendment row points at the original.
CREATE TABLE punch_amendment (
    id              bigserial PRIMARY KEY,
    punch_event_id  bigint NOT NULL REFERENCES punch_event(id) ON DELETE RESTRICT,
    new_direction   punch_direction,
    new_effective_at timestamptz,
    new_person_id   uuid REFERENCES person(id) ON DELETE RESTRICT,
    voided          boolean NOT NULL DEFAULT false,
    reason          text NOT NULL,
    created_by      uuid REFERENCES person(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX punch_amendment_event_idx ON punch_amendment (punch_event_id);

-- ---------------------------------------------------------------------
-- Derived attendance — safe to DROP and recompute from punch_event.
-- Treat everything below this line as a materialization, not a source.
-- ---------------------------------------------------------------------

CREATE TABLE attendance_span (
    id              bigserial PRIMARY KEY,
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    person_id       uuid NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    site_id         uuid REFERENCES site(id) ON DELETE SET NULL,
    business_date   date NOT NULL,
    in_event_id     bigint REFERENCES punch_event(id) ON DELETE RESTRICT,
    out_event_id    bigint REFERENCES punch_event(id) ON DELETE RESTRICT,
    started_at      timestamptz NOT NULL,
    ended_at        timestamptz,
    duration_s      integer GENERATED ALWAYS AS (
        CASE WHEN ended_at IS NULL THEN NULL
             ELSE EXTRACT(EPOCH FROM (ended_at - started_at))::integer END
    ) STORED,
    -- 'missing_out', 'overnight', 'duplicate_suppressed', 'low_time_conf'
    anomalies       text[] NOT NULL DEFAULT '{}',
    computed_at     timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT attendance_span_order CHECK (ended_at IS NULL OR ended_at >= started_at)
);

CREATE INDEX attendance_span_person_date_idx ON attendance_span (person_id, business_date DESC);
CREATE UNIQUE INDEX attendance_span_in_event_idx ON attendance_span (in_event_id)
    WHERE in_event_id IS NOT NULL;

CREATE TABLE attendance_day (
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    person_id       uuid NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    business_date   date NOT NULL,
    first_in_at     timestamptz,
    last_out_at     timestamptz,
    total_s         integer NOT NULL DEFAULT 0,
    span_count      integer NOT NULL DEFAULT 0,
    is_present      boolean NOT NULL DEFAULT false,
    is_late         boolean NOT NULL DEFAULT false,
    needs_review    boolean NOT NULL DEFAULT false,
    computed_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (person_id, business_date)
);

CREATE INDEX attendance_day_org_date_idx ON attendance_day (org_id, business_date DESC);
CREATE INDEX attendance_day_review_idx ON attendance_day (org_id, business_date)
    WHERE needs_review;

CREATE TABLE schedule (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    name            text NOT NULL,
    -- ISO weekday numbers 1..7 that this schedule applies to.
    weekdays        smallint[] NOT NULL DEFAULT '{1,2,3,4,5}',
    expected_in     time NOT NULL,
    expected_out    time NOT NULL,
    grace_minutes   integer NOT NULL DEFAULT 10,
    -- Where the business day is cut for overnight shifts (hospital wards).
    day_boundary    time NOT NULL DEFAULT '04:00',
    UNIQUE (org_id, name),
    CONSTRAINT schedule_grace_nonneg CHECK (grace_minutes >= 0)
);

CREATE TABLE person_schedule (
    person_id       uuid NOT NULL REFERENCES person(id) ON DELETE CASCADE,
    schedule_id     uuid NOT NULL REFERENCES schedule(id) ON DELETE CASCADE,
    effective_from  date NOT NULL DEFAULT CURRENT_DATE,
    effective_to    date,
    PRIMARY KEY (person_id, schedule_id, effective_from)
);

-- ---------------------------------------------------------------------
-- Device command queue (server -> device, pulled on poll)
-- ---------------------------------------------------------------------

CREATE TABLE device_command (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    device_id       uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    kind            command_kind NOT NULL,
    payload         jsonb NOT NULL DEFAULT '{}'::jsonb,
    status          command_status NOT NULL DEFAULT 'queued',
    attempts        integer NOT NULL DEFAULT 0,
    result          jsonb,
    error           text,
    expires_at      timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
    created_at      timestamptz NOT NULL DEFAULT now(),
    delivered_at    timestamptz,
    completed_at    timestamptz
);

CREATE INDEX device_command_pending_idx ON device_command (device_id, created_at)
    WHERE status IN ('queued', 'delivered');

-- ---------------------------------------------------------------------
-- Notification outbox (guardians, HR webhooks)
-- ---------------------------------------------------------------------

CREATE TABLE notification (
    id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id          uuid NOT NULL REFERENCES organization(id) ON DELETE CASCADE,
    punch_event_id  bigint REFERENCES punch_event(id) ON DELETE SET NULL,
    guardian_id     uuid REFERENCES guardian(id) ON DELETE SET NULL,
    channel         notify_channel NOT NULL,
    destination     text NOT NULL,
    body            text NOT NULL,
    status          notify_status NOT NULL DEFAULT 'pending',
    provider        text,
    provider_ref    text,
    attempts        integer NOT NULL DEFAULT 0,
    error           text,
    -- Dedupe key, e.g. 'arrival:<person_id>:<business_date>' so a double
    -- scan at the gate does not send a parent two SMS.
    dedupe_key      text,
    scheduled_for   timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now(),
    sent_at         timestamptz
);

CREATE UNIQUE INDEX notification_dedupe_idx ON notification (org_id, dedupe_key)
    WHERE dedupe_key IS NOT NULL;
CREATE INDEX notification_due_idx ON notification (scheduled_for)
    WHERE status = 'pending';

-- ---------------------------------------------------------------------
-- Sync + audit
-- ---------------------------------------------------------------------

CREATE TABLE sync_batch (
    id              bigserial PRIMARY KEY,
    device_id       uuid NOT NULL REFERENCES device(id) ON DELETE CASCADE,
    seq_start       bigint NOT NULL,
    seq_end         bigint NOT NULL,
    accepted        integer NOT NULL DEFAULT 0,
    duplicates      integer NOT NULL DEFAULT 0,
    rejected        integer NOT NULL DEFAULT 0,
    request_id      uuid,
    received_at     timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX sync_batch_device_idx ON sync_batch (device_id, received_at DESC);

-- Biometric access is auditable by law in most jurisdictions. Log reads
-- of credential material, not just writes.
CREATE TABLE audit_log (
    id              bigserial PRIMARY KEY,
    org_id          uuid REFERENCES organization(id) ON DELETE SET NULL,
    actor_kind      text NOT NULL,        -- 'user' | 'device' | 'system'
    actor_id        text,
    action          text NOT NULL,        -- 'credential.export', 'person.delete'
    subject_type    text,
    subject_id      text,
    detail          jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip              inet,
    created_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_org_time_idx ON audit_log (org_id, created_at DESC);
CREATE INDEX audit_log_subject_idx ON audit_log (subject_type, subject_id, created_at DESC);
