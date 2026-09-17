# Outbound Event Contract (v1)

This is the normative reference for the events `cmd/deliver` pushes to a
downstream consumer — the same role `docs/openapi.yaml` plays for the
device-facing API, but for the outbound side. Read `docs/SPEC.md` first if
you haven't; this assumes the schema and vocabulary it establishes
(`punch_event`, `attendance_span`, `attendance_day`, business dates, the
04:00 day boundary).

**This repo emits domain events about people and readers. It has no
knowledge of any consumer.** If you are mapping these into another system's
model (a FHIR facade, a payroll export, anything else), that translation is
entirely your side's responsibility — nothing here names or assumes a
specific consumer, and nothing here should.

---

## 1. Where events come from

`internal/attendance.Engine.Recompute` is both the attendance engine and the
**projector**. In the same transaction that deletes and re-inserts
`attendance_span`/`attendance_day` for the requested window, it:

1. reads the rows that existed for that window *before* the rewrite,
2. computes the new rows (as it already did),
3. diffs old against new, and
4. writes one `outbox_event` row per subject whose state actually changed.

An unchanged re-run — the common case, since `recompute` is typically cron-
driven and re-covers recent days on every run — emits nothing. Only a real
state change (a new punch, an amendment, a schedule change that reattributes
a shift) produces an event. This is what stops a routine cron tick from
re-sending the same attendance event for every span and day in its window
every single time it fires.

Because the outbox write happens in the same Postgres transaction as the
attendance write, an event is never emitted for a recompute that rolls back,
and an attendance change is never committed without its corresponding
outbox row (or vice versa).

## 2. Delivery model

`cmd/deliver` is a separate long-running process (see `cmd/gateway/main.go`'s
own stated separation: "attendance computation, notifications and the admin
UI live in separate services"). It polls `outbox_event` for due rows,
`POST`s each one's payload to **one configured endpoint**
(`PRESENCE_EMITTER_ENDPOINT_URL`), and tracks per-row delivery state:

```
pending → delivering → delivered
                     ↘ pending (retry, backoff applied)
                     ↘ dead (after 12 attempts, ~19 minutes)
```

**At-least-once, not exactly-once.** A delivery can succeed on the
consumer's side and still be recorded as failed here (the connection drops
before the response arrives) — a retry after that is a legitimate duplicate.
This service does not and cannot solve that for you: de-duplication has to
happen where you apply the event, using `X-Presence-Event-Id` (see §4).

**Retry schedule:** 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s, 300s, 300s —
doubling, capped at 5 minutes, 12 attempts total (`gateway/internal/delivery/backoff.go`).
After the 12th failure the event is marked `dead`: kept, with its last error,
not deleted, and not retried automatically. It is **not** replayed when a
later event for the same subject succeeds — see §3 for why that's fine.

**Ordering: best-effort only, once a retry is in flight.** Within one
delivery pass with no failures, events for an organisation are sent in
creation order. The moment any event is retried, a later-created event with
no failures of its own can be delivered before the retried one's next
attempt lands — this service does not hold back newer events to preserve
strict per-subject ordering, because doing so would mean a single stuck
subject blocking delivery for everyone else, and the volume this was built
for doesn't justify that complexity. **Do not rely on delivery order.** Rely
on `emitted_at` instead (§3).

## 3. Payload shape: full snapshot, not a delta

Every payload carries the **complete current state** of its subject, not a
diff from the previous event. Combined with a monotonic `emitted_at`, this
is what makes at-least-once delivery, out-of-order retries, and dead-letter
recovery all safe without any extra machinery on either side:

> **Consumer rule:** for a given subject key, apply an incoming event only
> if its `emitted_at` is newer than the last one you applied for that
> subject. Do this and duplicate delivery, retry reordering, and even a
> permanently dead-lettered event are all harmless — a dead event is simply
> superseded the next time that subject's state changes and a newer event
> arrives.

### `attendance_span.upserted`

```json
{
  "event_id": "f1ddd22c-7121-46e3-91e5-1de0879c6632",
  "event_type": "attendance_span.upserted",
  "org_id": "11111111-1111-1111-1111-111111111111",
  "emitted_at": "2026-09-17T15:12:54.518302026+03:00",
  "subject": {
    "person_id": "33333333-3333-3333-3333-333333333333",
    "in_event_id": 1,
    "out_event_id": 2
  },
  "data": {
    "business_date": "2026-09-17",
    "started_at": "2026-09-17T08:00:00+03:00",
    "ended_at": "2026-09-17T17:00:00+03:00",
    "duration_seconds": 32400,
    "open": false,
    "anomalies": []
  }
}
```

### `attendance_span.removed`

Same `subject`, no `data`. Fires when a previously-emitted span disappears
from the derived tables entirely — e.g. an amendment voided the punch that
anchored it.

### `attendance_day.upserted`

```json
{
  "event_id": "b30d98b2-6579-4bd6-89ba-c8f17831a103",
  "event_type": "attendance_day.upserted",
  "org_id": "11111111-1111-1111-1111-111111111111",
  "emitted_at": "2026-09-17T15:12:54.518302026+03:00",
  "subject": {
    "person_id": "33333333-3333-3333-3333-333333333333",
    "business_date": "2026-09-17"
  },
  "data": {
    "first_in_at": "2026-09-17T08:00:00+03:00",
    "last_out_at": "2026-09-17T17:00:00+03:00",
    "total_seconds": 32400,
    "span_count": 1,
    "is_present": true,
    "is_late": false,
    "needs_review": false
  }
}
```

### `attendance_day.removed`

Same `subject`, no `data`.

### Subject identity: read this before you key anything on it

**A span's identity is `subject.in_event_id` / `subject.out_event_id` — the
`punch_event` row(s) that anchor it — never `attendance_span.id`.**
`attendance_span.id` is a Postgres `bigserial` that `Engine.Recompute`
regenerates on *every* run: the engine unconditionally deletes and
re-inserts the whole recomputed window, so a span with byte-identical
content gets a brand new `id` each time. `punch_event` rows, by contrast,
are append-only and never deleted (invariant #2 in `docs/SPEC.md`) — they
are the only identifiers in this schema that are actually stable over time.

A span anchored by an `in` punch always carries `in_event_id` (the schema's
own `attendance_span_in_event_idx` unique index guarantees at most one span
per `in_event_id`). A `missing_in` marker span — an orphan clock-out with no
matching clock-in — has no `in_event_id` and carries `out_event_id` instead.
A consumer should treat `in_event_id ?? out_event_id` as the span's key, not
assume `in_event_id` is always present.

A day's identity is `(subject.person_id, subject.business_date)` — the same
key `attendance_day` already uses as its own primary key.

## 4. Security

**Every request is HMAC-SHA256 signed:**

```
X-Presence-Signature: t=<unix_ms>,v1=<hex hmac-sha256(secret, "<t>.<body>")>
```

Same shape Stripe and GitHub use for outbound webhooks, and the same shape
this platform's own device protocol uses HMAC for (`docs/SPEC.md` §3) —
chosen here for the identical reason: it lets a consumer verify both
authenticity and freshness without this service needing a nonce-replay
cache of its own. **Checking the timestamp window is the consumer's job**;
this service only supplies `t`.

Also carried on every request:

| Header | Meaning |
|---|---|
| `X-Presence-Event-Id` | `outbox_event.id`. The idempotency key — de-duplicate on this. |
| `X-Presence-Event-Type` | e.g. `attendance_day.upserted`. |
| `Content-Type` | `application/json` |

**Payloads carry data, not just an id to fetch.** Considered and rejected:
id-only payloads (the FHIR-facade-adjacent pattern where a notification
carries only a resource reference and the consumer fetches the full record
over an authenticated API) would require presence-platform to expose a new
authenticated *external* read API — a materially larger surface (a new auth
model, new questions about who may read which records) than a five-hundred-
person, roughly-thousand-events-a-day deployment justifies. These payloads
are already small derived-state snapshots, not raw biometric data, so the
confidentiality cost of carrying them directly is low relative to the
complexity cost of not doing so.

**HTTPS is required outside local development.** These payloads are
attendance records about identified people — personal data crossing a
network. HMAC gives origin and integrity, not confidentiality; without TLS,
anyone who can observe the traffic reads real people's attendance history.
`PRESENCE_EMITTER_ALLOW_INSECURE_HTTP=true` overrides this for local
development only, logs a loud warning at startup when set, and must never
be set in a real deployment.

**The endpoint is operator config, not a request parameter.** There is no
API — device-facing or otherwise — through which any caller can register or
change `PRESENCE_EMITTER_ENDPOINT_URL` at runtime. This is a materially
different threat model from a service that lets callers register arbitrary
webhook URLs (see the SSRF discussion in a sibling project's
`subscriptions.md` if you're integrating one of those): there is no window
between "an untrusted party supplies a URL" and "this service uses it,"
because no untrusted party ever supplies it. What this service still does,
because it costs little and a config mistake deserves to fail loudly at
startup the same way a missing secret does in `internal/config`: reject
non-HTTPS schemes (unless explicitly opted out, above) and reject an
endpoint that resolves to a loopback, link-local, private, or unspecified
address (`PRESENCE_EMITTER_ALLOW_PRIVATE_ENDPOINTS=true` for local
development, same loud-warning treatment). The delivery HTTP client also
never follows redirects — a compromised or misconfigured endpoint answering
with a `3xx` to a disallowed address is treated as an ordinary delivery
failure, not followed.

## 5. Configuration

| Variable | Required | Notes |
|---|---|---|
| `PRESENCE_DATABASE_URL` | yes | same database as the gateway |
| `PRESENCE_EMITTER_ENDPOINT_URL` | yes | must be `https://` unless `_ALLOW_INSECURE_HTTP` is set |
| `PRESENCE_EMITTER_SIGNING_SECRET` | yes | hex, ≥32 bytes — `openssl rand -hex 32` |
| `PRESENCE_EMITTER_KEY_ID` | yes | an identifier for this secret, for your own rotation bookkeeping |
| `PRESENCE_EMITTER_ALLOW_INSECURE_HTTP` | no | `true` to allow plain HTTP. Local development only. |
| `PRESENCE_EMITTER_ALLOW_PRIVATE_ENDPOINTS` | no | `true` to allow a loopback/private/link-local endpoint. Local development only. |
| `PRESENCE_EMITTER_POLL_INTERVAL` | no | default `5s` |
| `PRESENCE_EMITTER_HTTP_TIMEOUT` | no | default `10s` |

No defaults for the required settings, deliberately — same posture as
`internal/config` for the gateway's own secrets. If your deployment has no
downstream consumer yet, simply don't run `cmd/deliver`; `outbox_event` rows
accumulate harmlessly (`pending`) until something drains them, and the
projector's own diffing means there's no backlog cost to that beyond
storage.

## 6. What is deliberately not here

- **Occupancy events.** A `Location`- or room-level "how many people are
  here right now" signal would need a device-to-room/department mapping.
  This schema only maps a device to a `site` — nothing finer — so building
  occupancy events would mean inventing that mapping first. Out of scope
  here; flagged rather than guessed at.
- **Per-subject strict ordering / partitioned delivery.** See §2. Would
  require holding back newer events behind a stuck one per subject; not
  justified at this volume.
- **A second signing secret for rotation-without-downtime.** The device
  protocol supports two live secrets per device (`key_version` /
  `prev_secret_enc`) because there are potentially hundreds of physically
  remote terminals that cannot all be updated atomically. This emitter has
  exactly one configured downstream endpoint under direct operational
  control, so a coordinated secret rotation (update both sides at the same
  time) is a reasonable expectation, and the dual-secret machinery the
  device fleet needs would be unused complexity here.
