# Presence Platform — Data Model & Device Protocol (v1)

Companion files: [`001_schema.sql`](../db/001_schema.sql) · [`openapi.yaml`](openapi.yaml) · [`002_smoke_test.sql`](../db/002_smoke_test.sql)

Transport for v1 is **HTTPS only** — device-initiated, poll-based. MQTT migration path is at the end.

---

## 1. The five invariants

Everything else is a consequence of these. If you change one, re-read the whole spec.

| # | Invariant | Why |
|---|---|---|
| 1 | **Credentials are polymorphic.** Nothing downstream branches on "fingerprint". | Optical sensors fail on wet, sanitised, worn, and small fingers. Hospitals and schools *will* need cards. Retrofitting this later means rewriting the event pipeline. |
| 2 | **`punch_event` is append-only.** Attendance is derived and recomputable. | Attendance rules change (grace periods, overnight ward shifts, split shifts). If you compute at ingest, a rule change silently rewrites history. Enforced by trigger, not convention. |
| 3 | **Rejected ≠ discarded.** Every event the device sends is stored, resolvable or not. | "Unknown slot" usually means a roster race, not a bad actor. Dropping it loses evidence and — critically — lets a poison event wedge the device buffer forever. |
| 4 | **Slot → person bindings are time-bounded.** | Fingerprint modules address templates by a small integer (1..N). Slots get reused when staff leave. Without validity ranges, last year's punches silently re-attribute to whoever holds slot 42 today. |
| 5 | **Time is three separate facts**, never one column: what the device believed, when the server received it, what the platform will report on. | Devices lose power, RTCs drift, batteries die. Collapsing these makes bad timestamps indistinguishable from good ones. |

---

## 2. Data model

### Core shape

```
organization ─┬─ site ──── device ──── device_slot ──┐
              │                                       │
              ├─ person ─┬─ credential ───────────────┘
              │          ├─ guardian_person ── guardian
              │          └─ person_schedule ── schedule
              │
              └─ punch_event  (append-only, immutable)
                      │
                      ├─ punch_amendment   (corrections, additive)
                      ├─ attendance_span   (derived, droppable)
                      │      └─ attendance_day (derived rollup)
                      └─ notification      (outbox)
```

### The tables that carry the weight

**`credential`** — "a thing that identifies a person at a reader." Fingerprint is one variant alongside `rfid_card`, `nfc_tag`, `pin`, `qr`. Card UIDs and PINs are stored as keyed hashes, so a database leak doesn't hand out working credentials. Biometric templates are stored as AES-256-GCM ciphertext with a `template_key_id` for rotation. Raw fingerprint *images* are never stored, never transmitted, never leave the sensor.

Note `template_vendor`. Templates are proprietary byte formats — a Grow R307 template is meaningless to a Suprema reader. **Choosing your sensor family is a lock-in decision.** Record the vendor now so that when you migrate, you know exactly which credentials need re-enrolling rather than discovering it at cutover.

**`device_slot`** — the join between physical hardware and identity, with `valid_from`/`valid_to`. A partial unique index enforces one live occupant per physical slot; the historical index lets you resolve any past event correctly. This table is what makes attendance history stable across staff turnover.

**`punch_event`** — the source of truth. Note `person_id` is *snapshotted at ingest*, not joined at read time, so a later slot reassignment cannot rewrite the past. `status` distinguishes `resolved` / `unresolved` / `quarantined`. `src_time` + `time_conf` carry how much you should trust the timestamp:

| `src_time` | Meaning | `time_conf` |
|---|---|---|
| `rtc_synced` | RTC set from server within 24h | high |
| `rtc_unsynced` | RTC running but drift unknown | medium |
| `uptime_only` | RTC dead/never set; reconstruct from `received_at − (now_uptime − captured_uptime)` | low |
| `server_assigned` | No usable device time at all | low |

Anything `low` lands in an admin review queue rather than quietly polluting payroll.

**`punch_amendment`** — because events are immutable, a correction ("guard confirmed she left at 4pm") is an additive row, not an UPDATE. Your derivation layer applies amendments on top of raw events. Full audit trail for free, which matters when attendance data becomes a payroll dispute.

**`attendance_span` / `attendance_day`** — derived. You should be able to `TRUNCATE` both and rebuild from `punch_event` at any time. Treat that as a test you actually run.

**`schedule.day_boundary`** — defaults to `04:00`, not midnight. A nurse clocking out at 02:00 belongs to the previous business day. Getting this wrong is the single most common attendance-system bug.

**`notification.dedupe_key`** — `arrival:<person_id>:<date>`, unique-indexed. A child scanning twice at the gate must not send a parent two SMS. Parents notice; it's the fastest way to lose a school.

### Direction is computed server-side

The device sends `direction_hint` (from mounting position or a button). The server computes canonical `direction` from the person's prior state. Devices are wrong constantly — someone re-taps at the exit reader on the way in, a bidirectional device can't know. Store both, trust the server's.

---

## 3. Device → server protocol

Full definition in `openapi.yaml`. The design decisions worth arguing about:

### Authentication: HMAC, not mTLS

Each device holds a 32-byte secret issued once at provisioning. Every request carries:

```
X-Device-Id, X-Key-Version, X-Timestamp, X-Nonce, X-Signature, X-Request-Id
```

Signature is HMAC-SHA256 over the newline-joined canonical string:

```
v1
{METHOD}
{PATH}
{X-Timestamp}
{X-Nonce}
{sha256_hex(body)}
```

mTLS is stronger, but client-cert provisioning and rotation on ESP32 is a genuine time sink for a solo dev. HMAC gets you device identity, replay protection, and rotation with far less machinery. Move to mTLS when you have an ops person.

**Rotation** — `device.key_version` plus `prev_secret_enc` means the server accepts vN and vN+1 simultaneously until the device successfully uses the new key. No downtime, no bricked terminal in a school 200km away.

**Secrets are encrypted, not hashed.** Verifying an HMAC requires the server to hold the raw key, so hashing it would make it unverifiable — a mistake worth naming, because "hash all secrets" is the correct reflex almost everywhere else. Device secrets are sealed with AES-256-GCM under a KEK held outside the database, with the device id as additional authenticated data so a row cannot be lifted from one device and pasted into another. Bearer values the client presents verbatim — the one-time provisioning token — *are* hashed.

**The clock chicken-and-egg** — signing needs a roughly-correct clock, but the device's clock is exactly what might be broken. Resolution: `GET /v1/device/time` is unauthenticated and rate-limited. If a signed request arrives outside the ±300s window, the server returns `401 clock_skew` *with `server_time_ms` in the body*, and the device corrects and retries once. `(device_id, nonce)` is cached for the skew window to block replays.

### Four calls, in order of frequency

**`POST /heartbeat`** — every 60s. Sends telemetry, returns *version counters* (`config_version`, `roster_version`, `commands_pending`, `ack_through`), not data. The device only fetches deltas when a counter moves. One small request answers "do I need to do anything?"

It also returns optional `backoff_s`. When a school's power comes back and forty terminals reconnect simultaneously, you want to shed that herd rather than fall over.

**`POST /events`** — batched, at-least-once from the device, deduplicated server-side on `(device_id, seq)`. `seq` is a strictly monotonic counter persisted in NVS, incremented and committed *before* use, never reused across reboots.

Response returns `ack_through`: the highest seq **in that batch** such that every batch seq at or below it was durably stored. The device truncates its buffer only up to that point.

> Two subtleties, both of which will bite:
>
> **Rejected events still advance `ack_through`**, because they're still stored. Otherwise one unresolvable event sits at the head of the buffer forever, blocking every event behind it. This is the bug that kills DIY attendance systems in month three.
>
> **Contiguity is batch-relative, not history-relative.** The device commits its sequence counter to NVS *before* using it, so a power cut between commit and use burns a number and leaves a permanent gap. If the server demanded contiguity against its own history, that device's buffer would stall forever. Because the device always sends from its buffer head in ascending order, batch-relative contiguity is both sufficient and gap-tolerant.

**`GET /commands`** + **`POST /commands/{id}/result`** — server→device work: enroll, delete slot, reboot, firmware update, config change, remote wipe. Pull-based, so no inbound firewall rules at customer sites.

**`GET /roster?since=`** — slot → display-name deltas so the terminal can greet people offline. Carries `display_name` and `slot_no` only — never payroll numbers, admission numbers, or national IDs. **A lost or stolen terminal should be an inconvenience, not a data breach.**

### OTA is a security boundary

`GET /firmware` returns a manifest with `sha256` **and an Ed25519 signature** verified on-device against a public key compiled into the firmware. An unsigned OTA channel is a remote code execution channel into every hospital and school you've deployed to. Build the signing into your release script from day one; retrofitting it means physically touching every device.

---

## 4. Failure scenarios, walked

| Scenario | Behaviour |
|---|---|
| **Wi-Fi down at punch time** | Event written to flash ring buffer with RTC timestamp, `is_backfilled=true` on upload. Scanning never blocks on the network. |
| **Upload succeeded, ack lost** | Device retries the same batch. Server dedupes on `(device_id, seq)`, returns them as `duplicates`, advances `ack_through`. Effectively-once. |
| **RTC battery dead** | `src_time=uptime_only`. Server reconstructs wall time from `received_at − (current_uptime − captured_uptime)`, sets `time_conf=low`, flags for review. The punch is not lost. |
| **Poison event server can't resolve** | Stored as `unresolved` with a reason, counted in `ack_through`, surfaced in the triage queue. Buffer keeps draining. |
| **Slot reused after staff exit** | `device_slot.valid_to` closes the old binding. March punches on slot 42 resolve to the old holder, August punches to the new one. *(Verified: smoke test 1.)* |
| **Device secret stolen** | Queue `revoke`; set `device.state='suspended'`. Server rejects that `key_version`. Rotation via `prev_secret_enc` needs no site visit. |
| **Finger left on the sensor** | Firmware suppresses repeat reads of the *same slot* within `debounce_ms` (5s) — that's sensor bounce, not a second punch. Anything outside the window is recorded raw and deduped in the derived layer. |
| **Roster stale, unknown finger** | `allow_offline_unknown=true`: record the punch with the raw slot, let the person through, reconcile server-side. Refusing a nurse entry because your roster lagged is how you lose the account. |
| **Power cut mid-flash-write** | Fixed-size 64-byte buffer records with CRC32; corrupt records skipped on read. Head/tail pointers in NVS. |
| **Whole site reconnects at once** | Server returns `backoff_s`; device applies exponential backoff with jitter, 5s → 300s cap. |
| **Attendance rules change retroactively** | Truncate `attendance_span` + `attendance_day`, recompute from `punch_event` + `punch_amendment`. Raw data untouched. |

---

## 5. Firmware state machine (ESP32)

Two FreeRTOS tasks. **The scan loop never blocks on the network** — this is the whole design.

```
                  ┌──────────────────────────────────────┐
   BOOT ──► SELFTEST ──► [secret in NVS?] ──no──► PROVISION ──┐
                  │            │yes                            │
                  │            ▼                               │
                  │        TIME_SYNC ◄─────────────────────────┘
                  │            │
                  │            ▼
                  └──────►   READY  ◄──────────────┐
                            │  ▲                    │
                 finger/card│  │                    │
                            ▼  │                    │
                         CAPTURE                    │
                            │                       │
                            ▼                       │
                       LOCAL_MATCH                  │
                            │                       │
                            ▼                       │
                      BUFFER_WRITE ──fail──► FAULT ─┘
                            │
                            ▼
                        FEEDBACK ────────────────────┘
                     (beep + LED + name)

   Side states, entered from READY on command:
     ENROLL ──► capture ×2 ──► store slot ──► upload template ──► READY
     OTA    ──► download ──► verify sha256 + Ed25519 ──► flash ──► reboot
     FAULT  ──► sensor/flash error; audible alert, retry with backoff
```

**Task 1 — scan loop (core 1, never blocks):**
`READY → CAPTURE → LOCAL_MATCH → BUFFER_WRITE → FEEDBACK → READY`

Matching happens *on the sensor module*, which returns a slot number and score. The ESP32 never handles a fingerprint image.

**Feedback comes after the flash write succeeds, never before.** If you beep green then fail to persist, you've told a nurse she clocked in when she didn't. Order matters.

**Task 2 — network (core 0):**
`heartbeat (60s) → compare version counters → flush events (30s or on threshold) → pull commands → apply → sleep`

Never touches the scan loop's state directly; they communicate through the flash ring buffer and a FreeRTOS queue.

**Buffer:** fixed-size 64-byte records in a LittleFS ring file, CRC32 per record, head/tail in NVS. Fixed-size records give O(1) append and no fragmentation. At 4MB flash you can hold tens of thousands of events — days of offline operation.

**Sequence counter:** in NVS, `commit → then use`. If power drops between commit and use you burn a number, which is harmless. The reverse order would reuse one, which silently destroys idempotency.

---

## 6. Build order

1. **Schema + ingest endpoint.** Curl fake events. No hardware.
2. **ESP32 happy path** — enroll, scan, POST, feedback.
3. **Buffer + resync.** Unplug the router mid-day; verify no loss, no duplicates. This is the milestone that decides whether the product works.
4. **Command queue + remote enroll.** Removes the laptop from installations.
5. **OTA with signature verification.** Before device #3 leaves your desk.
6. **Derived attendance + admin UI.** Django admin covers a surprising amount.
7. **Notifications.** Africa's Talking SMS, dedupe key from day one.
8. **HR / portal integrations.** Last, because it's the part customers describe differently every time.

Ship steps 1–6 to one real office before writing any school-specific code.

## 7. MQTT migration (later)

The payload contract above is transport-agnostic on purpose. When device count or command latency justifies it:

- `dev/{device_id}/events` (QoS 1, device→server) — same batch envelope, same `ack_through` semantics via `dev/{device_id}/ack`
- `dev/{device_id}/cmd` (QoS 1, server→device) — replaces command polling, gives instant enroll
- `dev/{device_id}/state` — retained, replaces heartbeat telemetry
- LWT on `dev/{device_id}/state` gives you real offline detection instead of heartbeat-timeout guessing

Keep HTTPS for provisioning, firmware download, and template upload regardless — they're request/response by nature.

---

## Appendix: verification performed

`db/001_schema.sql` applies cleanly to PostgreSQL 16. `db/002_smoke_test.sql` asserts the invariants above and passes:

```
TEST 1 slot history resolution: PASS
TEST 2 one live occupant per slot: PASS
TEST 3 replay idempotency: PASS
TEST 4 unresolved retained / resolved requires person: PASS
TEST 5a UPDATE blocked: PASS
TEST 5b DELETE blocked: PASS
TEST 6 notification dedupe: PASS
TEST 7a generated duration column: PASS (30660 s)
TEST 7b E.164 validation: PASS
```

`openapi.yaml` validates against the OpenAPI 3.1 specification.

**Not covered here, and you need it before production:** retention and erasure policy for biometric templates (ODPC guidance expects a defined retention period and a working deletion path), the consent capture flow, and a DPIA. `audit_log` is scaffolded for the access-logging obligation — biometric *reads* need logging, not just writes.
