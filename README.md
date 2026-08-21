# presence-platform

Credential-agnostic presence and attendance tracking for offices, hospitals and schools. Terminals read a fingerprint (or a card, or a PIN) and record *who was here, when* — reliably, including while the network is down.

> **Status: early.** The gateway and schema are built and tested. The firmware's protocol-critical logic — ring buffer, signing string, batch serialisation, response parsing — is covered by host tests, and the batch payload it produces has been checked against the real gateway. It still will not run on a board: `setup()` never constructs the ring buffer, because the LittleFS-backed `Storage` implementation does not exist yet, and none of the code has been built with the ESP32 toolchain.

## Why this exists

Attendance systems are easy to demo and hard to run. The failure modes that matter are not "can it read a fingerprint" — they are the school's Wi-Fi dropping for six hours, an RTC battery dying, a slot being reassigned when a nurse leaves, and a payroll dispute six months later that needs an audit trail.

This repo is organised around five invariants:

1. **Credentials are polymorphic.** Nothing branches on "fingerprint". Optical sensors fail on wet, sanitised, worn and small fingers — which is to say, on hospitals and on children. Cards are a first-class credential, not a retrofit.
2. **The event log is append-only.** Attendance is derived and recomputable. When a customer changes their grace period, you recompute; you do not discover that ingest-time computation destroyed the history.
3. **Rejected is not discarded.** Every event a device sends is stored, resolvable or not — and rejections still advance the device's acknowledgement, so one unresolvable event cannot wedge the buffer behind it.
4. **Slot bindings are time-bounded.** Fingerprint modules address templates by a small integer, and those get recycled. Without validity ranges, last year's punches silently re-attribute to whoever holds slot 42 today.
5. **Time is three separate facts** — what the device believed, when the server received it, what the platform reports on — never collapsed into one column.

Full reasoning: [`docs/SPEC.md`](docs/SPEC.md).

## Layout

```
docs/       SPEC.md (design + protocol) and openapi.yaml (device API)
db/         Postgres schema and invariant tests
gateway/    Go device-facing ingest service + attendance engine
firmware/   ESP32 / PlatformIO terminal
```

## Quick start

```bash
cd gateway && go mod tidy && cd ..   # generates go.sum (not committed) on first checkout
docker compose up -d postgres        # binds host port 5432; see below if that is taken
make seed             # create the bench fixture, print the device secret
make db-load          # apply schema, run invariant tests
make test             # gateway unit tests + firmware host tests
make test-integration # gateway against real Postgres
make run              # start the gateway on :8080
```

### Getting a device onto the bench

`POST /v1/device/provision` is deliberately a 501 until the installer flow
exists, so a terminal has no way to obtain a secret on its own. `make seed`
fills that gap: it writes the fixture — one school, two people, one active
terminal with both fingerprint slots bound — and prints the device secret
once.

```
DEVICE_SECRET  90fc1acc7e787daf65860a3869f62f7a63aa321f5f1859cb4b6a4486e7a7abca
key_version    1
```

The row stores only ciphertext, sealed under your KEK with the device id as
additional data, so that printout is the only time you see the raw key. Paste
it into the terminal's NVS. `make seed RESET=1` reissues it — that tears down
the fixture, and because `punch_event` is append-only by trigger, the teardown
has to disable that trigger to clear the device's history. It is a bench tool;
do not point it at anything holding real attendance data.

Two things that will waste an afternoon otherwise:

- **Slot bindings are backdated a year on purpose.** Resolution happens as of
  an event's effective time, so a binding starting at "now" rejects every
  punch older than "now" — including anything a device uploads from a buffer
  it filled earlier, and every event whose time was rebuilt from an uptime
  delta. Those all present as `unknown_slot`, which reads like a signing
  fault and is not one.
- **`docker compose up postgres` binds host port 5432**, which collides with a
  system Postgres install. Either stop yours, or run Postgres on another port
  and pass `DB_URL=...` / `-db` to the make targets.

## The gateway

Device-facing HTTPS. Devices poll; nothing needs an inbound firewall rule at a customer site.

| Endpoint | Purpose |
|---|---|
| `GET /v1/device/time` | Unauthenticated clock reference. Signing needs a roughly-correct clock, and a dead RTC is exactly what breaks that — so this one cannot be signed. |
| `POST /v1/device/heartbeat` | Returns version counters, not data. The device fetches deltas only when a counter moves. |
| `POST /v1/device/events` | Batched, idempotent punch upload. |
| `GET /v1/device/commands` | Enroll, reboot, config, firmware, revoke. |
| `GET /v1/device/roster` | Slot → display name, so terminals greet people offline. |

**Auth** is HMAC-SHA256 over a canonical string (see [`docs/openapi.yaml`](docs/openapi.yaml)). mTLS is stronger, but client-cert provisioning and rotation on an ESP32 is a real time sink; HMAC gives device identity, replay protection and rotation with far less machinery. Move to mTLS when you have an ops person.

Two details worth knowing before you touch this code:

- **Clock skew is recoverable, not fatal.** A `401` carries `server_time_ms`, so a terminal with a dead RTC corrects itself and retries instead of being locked out.
- **`ack_through` is batch-relative, not history-relative.** A device that commits a sequence number to NVS and then loses power leaves a permanent gap. History-based contiguity would stall that device forever; batch-relative contiguity is gap-tolerant and still safe, because the device always sends from its buffer head in order.

### Configuration

| Variable | Notes |
|---|---|
| `PRESENCE_DATABASE_URL` | required |
| `PRESENCE_KEKS` | required, `id:hex64[,id:hex64]`. Multiple entries let you rotate without re-encrypting everything at once. |
| `PRESENCE_KEK_ID` | which key encrypts new writes |
| `PRESENCE_TOKEN_PEPPER` | required |

No defaults for secrets, deliberately: a gateway that silently boots with a development key in production is worse than one that refuses to start.

Device HMAC secrets are stored **encrypted, not hashed** — verifying an HMAC requires the raw key, so a hash would be unverifiable. They are sealed with AES-256-GCM under a KEK held outside the database, with the device id as additional authenticated data, so a Postgres dump alone yields nothing forgeable.

## The attendance engine

The gateway stores what happened. This turns it into what it means.

`internal/attendance` is split deliberately: `rules.go` is pure — no database, no clock, no I/O — because the hard parts of attendance are rules, not queries, and rules can only be exercised exhaustively if they don't need Postgres. `engine.go` reads rows, calls into the rules, and writes rows back.

```bash
recompute -org <uuid> -days 7 -review
```

Rebuilding is destructive-and-rebuild, and safe to run as often as you like. `attendance_span` and `attendance_day` contain nothing that cannot be regenerated from `punch_event` plus `punch_amendment` — that is the entire reason the event log is append-only. When a customer changes their grace period six months in, you re-run this.

The rules that matter, and why:

- **The day boundary defaults to 04:00, not midnight.** A nurse clocking out at 02:00 belongs to the shift that began the previous evening. Getting this wrong splits one night shift across two days' totals, and it is the most common attendance bug there is.
- **An ordinary night shift is not an anomaly.** `overnight` means "crossed a *business* day", not "crossed midnight". If 19:00→03:30 were flagged, every night nurse would generate a review item every shift and the queue would be useless inside a week.
- **Hours are never split across days.** A span is attributed wholly to the day it started, so one shift stays one auditable unit. If a payroll integration needs proportional splitting, it should do that at export time from the span's start and end.
- **An open span accrues zero time.** A forgotten clock-out would otherwise quietly bill hundreds of hours. It is flagged `missing_out` and the day goes to review.
- **Two clock-ins never merge into one long shift.** Merging would turn someone's mistake into paid hours.
- **An orphan clock-out is recorded, not discarded** — but it never counts as an arrival, or the person would look wildly late.
- **Anomalies are facts, not errors.** Attendance data that hides its own uncertainty is worse than data that admits it. Anything unusual sets `needs_review`, which is what puts a day in front of a human before it reaches payroll.

Corrections are additive `punch_amendment` rows, never edits — the raw event is immutable. Later amendment wins, per field.

## The firmware

Two FreeRTOS tasks, and one rule: **the scan loop never blocks on the network.** Core 1 scans, buffers and beeps; core 0 drains the buffer whenever it can.

Ordering matters in one specific place: the terminal confirms a punch **after** the flash write succeeds, never before. Beeping green on a write that failed tells someone they clocked in when they did not.

The offline buffer is a fixed-size-record ring in LittleFS with a CRC per record and cursors in NVS. Fixed records give O(1) append and no compaction pass that a power cut could interrupt halfway. A torn record is skipped on read rather than being fatal — the same failure shape as a poison event on the server, handled the same way.

Sequence numbers are committed to NVS **before** use. Losing power between commit and use burns a number, which is harmless because the gateway's ack logic is gap-tolerant. The reverse order would reuse a number after a reboot and silently destroy idempotency.

### Testing without hardware

The protocol-critical parts are deliberately free of Arduino headers so they compile and run on a host:

```bash
make firmware-test
```

This covers the ring buffer (ack semantics, power-cut corruption, overflow, reboot recovery) and the canonical signing string. The signing format is pinned by the **same golden vector** in both `gateway/internal/auth/conformance_test.go` and `firmware/test/host_test.cpp` — if someone changes the format on one side only, CI fails instead of every deployed terminal returning 401 the morning after a release.

### Bill of materials (prototype)

| Part | Note |
|---|---|
| ESP32-WROOM DevKit | Wi-Fi, dual core, 4MB flash for buffering and OTA |
| R307 / R503 fingerprint module | UART; stores and matches templates on-module |
| DS3231 RTC | Timestamps must survive power cuts |
| SSD1306 OLED, buzzer, RGB LED | Users need to know instantly whether it registered |
| RC522 / PN532 RFID reader | Add from day one, see invariant 1 |
| 5V supply + 18650/TP4056 backup | Power reliability is a real constraint |

## Roadmap

- [x] Schema, invariants, device protocol
- [x] Gateway: signing, idempotent ingest, commands, roster
- [x] Firmware: buffer + signing logic, host-tested
- [x] Firmware: batch serialisation + response parsing, host-tested against the gateway
- [ ] Firmware: LittleFS `Storage` implementation — until this exists `g_buffer` is null and the terminal cannot run
- [ ] Firmware: first build with the ESP32 toolchain, then first run on hardware
- [x] Attendance engine: pairing, day boundary, amendments, review queue
- [ ] Provisioning flow (currently returns 501 rather than pretending to work)
- [ ] OTA with Ed25519 verification — **before device #3 leaves the desk**; an unsigned OTA channel is remote code execution into every site you deploy to
- [ ] Admin UI over the review queue
- [ ] Guardian notifications (Africa's Talking / WhatsApp)
- [ ] HR and school-portal integrations

## Before production

Biometric data is regulated. In Kenya it is *sensitive personal data* under the Data Protection Act 2019, which brings ODPC registration, explicit consent, a DPIA, a defined retention period and a working deletion path; the ODPC has published draft guidance specifically on biometric processing. Children's data carries extra consent requirements.

`audit_log` is scaffolded for the access-logging obligation — biometric **reads** need logging, not just writes. The retention policy, consent capture and erasure path are not built yet. Do not deploy to a real school or hospital until they are.

## Licence

MIT — see [LICENSE](LICENSE).
