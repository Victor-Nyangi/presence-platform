# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`/home/nyangi/Bread/Projects/In Progress/CLAUDE.md` describes the surrounding workspace; this file is authoritative for anything under `presence-platform/`.

## What this is

Credential-agnostic presence/attendance tracking. Three deployables in one repo, no shared build:

- `db/` — Postgres schema + a SQL invariant suite
- `gateway/` — Go service: device-facing HTTPS ingest (`cmd/gateway`) and the derived-attendance rebuilder (`cmd/recompute`)
- `firmware/` — ESP32/PlatformIO terminal (skeleton; see *Firmware status* below)

`docs/SPEC.md` carries the design reasoning and `docs/openapi.yaml` is the normative device API. `README.md` restates most of it. **Read SPEC.md before changing protocol, schema, or attendance semantics** — nearly every non-obvious choice here is deliberate and explained there.

## Commands

Everything is driven from the repo-root `Makefile` (`make help` lists targets). `DB_URL` defaults to the docker-compose Postgres.

```bash
cd gateway && go mod tidy && cd ..   # REQUIRED on a fresh checkout: go.sum is not committed
docker compose up -d postgres
make db-load            # apply 001_schema.sql, then run 002_smoke_test.sql
make test               # gateway unit tests + firmware host tests
make test-integration   # gateway tests against real Postgres (see caveat below)
make firmware-test      # host-compiled firmware logic tests, no ESP32 toolchain needed
make build              # ./.build/gateway and ./.build/recompute
make run                # build + run the gateway on :8080
make fmt lint           # gofmt -w . / go vet ./...
make recompute ORG=<uuid> DAYS=7
```

Single tests:

```bash
cd gateway && go test -run TestPairOvernightShiftIsFlaggedAndNotSplit ./internal/attendance/
cd gateway && PRESENCE_TEST_DATABASE_URL="$DB_URL" go test -tags integration -run TestPoisonEventDoesNotWedgeTheBuffer ./internal/api/
```

Firmware hardware builds (`pio run`, `pio run -t upload`, `pio device monitor`) live in `firmware/platformio.ini`; the host tests deliberately need none of it.

CI (`.github/workflows/ci.yml`) runs: schema + smoke test, `go vet`, a `gofmt -l` emptiness check, `go test -race`, the integration suite, `make firmware-test`, and OpenAPI 3.1 validation of `docs/openapi.yaml`. A `gofmt` diff fails the build.

### Test layout gotchas

- Integration tests are behind `//go:build integration` and **skip silently** without `PRESENCE_TEST_DATABASE_URL`. `make test` therefore does not run them — a passing `make test` proves much less than it looks like.
- They also need `-p 1`. The `api` and `attendance` suites each `TRUNCATE` and re-seed the *same* database, so `go test`'s default package parallelism makes them clobber each other. `make test-integration` passes the flag; `.github/workflows/ci.yml:52` does **not**, so CI is intermittently red for this reason.
- Those tests `TRUNCATE` core tables on setup. Never point `PRESENCE_TEST_DATABASE_URL` at a database you care about.
- `db/` is mounted as `/docker-entrypoint-initdb.d` in compose, so both SQL files run on first boot of an empty volume. `002_smoke_test.sql` ends in `ROLLBACK`, so it leaves no rows.
- `firmware/test/host_test.cpp` is a single hand-rolled binary (no framework, no `-run` filter); it compiles only `crc32.cpp` alongside itself.

### Configuration

`PRESENCE_DATABASE_URL`, `PRESENCE_KEKS` (`id:hex64[,id:hex64]`), `PRESENCE_KEK_ID`, `PRESENCE_TOKEN_PEPPER` are all required with **no defaults** — `config.Load` returns an error rather than booting with a development key. Keep it that way. See `.env.example`.

## Architecture

### Layering, strictly enforced by convention

| Package | Rule |
|---|---|
| `internal/api` | HTTP only. Validates, delegates, shapes responses. **No SQL, no crypto.** |
| `internal/store` | **All** SQL lives here. If you need a new query, it goes in this file, not a handler. |
| `internal/attendance/rules.go` | **Pure.** No database, no clock, no I/O — so the rules can be exercised exhaustively without Postgres. |
| `internal/attendance/engine.go` | Reads rows → calls `rules.go` → writes rows. |
| `internal/model` | Wire types mirroring `docs/openapi.yaml`. Change one, change both. |

Handlers reach the store through the `signed()` middleware, which resolves the device and hands the handler a `*store.Device` plus the already-read body (the body must be read before verification because it is part of the signature).

### The invariants everything else follows from

Breaking one of these looks like a small change and isn't:

1. **`punch_event` is append-only** — enforced by a Postgres trigger, not convention. Corrections are additive `punch_amendment` rows; later amendment wins per field. `attendance_span` and `attendance_day` are fully derivable and safe to drop and rebuild.
2. **Rejected ≠ discarded.** Unresolvable events are stored with a reason *and still advance `ack_through`*. Making rejections not advance the ack wedges the device buffer permanently behind one poison event.
3. **`ack_through` is batch-relative, not history-relative.** The device burns sequence numbers on power loss (it commits to NVS before use), so contiguity against server history would stall that device forever. `IngestBatch` sorts the batch and walks it, stopping at the first seq that did not store.
4. **Slot→person bindings are time-bounded.** `store.resolve` queries `device_slot` *as of the event's effective time*, and `punch_event.person_id` is snapshotted at ingest. Both are required for history to survive slot reuse.
5. **Time is three columns** — `captured_at` (device belief), `received_at` (server), `effective_at` (what is reported on) — plus `src_time`/`time_conf`. `effectiveTime()` reconstructs wall time for `uptime_only` events from the uptime delta at upload. Never collapse these.
6. **Direction is computed server-side.** Devices send `direction_hint` only; `deriveDirection` uses device mode, or flips from the person's last resolved state for bidirectional readers.

### Attendance rules that are easy to get backwards

- **Day boundary defaults to 04:00, not midnight.** `BusinessDate` shifts back by the boundary before truncating.
- **`overnight` means "crossed a *business* day"**, not "crossed midnight". A routine 19:00→03:30 shift is clean; flagging it would flood the review queue.
- **A span is attributed wholly to the day it started.** Hours are never split across days.
- **An open span accrues zero time** (`Span.Duration()` returns 0) and flags `missing_out`.
- **Two `in`s never merge**, and an orphan `out` is recorded as a zero-length `missing_in` marker that must *not* count as an arrival in `Rollup`.
- Anomalies are facts, not errors; any anomaly or open span sets `needs_review`.
- The engine fetches `lookbackDays = 2` outside the requested window so window edges don't invent anomalies, but writes only the requested window.
- `rules.go` imports `_ "time/tzdata"` because the gateway ships distroless — without it `LoadLocation` fails in production and succeeds on every laptop. An unusable org timezone is a hard error, never a silent UTC fallback.
- Postgres weekdays are ISO (1=Mon..7=Sun), Go's are 0=Sun; `loadSchedules` converts with `%7`.

### Auth and secrets

- HMAC-SHA256 over a newline-joined canonical string: `v1 / METHOD / PATH / ts_ms / nonce / sha256_hex(body)`. **The path excludes the query string** (`r.URL.Path`).
- **The canonical format is pinned by the same golden vector on both sides** — `gateway/internal/auth/conformance_test.go` and `firmware/test/host_test.cpp`. Changing the format means changing both, or CI fails (which is the point: the alternative is every deployed terminal 401-ing after a release).
- `auth.Verify` checks **skew → signature → nonce**, in that order, and the order is load-bearing: skew first so a dead-RTC device gets a recoverable `ErrClockSkew` (every error body carries `server_time_ms`); nonce last so an unauthenticated caller cannot poison the cache.
- `GET /v1/device/time` is unauthenticated by necessity — signing needs a clock and the clock is what's broken.
- **Device HMAC secrets are encrypted (AES-256-GCM under a KEK), not hashed** — verification needs the raw key. AAD is the device id, so a row can't be moved between devices. Only bearer values the client presents verbatim (the provisioning token) are hashed.
- Two independent version counters, do not conflate: `key_version` (per-device secret generation) vs `secret_key_id` (platform-wide KEK generation). `LoadDevice` returns both current and previous device secrets so an in-flight rotation can't brick a terminal.
- `auth.MemoryNonceCache` is single-process. Behind a load balancer replay protection is broken — swap in Redis `SETNX` with a `2*MaxSkew` TTL before scaling out.

### Known-incomplete surfaces

- `POST /v1/device/provision` returns **501 on purpose** so it can't be mistaken for a working open endpoint. The installer flow isn't built.
- OTA signature verification (Ed25519) is designed but not implemented; per SPEC this must land before a third device ships.
- Retention/consent/erasure for biometric data and the `audit_log` read-logging path are scaffolded only. See the README's *Before production* section — biometric data is regulated (Kenya DPA 2019) and this is not deployable to a real school or hospital yet.

### Firmware status

The four previously-unimplemented helpers are done. `buildEventsJson` and `parseAckThrough` moved into `firmware/src/events_json.h`; `handleClockSkew` and `sendHeartbeat` are Arduino wrappers in `main.cpp`.

**It still cannot run on a board:** `setup()` never constructs `g_buffer` — the line is commented out because no LittleFS-backed `Storage` implementation exists — so the scan and net tasks would dereference null. Nothing here has been built with the ESP32 toolchain or run on hardware.

What *is* tested lives in `ring_buffer.h`, `canonical.h` and `events_json.h`, kept free of Arduino headers precisely so it compiles under plain `g++`. `events_json.h` also avoids `printf`: ESP-IDF's default newlib-nano does not handle `%lld` without an sdkconfig flag, and a wire format should not depend on a build option. Two ordering rules in that code are the whole point of it:

- **Confirm the punch only after the flash write succeeds.** Beeping green on a failed write tells someone they clocked in when they didn't.
- **Commit the sequence number to NVS before using it.** The reverse order reuses a number after a reboot and silently destroys idempotency.

`PunchRecord` is a 60-byte packed POD with a `static_assert` on its size — changing the layout is a storage format break.
