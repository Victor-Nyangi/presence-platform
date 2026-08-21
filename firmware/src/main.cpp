// main.cpp — ESP32 presence terminal.
//
// STATUS: complete but UNPROVEN ON HARDWARE. The structure, task split, and
// ordering rules below are the design that matters, and the protocol-critical
// pieces (ring buffer, signing string, batch serialisation, response parsing)
// are covered by host tests that run without an ESP32. Everything that
// touches the sensor, Wi-Fi, RTC or NVS is wired but has never been executed
// on a real board.
//
// The one rule this file exists to enforce: THE SCAN LOOP NEVER BLOCKS ON THE
// NETWORK. A nurse at 3am does not care that the uplink is down. Scanning,
// buffering and feedback happen on core 1 with no network calls anywhere in
// the path; core 0 drains the buffer whenever it can.
//
//                  ┌──────────────────────────────────────┐
//   BOOT ──► SELFTEST ──► [secret in NVS?] ──no──► PROVISION ──┐
//                  │            │yes                            │
//                  │            ▼                               │
//                  │        TIME_SYNC ◄─────────────────────────┘
//                  │            │
//                  └──────►   READY  ◄──────────────┐
//                            │  ▲                    │
//                 finger/card│  │                    │
//                            ▼  │                    │
//                         CAPTURE                    │
//                            ▼                       │
//                       LOCAL_MATCH                  │
//                            ▼                       │
//                      BUFFER_WRITE ──fail──► FAULT ─┘
//                            ▼
//                        FEEDBACK ────────────────────┘

#include <Arduino.h>
#include <Adafruit_Fingerprint.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <RTClib.h>
#include <WiFi.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include "canonical.h"
#include "events_json.h"
#include "littlefs_storage.h"
#include "ring_buffer.h"

namespace {

// --- pins / hardware -------------------------------------------------
constexpr int kFingerprintRX = 16;
constexpr int kFingerprintTX = 17;
constexpr int kBuzzerPin = 25;
constexpr int kLedGreenPin = 26;
constexpr int kLedRedPin = 27;

// --- protocol tuning (overridden by server config) -------------------
constexpr uint32_t kHeartbeatMs = 60'000;
constexpr uint32_t kFlushMs = 30'000;
constexpr uint32_t kDebounceMs = 5'000;
constexpr size_t kMaxBatch = 50;
constexpr uint32_t kBackoffMinMs = 5'000;
constexpr uint32_t kBackoffMaxMs = 300'000;

const char* kFirmwareVersion = "0.1.0";
const char* kApiBase = "https://api.example.com";

enum class State { Boot, SelfTest, Provision, TimeSync, Ready, Enroll, Ota, Fault };

State g_state = State::Boot;
uint32_t g_backoffMs = kBackoffMinMs;
Preferences g_nvs;
RTC_DS3231 g_rtc;
Adafruit_Fingerprint g_finger(&Serial2);

presence::LittleFsStorage* g_storage = nullptr;
presence::RingBuffer* g_buffer = nullptr;
QueueHandle_t g_feedbackQueue = nullptr;

uint8_t g_secret[32];
uint64_t g_seq = 0;
int64_t g_rtcOffsetMs = 0;  // server time minus RTC time
bool g_rtcTrusted = false;

// Debounce state: suppresses repeat reads of the SAME slot. A finger resting
// on the platen is sensor bounce, not a second punch. Anything outside the
// window is recorded raw and deduplicated server-side.
uint16_t g_lastSlot = 0;
uint32_t g_lastSlotAtMs = 0;

// --------------------------------------------------------------------
// Sequence numbers
//
// Commit to NVS BEFORE use. If power drops between commit and use we burn a
// number, which is harmless — the gateway's ack logic is gap-tolerant by
// design. The reverse order would REUSE a number after a reboot, which
// silently destroys idempotency: the server would treat a genuinely new
// punch as a duplicate and drop it.
// --------------------------------------------------------------------
uint64_t nextSeq() {
  g_seq++;
  g_nvs.putULong64("seq", g_seq);
  return g_seq;
}

int64_t nowEpochMs() {
  if (!g_rtcTrusted) return 0;
  return static_cast<int64_t>(g_rtc.now().unixtime()) * 1000 + g_rtcOffsetMs;
}

uint8_t timeSourceCode() {
  if (!g_rtcTrusted) return 2;                 // uptime_only
  return g_rtcOffsetMs == 0 ? 0 : 1;           // rtc_synced : rtc_unsynced
}

// --------------------------------------------------------------------
// Request signing — must stay byte-identical to the gateway. The format
// itself lives in canonical.h and is pinned by a golden vector on both sides.
// --------------------------------------------------------------------
std::string sha256Hex(const uint8_t* data, size_t len) {
  uint8_t out[32];
  mbedtls_sha256(data, len, out, 0);
  return presence::toHex(out, sizeof(out));
}

std::string hmacHex(const std::string& msg) {
  uint8_t out[32];
  const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  mbedtls_md_hmac(info, g_secret, sizeof(g_secret),
                  reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), out);
  return presence::toHex(out, sizeof(out));
}

std::string randomNonce() {
  char buf[33];
  for (int i = 0; i < 32; i += 8) {
    snprintf(buf + i, 9, "%08x", static_cast<unsigned>(esp_random()));
  }
  return std::string(buf, 32);
}

// randomUuid formats 16 random bytes as a v4 UUID. The gateway stores
// request_id in a uuid column, so anything else is a 500 on ingest rather
// than a clean rejection.
std::string randomUuid() {
  uint8_t raw[16];
  for (int i = 0; i < 16; i += 4) {
    const uint32_t r = esp_random();
    raw[i + 0] = static_cast<uint8_t>(r);
    raw[i + 1] = static_cast<uint8_t>(r >> 8);
    raw[i + 2] = static_cast<uint8_t>(r >> 16);
    raw[i + 3] = static_cast<uint8_t>(r >> 24);
  }
  raw[6] = (raw[6] & 0x0F) | 0x40;
  raw[8] = (raw[8] & 0x3F) | 0x80;
  return presence::formatUuid(raw);
}

// signedPost returns the HTTP status, or a negative value on transport error.
// path must NOT include a query string; the gateway signs the path alone.
int signedPost(const char* path, const std::string& body, String* response) {
  HTTPClient http;
  http.begin(String(kApiBase) + path);
  http.setTimeout(15000);

  const int64_t ts = nowEpochMs() ? nowEpochMs() : (int64_t)time(nullptr) * 1000;
  const std::string nonce = randomNonce();
  const std::string digest = sha256Hex(reinterpret_cast<const uint8_t*>(body.data()), body.size());
  const std::string sig = hmacHex(presence::canonicalString("POST", path, ts, nonce, digest));

  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Id", g_nvs.getString("device_id", ""));
  http.addHeader("X-Key-Version", String(g_nvs.getInt("key_version", 1)));
  http.addHeader("X-Timestamp", String((long long)ts));
  http.addHeader("X-Nonce", nonce.c_str());
  http.addHeader("X-Signature", sig.c_str());

  const int code = http.POST(reinterpret_cast<uint8_t*>(const_cast<char*>(body.data())), body.size());
  if (response) *response = http.getString();
  http.end();
  return code;
}

// --------------------------------------------------------------------
// Task 1: scan loop. Core 1. No network calls anywhere in this path.
// --------------------------------------------------------------------
void scanTask(void*) {
  for (;;) {
    if (g_state != State::Ready) {
      vTaskDelay(pdMS_TO_TICKS(50));
      continue;
    }

    if (g_finger.getImage() != FINGERPRINT_OK) {
      vTaskDelay(pdMS_TO_TICKS(50));
      continue;
    }
    if (g_finger.image2Tz() != FINGERPRINT_OK) continue;

    // Matching happens ON THE SENSOR MODULE. It returns a slot number and a
    // confidence score; the fingerprint image never reaches the ESP32, never
    // reaches flash, and never reaches the network.
    if (g_finger.fingerFastSearch() != FINGERPRINT_OK) {
      const uint8_t deny = 0;
      xQueueSend(g_feedbackQueue, &deny, 0);
      vTaskDelay(pdMS_TO_TICKS(600));
      continue;
    }

    const uint32_t nowMs = millis();
    if (g_finger.fingerID == g_lastSlot && (nowMs - g_lastSlotAtMs) < kDebounceMs) {
      vTaskDelay(pdMS_TO_TICKS(200));
      continue;
    }
    g_lastSlot = g_finger.fingerID;
    g_lastSlotAtMs = nowMs;

    presence::PunchRecord rec{};
    rec.seq = nextSeq();
    rec.capturedEpochMs = static_cast<uint64_t>(nowEpochMs());
    rec.capturedUptimeMs = static_cast<uint64_t>(esp_timer_get_time() / 1000);
    rec.slotNo = g_finger.fingerID;
    rec.matchScore = g_finger.confidence;
    rec.credentialKind = 0;
    rec.timeSource = timeSourceCode();
    rec.directionHint = 0;
    esp_fill_random(rec.uuid, sizeof(rec.uuid));
    rec.uuid[6] = (rec.uuid[6] & 0x0F) | 0x40;  // UUIDv4
    rec.uuid[8] = (rec.uuid[8] & 0x3F) | 0x80;

    // ORDER MATTERS. Persist first, confirm second. Beeping green before the
    // flash write succeeds tells someone they clocked in when they did not.
    const bool persisted = g_buffer->append(rec);
    const uint8_t verdict = persisted ? 1 : 2;
    xQueueSend(g_feedbackQueue, &verdict, 0);

    if (!persisted) g_state = State::Fault;
    vTaskDelay(pdMS_TO_TICKS(800));
  }
}

// Feedback is its own consumer so the scan loop is never blocked by a
// half-second buzzer tone.
void feedbackTask(void*) {
  uint8_t verdict;
  for (;;) {
    if (xQueueReceive(g_feedbackQueue, &verdict, portMAX_DELAY) != pdTRUE) continue;
    switch (verdict) {
      case 1:  // stored
        digitalWrite(kLedGreenPin, HIGH);
        tone(kBuzzerPin, 2000, 120);
        vTaskDelay(pdMS_TO_TICKS(400));
        digitalWrite(kLedGreenPin, LOW);
        break;
      default:  // not matched, or not stored
        digitalWrite(kLedRedPin, HIGH);
        tone(kBuzzerPin, 400, 400);
        vTaskDelay(pdMS_TO_TICKS(600));
        digitalWrite(kLedRedPin, LOW);
        break;
    }
  }
}

// --------------------------------------------------------------------
// Task 2: network. Core 0. Never touches scan state directly — the ring
// buffer and the feedback queue are the only shared surfaces.
// --------------------------------------------------------------------

// Batch serialisation and response parsing live in events_json.h, free of
// Arduino headers and covered by the host tests, for the same reason the
// signing string does: a field name that disagrees with the gateway does not
// fail loudly, it stores the punch as malformed. What remains here is the
// part that genuinely needs the hardware.

// handleClockSkew turns a 401 into a correction instead of a lockout.
//
// Signing needs a roughly-correct clock, and a dead RTC battery is exactly
// what breaks that — so the gateway returns its own time with the rejection.
// We adopt it as an offset rather than trusting the RTC, and mark the clock
// usable so the retry signs inside the window.
void handleClockSkew(const String& problemResponse) {
  int64_t serverMs = 0;
  if (!presence::parseJsonInt(problemResponse.c_str(), "server_time_ms", &serverMs)) {
    // A 401 without a server clock is a real auth failure (wrong secret,
    // revoked device), not a skew we can correct. Retrying cannot help.
    return;
  }

  const int64_t rtcMs = static_cast<int64_t>(g_rtc.now().unixtime()) * 1000;
  g_rtcOffsetMs = serverMs - rtcMs;
  g_rtcTrusted = true;

  // Persist the offset so a reboot does not have to earn another 401 to
  // rediscover it.
  g_nvs.putLong64("rtc_offset", g_rtcOffsetMs);

  // Once the drift is beyond a minute the RTC itself is wrong, not merely
  // unsynchronised; write it back so buffered punches taken before the next
  // successful upload carry a sane timestamp.
  if (g_rtcOffsetMs > 60'000 || g_rtcOffsetMs < -60'000) {
    g_rtc.adjust(DateTime(static_cast<uint32_t>(serverMs / 1000)));
    g_rtcOffsetMs = 0;
    g_nvs.putLong64("rtc_offset", 0);
  }
}

// sendHeartbeat reports telemetry and reads back VERSION COUNTERS, not data.
// The device compares them against what it holds and fetches a delta only
// when one actually moves, which is what keeps a 60-second poll small enough
// to run over a school's uplink.
bool sendHeartbeat() {
  std::string body = "{\"firmware_version\":\"";
  body += kFirmwareVersion;
  body += "\",\"uptime_ms\":";
  body += presence::jsonInt(static_cast<int64_t>(esp_timer_get_time() / 1000));
  body += ",\"buffer_depth\":";
  body += presence::jsonInt(static_cast<int64_t>(g_buffer->depth()));
  body += ",\"last_seq\":";
  body += presence::jsonInt(static_cast<int64_t>(g_seq));
  body += ",\"rssi\":";
  body += presence::jsonInt(WiFi.RSSI());
  body += ",\"free_heap\":";
  body += presence::jsonInt(static_cast<int64_t>(ESP.getFreeHeap()));
  body += ",\"sensor_ok\":";
  body += g_finger.verifyPassword() ? "true" : "false";
  body += ",\"rtc_ok\":";
  body += g_rtcTrusted ? "true" : "false";
  body += "}";

  String resp;
  const int code = signedPost("/v1/device/heartbeat", body, &resp);
  if (code == 401) {
    handleClockSkew(resp);
    return false;
  }
  if (code != 200) return false;

  int64_t v = 0;
  if (presence::parseJsonInt(resp.c_str(), "server_time_ms", &v) && !g_rtcTrusted) {
    // First contact after a cold boot with a dead RTC: adopt the server's
    // clock here rather than waiting for a punch to be rejected.
    g_rtc.adjust(DateTime(static_cast<uint32_t>(v / 1000)));
    g_rtcOffsetMs = 0;
    g_rtcTrusted = true;
  }

  // The server can shed a reconnect herd: when a site's power returns and
  // forty terminals come back at once, it asks them to spread out.
  if (presence::parseJsonInt(resp.c_str(), "backoff_s", &v) && v > 0) {
    g_backoffMs = static_cast<uint32_t>(v) * 1000;
  }
  if (presence::parseJsonInt(resp.c_str(), "commands_pending", &v) && v > 0) {
    // Command handling is not built yet. Recording the count keeps the
    // heartbeat honest rather than pretending nothing is queued.
    log_i("commands pending: %lld", static_cast<long long>(v));
  }
  return true;
}

void resetBackoff() { g_backoffMs = kBackoffMinMs; }

void growBackoff() {
  g_backoffMs = min(g_backoffMs * 2, kBackoffMaxMs);
  // Jitter: when a school's power returns, forty terminals reconnect at once.
  // Without this they retry in lockstep and hammer the gateway together.
  g_backoffMs += esp_random() % (g_backoffMs / 4 + 1);
}

// flushEvents uploads from the buffer tail and drops ONLY what the server
// acknowledged. A lost response therefore costs a retry, never a punch.
bool flushEvents() {
  presence::PunchRecord batch[kMaxBatch];
  const size_t n = g_buffer->peek(batch, kMaxBatch);
  if (n == 0) return true;

  const presence::BatchMeta meta{
      randomUuid(),
      static_cast<uint64_t>(esp_timer_get_time() / 1000),
      g_buffer->depth(),
  };
  const std::string body = presence::buildEventsJson(batch, n, meta);
  String resp;
  const int code = signedPost("/v1/device/events", body, &resp);

  if (code == 401) {
    // Recoverable by design: the gateway returns its own clock with the
    // rejection so a terminal with a dead RTC can correct itself instead of
    // being locked out permanently.
    handleClockSkew(resp);
    return false;
  }
  if (code != 200) return false;

  // -1 means the response carried no ack at all. Truncating on that would
  // drop punches the server never confirmed, so treat it as a failed flush.
  const int64_t ack = presence::parseAckThrough(resp.c_str());
  if (ack < 0) return false;
  if (ack > 0) g_buffer->ackThrough(static_cast<uint64_t>(ack));
  return true;
}

void netTask(void*) {
  uint32_t lastHeartbeat = 0, lastFlush = 0;
  for (;;) {
    if (WiFi.status() != WL_CONNECTED) {
      // Scanning continues regardless; this is the whole point of the buffer.
      WiFi.reconnect();
      vTaskDelay(pdMS_TO_TICKS(g_backoffMs));
      growBackoff();
      continue;
    }

    const uint32_t now = millis();
    bool ok = true;

    if (now - lastHeartbeat > kHeartbeatMs) {
      ok = sendHeartbeat() && ok;  // returns version counters; fetch deltas only when they move
      lastHeartbeat = now;
    }
    if (now - lastFlush > kFlushMs || g_buffer->depth() >= kMaxBatch) {
      ok = flushEvents() && ok;
      lastFlush = now;
    }

    ok ? resetBackoff() : growBackoff();
    vTaskDelay(pdMS_TO_TICKS(ok ? 1000 : g_backoffMs));
  }
}

}  // namespace

void setup() {
  Serial.begin(115200);
  pinMode(kBuzzerPin, OUTPUT);
  pinMode(kLedGreenPin, OUTPUT);
  pinMode(kLedRedPin, OUTPUT);

  g_state = State::SelfTest;
  LittleFS.begin(true);
  g_nvs.begin("presence", false);
  g_seq = g_nvs.getULong64("seq", 0);

  Serial2.begin(57600, SERIAL_8N1, kFingerprintRX, kFingerprintTX);
  if (!g_finger.verifyPassword()) g_state = State::Fault;

  // A dead RTC is not fatal. Events are stamped with uptime instead and the
  // gateway reconstructs wall time from the delta at upload, flagging them
  // low-confidence for review rather than discarding them.
  g_rtcTrusted = g_rtc.begin() && !g_rtc.lostPower();

  // Restore the correction learned from the last clock_skew rejection, so a
  // reboot does not have to earn another 401 to rediscover it.
  g_rtcOffsetMs = g_nvs.getLong64("rtc_offset", 0);

  g_feedbackQueue = xQueueCreate(8, sizeof(uint8_t));

  // The buffer is what makes an outage survivable, so a terminal that
  // cannot open one is faulted rather than left running. Booting without it
  // would look healthy and silently drop every punch taken offline.
  g_storage = new presence::LittleFsStorage(&g_nvs);
  g_buffer = new presence::RingBuffer(g_storage);
  if (!g_storage->begin() || !g_buffer->begin()) {
    Serial.println("FAULT: punch buffer unavailable");
    g_state = State::Fault;
  } else {
    // Printed because the capacity is computed from whatever the LittleFS
    // partition actually has. This line is the authoritative answer to how
    // long an outage this device can ride out; docs can only estimate it.
    Serial.printf("punch buffer: %u records, %u buffered\n",
                  static_cast<unsigned>(g_storage->records()),
                  static_cast<unsigned>(g_buffer->depth()));
  }

  if (!g_nvs.isKey("device_secret")) {
    g_state = State::Provision;
  } else {
    g_nvs.getBytes("device_secret", g_secret, sizeof(g_secret));
    g_state = State::TimeSync;
  }

  xTaskCreatePinnedToCore(scanTask, "scan", 8192, nullptr, 2, nullptr, 1);
  xTaskCreatePinnedToCore(feedbackTask, "feedback", 4096, nullptr, 1, nullptr, 1);
  xTaskCreatePinnedToCore(netTask, "net", 16384, nullptr, 1, nullptr, 0);
}

void loop() { vTaskDelay(pdMS_TO_TICKS(1000)); }
