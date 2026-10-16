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
//
//   OTA (net task, scanning continues throughout):
//     manifest ──► newer than running AND floor? ──► download to the idle slot
//     ──► read it back ──► sha256 + Ed25519 (preamble with the version, then
//     the image) ──► record pending in NVS ──► set boot ──► reboot
//     Any failure leaves the boot partition alone, so the running image stays.
//
//   After the reboot the new image is PENDING_VERIFY. The first successful
//   heartbeat marks it valid and raises the version floor; no heartbeat within
//   the confirm window, a crash or a power cut reboots it unconfirmed and the
//   bootloader falls back to the previous slot. See ota_guard.h.

#include <Arduino.h>
#include <Adafruit_Fingerprint.h>
#include <HTTPClient.h>
#include <LittleFS.h>
#include <Preferences.h>
#include <RTClib.h>
#include <WiFi.h>
#include <esp_ota_ops.h>
#include <esp_partition.h>
#include <esp_rom_sys.h>
#include <esp_timer.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>

#include <algorithm>
#include <memory>
#include <new>

#include "canonical.h"
#include "events_json.h"
#include "littlefs_storage.h"
#include "ota_guard.h"
#include "ota_pubkey.h"
#include "ota_verify.h"
#include "ring_buffer.h"

// The version, as a marker `fwsign sign` finds in the image and compares with
// its -version flag. The signed version is what the terminal trusts, so a
// release signed as 0.3.0 that is really a 0.2.0 build would confuse every
// comparison after it; fwsign refuses to sign one. kFirmwareVersion points
// into this array, so the linker cannot drop it.
extern "C" const char kPresenceVersionMarker[];
extern "C" const char kPresenceVersionMarker[] = "PRESENCE_FW_VERSION=" FIRMWARE_VERSION;

// Arduino's initArduino() marks a PENDING_VERIFY image valid before setup()
// runs unless the sketch defines this hook to return true. Defining it hands
// that decision to OtaGuard: valid only after the first good heartbeat. (The
// bootloader in this core is built with CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE.)
extern "C" bool verifyRollbackLater() { return true; }

namespace {

const char* kFirmwareVersion = kPresenceVersionMarker + sizeof("PRESENCE_FW_VERSION=") - 1;

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

// From platformio.ini's -DFIRMWARE_VERSION, so the version a build reports
// (heartbeat, OTA comparison) is the one it was built as. It must be
// MAJOR.MINOR.PATCH: downgrade protection compares it numerically, and a
// build whose version cannot be compared does not compile.
#ifndef FIRMWARE_VERSION
#define FIRMWARE_VERSION "0.0.0"
#endif
static_assert(presence::otaVersionCodeLiteral(FIRMWARE_VERSION) != presence::kInvalidOtaVersion,
              "FIRMWARE_VERSION must be MAJOR.MINOR.PATCH (docs/ota-signing.md)");
const char* kApiBase = "https://api.example.com";

// How long a freshly installed image has to reach the gateway before it is
// rolled back. Heartbeats run every 60 s and back off to 5 min on failure, so
// ten minutes is several attempts. The bench env shortens it.
#ifndef PRESENCE_OTA_CONFIRM_MS
#define PRESENCE_OTA_CONFIRM_MS 600000
#endif

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

// Set by the heartbeat, consumed by the net task.
bool g_firmwareAvailable = false;
// The sha256 of the last image that FAILED VERIFICATION, so a manifest that
// keeps advertising a bad image costs one download, not one every minute.
// Transport failures are not recorded here; those are worth retrying.
uint8_t g_otaRejectedSha[presence::kSha256Bytes] = {};
bool g_otaRejected = false;

// OtaGuard's two bindings. The decisions are in ota_guard.h, under host test.
class NvsOtaStateStore : public presence::OtaStateStore {
 public:
  bool load(presence::OtaPersistedState* out) override {
    if (!g_nvs.isKey("ota_state") || g_nvs.getBytesLength("ota_state") != sizeof(*out)) return false;
    return g_nvs.getBytes("ota_state", out, sizeof(*out)) == sizeof(*out);
  }
  bool save(const presence::OtaPersistedState& s) override {
    return g_nvs.putBytes("ota_state", &s, sizeof(s)) == sizeof(s);
  }
};

void confirmDeadlineExpired(void*);

class EspBootControl : public presence::OtaBootControl {
 public:
  bool markValid() override { return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK; }
  void rollback() override {
    Serial.println("OTA: new image not confirmed in time, rolling back to the previous one");
    Serial.flush();
    // Reboots when otadata names a previous slot. On the first update after a
    // USB flash it does not (the flashed slot has no otadata entry yet), and
    // this returns ESP_ERR_OTA_ROLLBACK_FAILED. Rebooting anyway is the same
    // rollback: this image is still PENDING_VERIFY, so the bootloader marks it
    // ABORTED and, with no other entry, boots ota_0, which holds the old image.
    esp_ota_mark_app_invalid_rollback_and_reboot();
    esp_restart();
  }
  // esp_timer, not the task watchdog: the network task blocks for minutes
  // by design (backoff, 15 s HTTP timeouts, a 775 KB download), so a TWDT
  // would need feeding at every one of those points, and it would also reset
  // a confirmed terminal whose network task merely stalled. The timer runs in
  // the esp_timer task, which no application task can starve, and does one
  // thing that is safe whatever state the image is in.
  bool armConfirmDeadline(uint32_t ms) override {
    if (timer_ == nullptr) {
      esp_timer_create_args_t args = {};
      args.callback = &confirmDeadlineExpired;
      args.name = "ota_confirm";
      if (esp_timer_create(&args, &timer_) != ESP_OK) return false;
    }
    return esp_timer_start_once(timer_, static_cast<uint64_t>(ms) * 1000) == ESP_OK;
  }
  void cancelConfirmDeadline() override {
    if (timer_ != nullptr) esp_timer_stop(timer_);
  }
  void restartUnconfirmed() override {
    // No Serial here: the UART driver's lock may be held by the task that
    // hung. The ROM printf writes straight to the FIFO.
    esp_rom_printf("OTA: confirm deadline passed, restarting into the previous image\n");
    esp_restart();
  }

 private:
  esp_timer_handle_t timer_ = nullptr;
};

NvsOtaStateStore g_otaStore;
EspBootControl g_bootControl;
presence::OtaGuard g_otaGuard(&g_otaStore, &g_bootControl, PRESENCE_OTA_CONFIRM_MS);

void confirmDeadlineExpired(void*) { g_otaGuard.onConfirmDeadline(); }

// Serialises OtaGuard and applyOta between the net task and, in the bench
// build, the serial loader in loop(): two updates writing the idle slot at
// once would corrupt each other.
SemaphoreHandle_t g_otaMutex = nullptr;
struct OtaLock {
  OtaLock() { xSemaphoreTake(g_otaMutex, portMAX_DELAY); }
  ~OtaLock() { xSemaphoreGive(g_otaMutex); }
};

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

// addAuthHeaders signs one request. path must NOT include a query string;
// the gateway signs r.URL.Path alone.
void addAuthHeaders(HTTPClient& http, const char* method, const char* path, const std::string& body) {
  const int64_t ts = nowEpochMs() ? nowEpochMs() : (int64_t)time(nullptr) * 1000;
  const std::string nonce = randomNonce();
  const std::string digest = sha256Hex(reinterpret_cast<const uint8_t*>(body.data()), body.size());
  const std::string sig = hmacHex(presence::canonicalString(method, path, ts, nonce, digest));

  http.addHeader("X-Device-Id", g_nvs.getString("device_id", ""));
  http.addHeader("X-Key-Version", String(g_nvs.getInt("key_version", 1)));
  http.addHeader("X-Timestamp", String((long long)ts));
  http.addHeader("X-Nonce", nonce.c_str());
  http.addHeader("X-Signature", sig.c_str());
}

// signedPost returns the HTTP status, or a negative value on transport error.
int signedPost(const char* path, const std::string& body, String* response) {
  HTTPClient http;
  http.begin(String(kApiBase) + path);
  http.setTimeout(15000);
  http.addHeader("Content-Type", "application/json");
  addAuthHeaders(http, "POST", path, body);

  const int code = http.POST(reinterpret_cast<uint8_t*>(const_cast<char*>(body.data())), body.size());
  if (response) *response = http.getString();
  http.end();
  return code;
}

// signedGet: the query string goes on the URL but not into the signature.
int signedGet(const char* path, const String& query, String* response) {
  HTTPClient http;
  http.begin(String(kApiBase) + path + (query.length() ? "?" + query : String()));
  http.setTimeout(15000);
  addAuthHeaders(http, "GET", path, std::string());

  const int code = http.GET();
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
  bool firmware = false;
  if (presence::parseJsonBool(resp.c_str(), "firmware_available", &firmware)) {
    g_firmwareAvailable = firmware;
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

// --------------------------------------------------------------------
// OTA. SPEC §3: the OTA channel is a security boundary, so an image is
// bootable only after its Ed25519 signature verifies against the key
// compiled into THIS firmware (ota_pubkey.h). The verification logic lives
// in ota_verify.h under host test; this is the flash plumbing around it.
//
// Two ordering rules, in the spirit of "persist before confirm":
//
// - VERIFY WHAT WILL BOOT, NOT WHAT CAME OVER THE WIRE. The image is written
//   to the idle slot first and then read back from flash for sha256 and
//   Ed25519, so a bit that flips between download and flash cannot slip
//   past a check that ran on the RAM copy.
// - esp_ota_set_boot_partition() IS THE COMMIT, AND IT COMES LAST. Until it
//   runs, otadata still points at the running image. Every failure path
//   returns before it, and erases the head of the rejected slot so nothing
//   (rollback included) can ever select it.
// - THE DOWNGRADE CHECK COMES FIRST, the pending record just before the
//   commit (ota_guard.h). The version checked is the one the signature covers,
//   so a replayed old image cannot claim to be new.
// --------------------------------------------------------------------
enum class OtaOutcome { Applied, Transient, Rejected };

struct OtaResult {
  OtaOutcome outcome;
  const char* reason;  // nullptr when applied
};

constexpr size_t kOtaChunk = 4096;
constexpr uint32_t kOtaReadTimeoutMs = 30'000;

void invalidateSlot(const esp_partition_t* slot) {
  esp_partition_erase_range(slot, 0, SPI_FLASH_SEC_SIZE);
}

// applyOta streams `size` bytes from `in` into the idle OTA slot, verifies
// them from flash, and on success makes that slot the boot partition. It
// never reboots; the caller does. ready (optional) is called whenever applyOta
// is ready for the next chunk -- once after the slot is erased, then after
// each chunk is written. The bench serial loader uses it for flow control:
// flash erases and writes stall interrupts that are not in IRAM, the UART's
// among them, so bytes sent during one would overflow the 128-byte FIFO.
OtaResult applyOta(Stream& in, const std::string& version, size_t size,
                   const uint8_t sha256[presence::kSha256Bytes],
                   const uint8_t signature[presence::kEd25519SignatureBytes], void (*ready)()) {
  OtaLock lock;  // one update at a time
  // Refuse before erasing anything: with no usable key, nothing may verify.
  if (presence::isUnusableKey(presence::kOtaReleasePublicKey)) {
    return {OtaOutcome::Rejected, "no usable release key compiled in"};
  }
  if (size == 0) return {OtaOutcome::Rejected, "empty image"};
  // Older, equal, at or below the floor, rolled back once, or arriving while
  // this image is itself unconfirmed: refused before a byte is erased.
  const presence::OtaCandidate candidate = g_otaGuard.check(version, sha256);
  if (candidate != presence::OtaCandidate::Accept) {
    return {OtaOutcome::Rejected, presence::otaCandidateName(candidate)};
  }

  const esp_partition_t* slot = esp_ota_get_next_update_partition(nullptr);
  if (slot == nullptr) return {OtaOutcome::Rejected, "no idle OTA slot"};
  if (size > slot->size) return {OtaOutcome::Rejected, "image larger than the OTA slot"};

  std::unique_ptr<uint8_t[]> buf(new (std::nothrow) uint8_t[kOtaChunk]);
  if (!buf) return {OtaOutcome::Transient, "out of memory"};

  esp_ota_handle_t handle = 0;
  // Erases the whole of `size` up front, so no erase happens mid-download.
  if (esp_ota_begin(slot, size, &handle) != ESP_OK) return {OtaOutcome::Transient, "esp_ota_begin failed"};
  if (ready) ready();

  in.setTimeout(kOtaReadTimeoutMs);
  for (size_t done = 0; done < size;) {
    const size_t want = (size - done) < kOtaChunk ? (size - done) : kOtaChunk;
    if (in.readBytes(buf.get(), want) != want) {
      esp_ota_abort(handle);
      invalidateSlot(slot);
      return {OtaOutcome::Transient, "download truncated"};
    }
    if (esp_ota_write(handle, buf.get(), want) != ESP_OK) {
      esp_ota_abort(handle);
      invalidateSlot(slot);
      return {OtaOutcome::Transient, "flash write failed"};
    }
    done += want;
    if (ready && done < size) ready();
  }

  // esp_ota_end checks the app image format and its checksums. That catches
  // a corrupt download; it is NOT the security check -- anyone can build a
  // well-formed image. The handle is freed whatever it returns.
  if (esp_ota_end(handle) != ESP_OK) {
    invalidateSlot(slot);
    return {OtaOutcome::Rejected, "not a valid app image"};
  }

  presence::ImageVerifier verifier(presence::kOtaReleasePublicKey, signature, version, size);
  mbedtls_sha256_context sha;
  mbedtls_sha256_init(&sha);
  mbedtls_sha256_starts_ret(&sha, 0);
  for (size_t off = 0; off < size; off += kOtaChunk) {
    const size_t n = (size - off) < kOtaChunk ? (size - off) : kOtaChunk;
    if (esp_partition_read(slot, off, buf.get(), n) != ESP_OK) {
      mbedtls_sha256_free(&sha);
      invalidateSlot(slot);
      return {OtaOutcome::Transient, "flash read-back failed"};
    }
    mbedtls_sha256_update_ret(&sha, buf.get(), n);
    verifier.update(buf.get(), n);
  }
  uint8_t digest[presence::kSha256Bytes];
  mbedtls_sha256_finish_ret(&sha, digest);
  mbedtls_sha256_free(&sha);
  const presence::OtaVerdict verdict = verifier.finish();

  if (memcmp(digest, sha256, sizeof(digest)) != 0) {
    invalidateSlot(slot);
    return {OtaOutcome::Rejected, "sha256 does not match manifest"};
  }
  if (verdict != presence::OtaVerdict::Ok) {
    invalidateSlot(slot);
    return {OtaOutcome::Rejected, presence::otaVerdictName(verdict)};
  }

  // Pending record BEFORE the commit, so a rollback is always noticed.
  if (!g_otaGuard.notePending(version, sha256)) {
    invalidateSlot(slot);
    return {OtaOutcome::Transient, "could not record the pending update in NVS"};
  }
  // The commit. Only a verified, newer image gets here.
  if (esp_ota_set_boot_partition(slot) != ESP_OK) {
    g_otaGuard.clearPending();
    invalidateSlot(slot);
    return {OtaOutcome::Transient, "esp_ota_set_boot_partition failed"};
  }
  return {OtaOutcome::Applied, nullptr};
}

void rebootIntoNewImage() {
  Serial.println("OTA: image verified, boot partition set, rebooting");
  Serial.flush();
  // The punch buffer is in flash and the sequence counter is committed
  // before use, so a reboot here loses nothing that was confirmed.
  vTaskDelay(pdMS_TO_TICKS(200));
  esp_restart();
}

// checkFirmware fetches the manifest and, if it offers an image this
// terminal has not already rejected, downloads and applies it. Scanning
// continues on core 1 throughout; only the final reboot interrupts it.
bool checkFirmware() {
  String resp;
  const int code = signedGet("/v1/device/firmware", String("current=") + kFirmwareVersion, &resp);
  if (code == 401) {
    handleClockSkew(resp);
    return false;
  }
  if (code != 200) return false;

  presence::OtaManifest m;
  if (!presence::parseOtaManifest(resp.c_str(), &m)) {
    log_e("OTA: malformed manifest ignored");
    return false;
  }
  if (!m.available) {
    g_firmwareAvailable = false;
    return true;
  }
  if (g_otaRejected && memcmp(m.sha256, g_otaRejectedSha, sizeof(g_otaRejectedSha)) == 0) {
    return true;  // already refused this exact image; wait for a new one
  }
  presence::OtaCandidate candidate;
  {
    OtaLock lock;
    candidate = g_otaGuard.check(m.version, m.sha256);
  }
  if (candidate != presence::OtaCandidate::Accept) {
    // Not an error: the gateway does not know this terminal's floor.
    log_i("OTA: %s not taken: %s", m.version.c_str(), presence::otaCandidateName(candidate));
    g_firmwareAvailable = false;
    return true;
  }

  // A gateway-hosted image is a path on the API base, downloaded with the
  // same HMAC signature as every other device call. An absolute URL (an image
  // hosted elsewhere) is fetched unauthenticated, possibly over plain HTTP.
  // Either way the image's integrity comes from the signature, not the
  // transport.
  HTTPClient http;
  if (presence::otaUrlIsGatewayPath(m.url)) {
    http.begin(String(kApiBase) + m.url.c_str());
    addAuthHeaders(http, "GET", m.url.c_str(), std::string());
  } else {
    http.begin(m.url.c_str());
  }
  http.setTimeout(15000);
  const int got = http.GET();
  if (got != 200) {
    http.end();
    return false;
  }
  const int contentLength = http.getSize();
  if (contentLength >= 0 && static_cast<uint64_t>(contentLength) != m.size) {
    http.end();
    log_e("OTA: Content-Length %d does not match manifest size", contentLength);
    return false;
  }
  const OtaResult r =
      applyOta(*http.getStreamPtr(), m.version, static_cast<size_t>(m.size), m.sha256, m.signature, nullptr);
  http.end();

  if (r.outcome == OtaOutcome::Applied) rebootIntoNewImage();
  log_e("OTA: %s %s: %s", r.outcome == OtaOutcome::Rejected ? "rejected" : "failed", m.version.c_str(),
        r.reason);
  if (r.outcome == OtaOutcome::Rejected) {
    memcpy(g_otaRejectedSha, m.sha256, sizeof(g_otaRejectedSha));
    g_otaRejected = true;
  }
  return false;
}

#ifdef PRESENCE_BENCH_SERIAL_OTA
// Bench-only: the same applyOta, fed from the USB serial port, so the
// signature gate can be proven on a board before the gateway serves
// manifests. Built into esp32dev-debug only. It is no weaker than the
// network path -- the image still has to verify against the compiled-in
// key and pass the downgrade check -- and anyone at the USB port can
// already reflash with esptool.
//
// Protocol (firmware/tools/serial_ota.py speaks it):
//   host:   OTA <version> <size> <sha256-hex> <signature-hex>\n
//   device: OTA NEXT            (send the next 4096 bytes; repeats per chunk)
//   device: OTA OK              then reboots into the new image
//   device: OTA REJECT <reason> and keeps running the current image
//   host:   OTA STATUS\n        device: OTA STATUS running=.. floor=.. awaiting=.. pending=.. bad=..
//   host:   OTA HEALTHY\n       stands in for the first good heartbeat, which
//                               a bench board with no Wi-Fi never gets:
//                               device: OTA CONFIRMED running=.. floor=.. ...
void benchAck() { Serial.println("OTA NEXT"); }

void benchStatus(const char* tag) {
  OtaLock lock;
  const presence::OtaPersistedState& st = g_otaGuard.state();
  Serial.printf("OTA %s running=%s floor=%s awaiting=%d pending=%s bad=%s\n", tag, kFirmwareVersion,
                presence::formatOtaVersion(g_otaGuard.floor()).c_str(), g_otaGuard.awaitingConfirm() ? 1 : 0,
                st.hasPending ? presence::formatOtaVersion(st.pendingVersion).c_str() : "-",
                st.hasBad ? presence::toHex(st.badSha, 4).c_str() : "-");
}

void benchSerialOta() {
  if (!Serial.available()) return;
  String line = Serial.readStringUntil('\n');
  line.trim();
  if (line == "OTA STATUS") {
    benchStatus("STATUS");
    return;
  }
  if (line == "OTA HEALTHY") {
    {
      OtaLock lock;
      g_otaGuard.onHealthy();
    }
    benchStatus(g_otaGuard.healthy() ? "CONFIRMED" : "NOT-CONFIRMED");
    return;
  }
  if (!line.startsWith("OTA ")) return;

  // OTA <version> <size> <sha256> <signature>
  String field[4];
  int from = 4;
  for (int i = 0; i < 4; i++) {
    const int sp = line.indexOf(' ', from);
    if (i < 3 && sp < 0) {
      Serial.println("OTA REJECT malformed header");
      return;
    }
    field[i] = i < 3 ? line.substring(from, sp) : line.substring(from);
    from = sp + 1;
  }
  const std::string version = field[0].c_str();
  const long size = field[1].toInt();
  uint8_t sha[presence::kSha256Bytes];
  uint8_t sig[presence::kEd25519SignatureBytes];
  if (size <= 0 || !presence::decodeHexExact(field[2].c_str(), sha, sizeof(sha)) ||
      !presence::decodeHexExact(field[3].c_str(), sig, sizeof(sig))) {
    Serial.println("OTA REJECT malformed header");
    return;
  }

  const OtaResult r = applyOta(Serial, version, static_cast<size_t>(size), sha, sig, benchAck);
  if (r.outcome == OtaOutcome::Applied) {
    Serial.println("OTA OK");
    rebootIntoNewImage();
  }
  Serial.printf("OTA REJECT %s\n", r.reason);
}
#endif

// confirmHealthy: the gateway answered, so this image works. Marks a pending
// image valid and raises the version floor (ota_guard.h).
void confirmHealthy() {
  OtaLock lock;
  const bool wasAwaiting = g_otaGuard.awaitingConfirm();
  g_otaGuard.onHealthy();
  if (wasAwaiting && !g_otaGuard.awaitingConfirm()) {
    Serial.printf("OTA: %s confirmed by a gateway heartbeat; version floor %s\n", kFirmwareVersion,
                  presence::formatOtaVersion(g_otaGuard.floor()).c_str());
  }
}

// netSleep waits ms, but in one-second steps while an image awaits
// confirmation, so the rollback deadline is kept to the second instead of
// slipping by a whole backoff (up to five minutes with Wi-Fi down).
void netSleep(uint32_t ms) {
  while (ms > 0) {
    const uint32_t step = g_otaGuard.awaitingConfirm() ? std::min<uint32_t>(ms, 1000) : ms;
    vTaskDelay(pdMS_TO_TICKS(step));
    ms -= step;
    if (g_otaGuard.awaitingConfirm()) {
      OtaLock lock;
      g_otaGuard.tick(millis());
    }
  }
}

void netTask(void*) {
  uint32_t lastHeartbeat = 0, lastFlush = 0;
  for (;;) {
    // Before the Wi-Fi check on purpose: an image that cannot bring up Wi-Fi
    // is exactly the one that must roll back.
    {
      OtaLock lock;
      g_otaGuard.tick(millis());  // reboots into the previous slot when the window has passed
    }
    if (WiFi.status() != WL_CONNECTED) {
      // Scanning continues regardless; this is the whole point of the buffer.
      WiFi.reconnect();
      netSleep(g_backoffMs);
      growBackoff();
      continue;
    }

    const uint32_t now = millis();
    bool ok = true;
    bool otaDue = false;

    if (now - lastHeartbeat > kHeartbeatMs) {
      const bool heartbeat = sendHeartbeat();  // returns version counters; fetch deltas only when they move
      if (heartbeat) confirmHealthy();
      ok = heartbeat && ok;
      lastHeartbeat = now;
      otaDue = g_firmwareAvailable;
    }
    if (now - lastFlush > kFlushMs || g_buffer->depth() >= kMaxBatch) {
      ok = flushEvents() && ok;
      lastFlush = now;
    }
    // At most once per heartbeat, and after the flush so a reboot into a new
    // image leaves as little as possible buffered. A failed OTA check does
    // not feed the backoff: it must never delay punch uploads.
    if (otaDue) checkFirmware();  // reboots on success

    ok ? resetBackoff() : growBackoff();
    netSleep(ok ? 1000 : g_backoffMs);
  }
}

}  // namespace

void setup() {
#ifdef PRESENCE_BENCH_SERIAL_OTA
  // Room for a whole 4 KB chunk, so the loader never overruns the UART.
  Serial.setRxBufferSize(kOtaChunk + 256);
#endif
  Serial.begin(115200);
  pinMode(kBuzzerPin, OUTPUT);
  pinMode(kLedGreenPin, OUTPUT);
  pinMode(kLedRedPin, OUTPUT);

  // Which build, from which slot: after an OTA the label flips between app0
  // and app1, and after a rejected one it must not have.
  const esp_partition_t* running = esp_ota_get_running_partition();
  Serial.printf("presence terminal %s, running from %s\n", kFirmwareVersion, running ? running->label : "?");

  g_state = State::SelfTest;
  LittleFS.begin(true);
  g_nvs.begin("presence", false);
  g_seq = g_nvs.getULong64("seq", 0);

  // OTA state before anything can fail: a new image must start its confirm
  // window even if the sensor or the buffer then faults the terminal.
  g_otaMutex = xSemaphoreCreateMutex();
  bool pendingVerify = false;
  esp_ota_img_states_t imgState;
  if (running != nullptr && esp_ota_get_state_partition(running, &imgState) == ESP_OK) {
    pendingVerify = imgState == ESP_OTA_IMG_PENDING_VERIFY;
  }
  switch (g_otaGuard.begin(kFirmwareVersion, pendingVerify, millis())) {
    case presence::OtaBootKind::AwaitingConfirm:
      Serial.printf("OTA: new image pending; rolls back unless the gateway answers within %u s\n",
                    static_cast<unsigned>(g_otaGuard.confirmTimeoutMs() / 1000));
      if (!g_otaGuard.confirmDeadlineArmed()) {
        // The network task's tick() still enforces the window, but a hung
        // task would then leave the image unconfirmed until a power cycle.
        Serial.println("OTA: WARNING: could not arm the confirm timer; relying on the network task");
      }
      break;
    case presence::OtaBootKind::RolledBack:
      Serial.println("OTA: the last update did not stay booted; rolled back, and that image will not be retried");
      break;
    case presence::OtaBootKind::Normal:
      break;
  }
  Serial.printf("OTA: version floor %s\n", presence::formatOtaVersion(g_otaGuard.floor()).c_str());

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

  // Loud on purpose: a terminal that leaves the desk like this can only ever
  // be updated by someone physically plugging into it.
  if (presence::isSentinelKey(presence::kOtaReleasePublicKey)) {
    Serial.println("WARNING: no OTA release key compiled in; over-the-air updates are disabled");
  } else if (presence::isUnusableKey(presence::kOtaReleasePublicKey)) {
    // A small-order key accepts a forged signature on any image, so it is
    // refused like the sentinel. Reaching this means a bad key was pasted.
    Serial.println("WARNING: the OTA release key is a small-order point; over-the-air updates are disabled");
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

void loop() {
#ifdef PRESENCE_BENCH_SERIAL_OTA
  benchSerialOta();
  vTaskDelay(pdMS_TO_TICKS(50));
#else
  vTaskDelay(pdMS_TO_TICKS(1000));
#endif
}
