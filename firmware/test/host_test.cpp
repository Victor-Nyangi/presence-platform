// Host-side tests for the parts of the firmware that must agree with the
// gateway or survive power loss. Runs with plain g++, no ESP32 toolchain:
//
//     make firmware-test
//
// What is NOT covered here: anything touching the sensor, Wi-Fi, or real
// flash. Those need hardware.

#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "../src/canonical.h"
#include "../src/events_json.h"
#include "../src/ring_buffer.h"

using namespace presence;

static int failures = 0;

static void check(bool cond, const char* name, const std::string& detail = "") {
  if (cond) {
    printf("  PASS  %s\n", name);
  } else {
    printf("  FAIL  %s %s\n", name, detail.c_str());
    failures++;
  }
}

// ---------------------------------------------------------------------
// In-memory storage so buffer logic is testable without LittleFS.
// ---------------------------------------------------------------------
class MemStorage : public Storage {
 public:
  explicit MemStorage(size_t bytes) : buf_(bytes, 0) {}

  bool readAt(size_t offset, uint8_t* dst, size_t len) override {
    if (offset + len > buf_.size()) return false;
    memcpy(dst, buf_.data() + offset, len);
    return true;
  }
  bool writeAt(size_t offset, const uint8_t* src, size_t len) override {
    if (offset + len > buf_.size()) return false;
    if (failNextWrite_) {
      failNextWrite_ = false;
      return false;
    }
    memcpy(buf_.data() + offset, src, len);
    return true;
  }
  size_t capacityBytes() const override { return buf_.size(); }
  bool saveCursors(uint64_t head, uint64_t tail) override {
    head_ = head;
    tail_ = tail;
    return true;
  }
  bool loadCursors(uint64_t* head, uint64_t* tail) override {
    *head = head_;
    *tail = tail_;
    return true;
  }

  // Simulate a power cut partway through a record write.
  void corruptRecord(size_t index) {
    buf_[index * sizeof(PunchRecord) + 4] ^= 0xFF;
  }
  void failNextWrite() { failNextWrite_ = true; }
  // Plant a cursor pair that the API itself could never produce.
  void setCursors(uint64_t head, uint64_t tail) { head_ = head; tail_ = tail; }

 private:
  std::vector<uint8_t> buf_;
  uint64_t head_ = 0, tail_ = 0;
  bool failNextWrite_ = false;
};

// ---------------------------------------------------------------------
// FileStorage -- the same shape as the on-device LittleFsStorage, but on
// stdio.
//
// LittleFS itself needs hardware, so what this pins down is the part that
// does not: that records and cursors genuinely survive the process going
// away, with the cursors in a separate store from the data exactly as NVS
// is separate from the ring file on the device. That separation is the
// reason a torn data write cannot orphan the cursors, so it is worth
// testing against something that really is two files.
//
// These are characterisation tests over RingBuffer rather than tests that
// drove new code -- they are the closest thing to the "unplug it mid-day"
// milestone that runs without a board.
// ---------------------------------------------------------------------
class FileStorage : public Storage {
 public:
  FileStorage(const std::string& dataPath, const std::string& cursorPath, size_t bytes)
      : dataPath_(dataPath), cursorPath_(cursorPath), bytes_(bytes) {
    f_ = fopen(dataPath_.c_str(), "r+b");
    if (f_ == nullptr) {
      // First boot: create the file at full size rather than growing it as
      // punches arrive. On LittleFS a write past the high-water mark can
      // fail for want of space, and it would do so during an outage -- the
      // one moment the buffer is the only copy of the data. Preallocating
      // moves that failure to startup, where it is visible.
      f_ = fopen(dataPath_.c_str(), "w+b");
      if (f_ == nullptr) return;
      const std::vector<uint8_t> zeros(bytes_, 0);
      fwrite(zeros.data(), 1, zeros.size(), f_);
      fflush(f_);
    }
  }
  ~FileStorage() override {
    if (f_ != nullptr) fclose(f_);
  }

  bool ok() const { return f_ != nullptr; }

  bool readAt(size_t offset, uint8_t* dst, size_t len) override {
    if (f_ == nullptr || offset + len > bytes_) return false;
    if (fseek(f_, static_cast<long>(offset), SEEK_SET) != 0) return false;
    return fread(dst, 1, len, f_) == len;
  }
  bool writeAt(size_t offset, const uint8_t* src, size_t len) override {
    if (f_ == nullptr || offset + len > bytes_) return false;
    if (fseek(f_, static_cast<long>(offset), SEEK_SET) != 0) return false;
    if (fwrite(src, 1, len, f_) != len) return false;
    return fflush(f_) == 0;
  }
  size_t capacityBytes() const override { return bytes_; }

  // One record holding both cursors, mirroring the single NVS blob the
  // device writes. Two separate entries could tear against each other.
  bool saveCursors(uint64_t head, uint64_t tail) override {
    FILE* c = fopen(cursorPath_.c_str(), "wb");
    if (c == nullptr) return false;
    const uint64_t pair[2] = {head, tail};
    const bool wrote = fwrite(pair, sizeof(pair), 1, c) == 1;
    fclose(c);
    return wrote;
  }
  bool loadCursors(uint64_t* head, uint64_t* tail) override {
    FILE* c = fopen(cursorPath_.c_str(), "rb");
    if (c == nullptr) return false;
    uint64_t pair[2] = {0, 0};
    const bool read = fread(pair, sizeof(pair), 1, c) == 1;
    fclose(c);
    if (!read) return false;
    *head = pair[0];
    *tail = pair[1];
    return true;
  }

 private:
  std::string dataPath_;
  std::string cursorPath_;
  size_t bytes_;
  FILE* f_ = nullptr;
};

static const char* kRingPath = ".build/fwtest_ring.bin";
static const char* kCursorPath = ".build/fwtest_cursors.bin";

static void clearRingFiles() {
  remove(kRingPath);
  remove(kCursorPath);
}

static PunchRecord makeRecord(uint64_t seq) {
  PunchRecord r{};
  r.seq = seq;
  r.capturedEpochMs = 1755500000000ull + seq;
  r.capturedUptimeMs = seq * 1000;
  r.slotNo = 42;
  r.matchScore = 150;
  r.credentialKind = 0;
  r.timeSource = 0;
  r.directionHint = 0;
  return r;
}

// ---------------------------------------------------------------------

static void testCanonicalString() {
  printf("canonical string\n");

  // Golden vector generated by the Go gateway (see gateway/internal/auth).
  // If this drifts, every device in the field starts returning 401.
  const std::string got = canonicalString(
      "post", "/v1/device/events", 1755500000000LL, "abc123",
      "b7e23ec29af22b0b4e41da31e868d57226121c84d0d1a5d8b1a9a5d0b0c58e1e");

  const std::string want =
      "v1\n"
      "POST\n"
      "/v1/device/events\n"
      "1755500000000\n"
      "abc123\n"
      "b7e23ec29af22b0b4e41da31e868d57226121c84d0d1a5d8b1a9a5d0b0c58e1e";

  check(got == want, "matches the gateway's format", "\n---got---\n" + got);
  check(canonicalString("get", "/x", 1, "n", "d").find("GET") == 3,
        "method is upper-cased");
}

static void testCrcDetectsCorruption() {
  printf("crc32\n");
  const uint8_t a[] = {1, 2, 3, 4, 5};
  uint8_t b[] = {1, 2, 3, 4, 6};
  check(crc32(a, 5) != crc32(b, 5), "differs on a single-bit change");
  check(crc32(a, 5) == crc32(a, 5), "is stable");
  // Known-answer test for CRC-32/IEEE of "123456789".
  const char* s = "123456789";
  check(crc32(reinterpret_cast<const uint8_t*>(s), 9) == 0xCBF43926u,
        "matches the standard check value");
}

static void testAppendAndPeek() {
  printf("buffer append/peek\n");
  MemStorage st(sizeof(PunchRecord) * 8);
  RingBuffer rb(&st);
  assert(rb.begin());

  check(rb.empty(), "starts empty");
  for (uint64_t i = 1; i <= 5; i++) assert(rb.append(makeRecord(i)));
  check(rb.depth() == 5, "depth tracks appends");

  PunchRecord out[10];
  const size_t n = rb.peek(out, 10);
  check(n == 5, "peek returns everything buffered");
  check(out[0].seq == 1 && out[4].seq == 5, "peek returns oldest first");
  check(rb.depth() == 5, "peek does not consume");
}

// The core offline guarantee: nothing is dropped until the SERVER says so.
static void testAckOnlyDropsAcknowledged() {
  printf("ack semantics\n");
  MemStorage st(sizeof(PunchRecord) * 16);
  RingBuffer rb(&st);
  assert(rb.begin());
  for (uint64_t i = 1; i <= 10; i++) assert(rb.append(makeRecord(i)));

  const size_t dropped = rb.ackThrough(4);
  check(dropped == 4, "drops exactly the acknowledged records");
  check(rb.depth() == 6, "keeps the unacknowledged remainder");

  PunchRecord out[16];
  const size_t n = rb.peek(out, 16);
  check(n == 6 && out[0].seq == 5, "resumes from the first unacknowledged seq");

  // A lost response means the device re-sends; the server dedupes.
  const size_t again = rb.ackThrough(4);
  check(again == 0, "re-acking an old seq is a no-op");
}

// A power cut mid-write leaves a torn record. It must be skipped, not fatal,
// and must not stall the drain — the same failure mode as a poison event on
// the server side.
static void testCorruptRecordIsSkipped() {
  printf("power-cut resilience\n");
  MemStorage st(sizeof(PunchRecord) * 8);
  RingBuffer rb(&st);
  assert(rb.begin());
  for (uint64_t i = 1; i <= 4; i++) assert(rb.append(makeRecord(i)));

  st.corruptRecord(1);  // seq 2

  PunchRecord out[8];
  const size_t n = rb.peek(out, 8);
  check(n == 3, "corrupt record is skipped, others survive");
  bool sawTwo = false;
  for (size_t i = 0; i < n; i++) {
    if (out[i].seq == 2) sawTwo = true;
  }
  check(!sawTwo, "the corrupt record is not returned");

  // And it must not block the tail forever.
  rb.ackThrough(4);
  check(rb.empty(), "drain completes past the corrupt record");
}

static void testFailedWriteIsReported() {
  printf("write failure\n");
  MemStorage st(sizeof(PunchRecord) * 4);
  RingBuffer rb(&st);
  assert(rb.begin());

  st.failNextWrite();
  const bool ok = rb.append(makeRecord(1));
  check(!ok, "append reports failure rather than silently succeeding");
  check(rb.depth() == 0, "a failed append does not advance the head");
  // This is why the firmware must beep only AFTER append() returns true:
  // otherwise it would confirm a punch that was never stored.
}

// A very long outage must not brick the reader. Oldest data is sacrificed.
static void testOverflowDropsOldest() {
  printf("overflow\n");
  MemStorage st(sizeof(PunchRecord) * 4);
  RingBuffer rb(&st);
  assert(rb.begin());
  for (uint64_t i = 1; i <= 6; i++) assert(rb.append(makeRecord(i)));

  check(rb.depth() == 4, "depth is capped at capacity");
  PunchRecord out[8];
  const size_t n = rb.peek(out, 8);
  check(n == 4 && out[0].seq == 3, "oldest records are dropped, newest kept");
}

static void testCursorsSurviveReboot() {
  printf("reboot\n");
  MemStorage st(sizeof(PunchRecord) * 8);
  {
    RingBuffer rb(&st);
    assert(rb.begin());
    for (uint64_t i = 1; i <= 3; i++) assert(rb.append(makeRecord(i)));
    rb.ackThrough(1);
  }
  RingBuffer rebooted(&st);
  assert(rebooted.begin());
  check(rebooted.depth() == 2, "head/tail restored from NVS after a restart");
  PunchRecord out[8];
  const size_t n = rebooted.peek(out, 8);
  check(n == 2 && out[0].seq == 2, "resumes at the right sequence");
}

// ---------------------------------------------------------------------
// Ring file sizing (ring_buffer.h)
//
// The device sizes its ring file from whatever the LittleFS partition
// actually has, rather than a magic number, so that enlarging the
// partition later grows the buffer with no code change. The arithmetic
// is pure and lives here because getting it wrong is silent: the buffer
// just ends up smaller than anyone thinks it is.
// ---------------------------------------------------------------------
static void testRingCapacitySizing() {
  printf("ring sizing\n");
  const size_t rec = sizeof(PunchRecord);

  // 10 records' worth of space plus a stray 17 bytes: the remainder is
  // unusable, because RingBuffer indexes by whole records.
  check(ringCapacityBytes(rec * 10 + 17, 0, 0, 0, 1) == rec * 10,
        "rounds down to a whole number of records");

  check(ringCapacityBytes(rec * 10, 0, 0, rec * 2, 1) == rec * 8,
        "holds back the reserve for filesystem metadata");

  // The second boot is the one that catches people out: usedBytes now
  // includes the ring file itself, so a naive free-space calculation
  // shrinks the buffer to nothing on every restart.
  check(ringCapacityBytes(rec * 10, rec * 10, rec * 10, 0, 1) == rec * 10,
        "reclaims the existing ring file instead of shrinking each boot");

  check(ringCapacityBytes(rec * 4, 0, 0, 0, 8) == 0,
        "refuses a partition too small to hold the minimum");

  check(ringCapacityBytes(rec * 4, rec * 9, 0, 0, 1) == 0,
        "returns zero rather than underflowing when used exceeds total");

  check(ringCapacityBytes(rec * 4, 0, 0, rec * 9, 1) == 0,
        "returns zero when the reserve exceeds what is available");
}

// A cursor pair with the tail past the head is not reachable through the
// API; it means the persisted cursors were corrupted. It must not survive
// begin(), because depth() is unsigned subtraction -- tail > head does not
// fault, it underflows to ~1.8e19 and leaves full() permanently true, so
// every subsequent punch silently evicts a good record.
static void testCorruptCursorsDoNotUnderflowDepth() {
  printf("corrupt cursors\n");
  MemStorage st(sizeof(PunchRecord) * 8);
  st.setCursors(2, 5);
  RingBuffer rb(&st);
  check(rb.begin(), "begin still succeeds");
  check(rb.depth() == 0, "an impossible cursor pair does not underflow depth");
  check(!rb.full(), "and does not leave the buffer permanently full");
}

// Likewise a head further ahead of the tail than the ring can hold: the
// records in between no longer exist, so claiming that depth would hand
// peek() a wrapped, misleading view of the file.
static void testCursorsBeyondCapacityAreClamped() {
  printf("cursors beyond capacity\n");
  MemStorage st(sizeof(PunchRecord) * 4);
  st.setCursors(100, 0);
  RingBuffer rb(&st);
  check(rb.begin(), "begin still succeeds");
  check(rb.depth() == 4, "depth is clamped to what the ring can actually hold");
}

// A buffer whose begin() failed has no slots, and append() indexes with
// "head % slots". Nothing should call it in that state -- scanTask is gated
// on State::Ready and a failed buffer faults the terminal -- but "nothing
// should" is not a guarantee, and the failure mode is a divide-by-zero
// reboot loop rather than a dropped punch.
static void testAppendOnUnstartedBufferFails() {
  printf("unstarted buffer\n");
  MemStorage st(0);
  RingBuffer rb(&st);
  check(!rb.begin(), "begin refuses a storage with no room for a record");
  check(!rb.append(makeRecord(1)),
        "append reports failure rather than dividing by zero");
}

static void testRecordsSurviveProcessRestart() {
  printf("restart persistence\n");
  clearRingFiles();
  const size_t bytes = sizeof(PunchRecord) * 8;
  {
    FileStorage st(kRingPath, kCursorPath, bytes);
    RingBuffer rb(&st);
    assert(rb.begin());
    for (uint64_t i = 1; i <= 5; i++) assert(rb.append(makeRecord(i)));
  }
  FileStorage reopened(kRingPath, kCursorPath, bytes);
  RingBuffer rb(&reopened);
  check(rb.begin(), "reopens an existing ring file");
  check(rb.depth() == 5, "every buffered punch survived the restart");
  PunchRecord out[8];
  const size_t n = rb.peek(out, 8);
  check(n == 5 && out[0].seq == 1 && out[4].seq == 5,
        "records come back in order with their sequence numbers intact");
}

static void testAckStateSurvivesRestart() {
  printf("restart ack state\n");
  clearRingFiles();
  const size_t bytes = sizeof(PunchRecord) * 8;
  {
    FileStorage st(kRingPath, kCursorPath, bytes);
    RingBuffer rb(&st);
    assert(rb.begin());
    for (uint64_t i = 1; i <= 5; i++) assert(rb.append(makeRecord(i)));
    rb.ackThrough(3);
  }
  FileStorage reopened(kRingPath, kCursorPath, bytes);
  RingBuffer rb(&reopened);
  assert(rb.begin());
  check(rb.depth() == 2, "acknowledged records stay dropped across a restart");
  PunchRecord out[8];
  const size_t n = rb.peek(out, 8);
  check(n == 2 && out[0].seq == 4,
        "the device does not resend what the server already stored");
}

static void testTornRecordInFileIsSkippedAfterRestart() {
  printf("restart torn record\n");
  clearRingFiles();
  const size_t bytes = sizeof(PunchRecord) * 8;
  {
    FileStorage st(kRingPath, kCursorPath, bytes);
    RingBuffer rb(&st);
    assert(rb.begin());
    for (uint64_t i = 1; i <= 4; i++) assert(rb.append(makeRecord(i)));
  }
  // Corrupt the third record in the file itself, the way a power cut
  // partway through a write would.
  {
    FILE* f = fopen(kRingPath, "r+b");
    assert(f != nullptr);
    assert(fseek(f, static_cast<long>(sizeof(PunchRecord) * 2 + 4), SEEK_SET) == 0);
    uint8_t b = 0;
    assert(fread(&b, 1, 1, f) == 1);
    b ^= 0xFF;
    assert(fseek(f, static_cast<long>(sizeof(PunchRecord) * 2 + 4), SEEK_SET) == 0);
    assert(fwrite(&b, 1, 1, f) == 1);
    fclose(f);
  }
  FileStorage reopened(kRingPath, kCursorPath, bytes);
  RingBuffer rb(&reopened);
  assert(rb.begin());
  PunchRecord out[8];
  const size_t n = rb.peek(out, 8);
  check(n == 3, "the torn record is skipped and the rest still upload");
  bool sawThree = false;
  for (size_t i = 0; i < n; i++) {
    if (out[i].seq == 3) sawThree = true;
  }
  check(!sawThree, "the torn record itself is never returned");
}

static void testRingFileIsPreallocatedToFullSize() {
  printf("preallocation\n");
  clearRingFiles();
  const size_t bytes = sizeof(PunchRecord) * 8;
  FileStorage st(kRingPath, kCursorPath, bytes);
  check(st.ok(), "the ring file is created on first boot");
  FILE* f = fopen(kRingPath, "rb");
  assert(f != nullptr);
  assert(fseek(f, 0, SEEK_END) == 0);
  const long size = ftell(f);
  fclose(f);
  check(size == static_cast<long>(bytes),
        "the file is full size before the first punch, so a write during an "
        "outage cannot fail for space");
  clearRingFiles();
}

// ---------------------------------------------------------------------
// Batch serialisation and response parsing (events_json.h)
//
// This is protocol-critical: a field name or enum spelling that disagrees
// with the gateway's model.go does not fail loudly, it stores the punch as
// malformed. So the wire shape is pinned here rather than trusted.
// ---------------------------------------------------------------------

static bool contains(const std::string& haystack, const std::string& needle) {
  return haystack.find(needle) != std::string::npos;
}

static PunchRecord fingerprintRecord(uint64_t seq, uint64_t epochMs, uint16_t slot) {
  PunchRecord r{};
  r.seq = seq;
  r.capturedEpochMs = epochMs;
  r.capturedUptimeMs = 120'000;
  r.slotNo = slot;
  r.matchScore = 180;
  r.credentialKind = 0;  // fingerprint
  r.timeSource = 0;      // rtc_synced
  r.directionHint = 1;   // in
  for (int i = 0; i < 16; i++) r.uuid[i] = static_cast<uint8_t>(i + 1);
  return r;
}

static void testRfc3339Formatting() {
  printf("rfc3339 formatting\n");
  check(formatRfc3339Utc(0) == "1970-01-01T00:00:00.000Z", "epoch");
  check(formatRfc3339Utc(1755500000000LL) == "2025-08-18T06:53:20.000Z", "a known instant");
  // 2024 is a leap year; 2100 is not, despite being divisible by 4. A
  // hand-rolled calendar that gets either wrong misdates every punch after it.
  check(formatRfc3339Utc(1709164800000LL) == "2024-02-29T00:00:00.000Z", "leap day");
  check(formatRfc3339Utc(1709251199000LL) == "2024-02-29T23:59:59.000Z", "last second of a leap day");
  check(formatRfc3339Utc(946684800000LL) == "2000-01-01T00:00:00.000Z", "leap century");
  check(formatRfc3339Utc(4102444800000LL) == "2100-01-01T00:00:00.000Z", "non-leap century");
  check(formatRfc3339Utc(1755500000123LL) == "2025-08-18T06:53:20.123Z", "milliseconds are preserved");
}

static void testUuidFormatting() {
  printf("uuid formatting\n");
  uint8_t raw[16];
  for (int i = 0; i < 16; i++) raw[i] = static_cast<uint8_t>(i + 1);
  check(formatUuid(raw) == "01020304-0506-0708-090a-0b0c0d0e0f10", "8-4-4-4-12 lowercase hex");
}

static void testBatchWireShape() {
  printf("events batch wire shape\n");
  const PunchRecord rec = fingerprintRecord(7, 1755500000000LL, 42);
  BatchMeta meta{"1d1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8", 300'000, 3};
  const std::string body = buildEventsJson(&rec, 1, meta);

  check(contains(body, "\"request_id\":\"1d1a2b3c-4d5e-6f70-8192-a3b4c5d6e7f8\""), "request_id");
  // device_uptime_ms is what lets the gateway rebuild wall time for a punch
  // taken with a dead RTC. Omitting it silently downgrades those events.
  check(contains(body, "\"device_uptime_ms\":300000"), "device_uptime_ms");
  check(contains(body, "\"buffer_depth\":3"), "buffer_depth");
  check(contains(body, "\"seq\":7"), "seq");
  check(contains(body, "\"event_uuid\":\"01020304-0506-0708-090a-0b0c0d0e0f10\""), "event_uuid");
  check(contains(body, "\"captured_at\":\"2025-08-18T06:53:20.000Z\""), "captured_at");
  check(contains(body, "\"captured_uptime_ms\":120000"), "captured_uptime_ms");
  check(contains(body, "\"time_source\":\"rtc_synced\""), "time_source");
  check(contains(body, "\"credential_kind\":\"fingerprint\""), "credential_kind");
  check(contains(body, "\"slot_no\":42"), "slot_no");
  check(contains(body, "\"match_score\":180"), "match_score");
  check(contains(body, "\"direction_hint\":\"in\""), "direction_hint");
  check(body.front() == '{' && body.back() == '}', "is a JSON object");
}

static void testEnumMappings() {
  printf("enum code to wire string\n");
  PunchRecord r = fingerprintRecord(1, 1755500000000LL, 5);

  r.timeSource = 1;
  check(contains(buildEventsJson(&r, 1, BatchMeta{"r", 1, 0}), "\"time_source\":\"rtc_unsynced\""), "rtc_unsynced");
  r.timeSource = 2;
  check(contains(buildEventsJson(&r, 1, BatchMeta{"r", 1, 0}), "\"time_source\":\"uptime_only\""), "uptime_only");

  r.timeSource = 0;
  r.directionHint = 0;
  check(contains(buildEventsJson(&r, 1, BatchMeta{"r", 1, 0}), "\"direction_hint\":\"unknown\""), "direction unknown");
  r.directionHint = 2;
  check(contains(buildEventsJson(&r, 1, BatchMeta{"r", 1, 0}), "\"direction_hint\":\"out\""), "direction out");

  const char* kinds[] = {"fingerprint", "rfid_card", "nfc_tag", "pin", "qr"};
  bool allOk = true;
  for (uint8_t k = 0; k < 5; k++) {
    r.credentialKind = k;
    const std::string want = std::string("\"credential_kind\":\"") + kinds[k] + "\"";
    if (!contains(buildEventsJson(&r, 1, BatchMeta{"r", 1, 0}), want)) allOk = false;
  }
  check(allOk, "all five credential kinds map to the schema's enum spellings");
}

static void testDeadRtcOmitsCapturedAt() {
  printf("dead RTC\n");
  // capturedEpochMs == 0 means the RTC was never set. Emitting
  // 1970-01-01 would record a 56-year clock skew; omitting the key lets Go
  // decode a zero time.Time, which store.insertEvent replaces with the
  // effective time it reconstructs from the uptime delta.
  PunchRecord r = fingerprintRecord(1, 0, 42);
  r.timeSource = 2;
  const std::string body = buildEventsJson(&r, 1, BatchMeta{"r", 500'000, 1});
  check(!contains(body, "captured_at"), "captured_at is omitted entirely");
  check(!contains(body, "1970"), "no epoch-zero timestamp leaks into the payload");
  check(contains(body, "\"captured_uptime_ms\":120000"), "uptime is still sent");
  check(contains(body, "\"device_uptime_ms\":500000"), "upload uptime is still sent");
}

static void testMultipleEvents() {
  printf("batching\n");
  PunchRecord recs[3];
  for (int i = 0; i < 3; i++) recs[i] = fingerprintRecord(static_cast<uint64_t>(i + 1), 1755500000000LL, 42);
  const std::string body = buildEventsJson(recs, 3, BatchMeta{"r", 1, 3});
  check(contains(body, "\"seq\":1") && contains(body, "\"seq\":2") && contains(body, "\"seq\":3"), "all three present");
  check(!contains(body, ",]") && !contains(body, "[,"), "no malformed array separators");
  size_t braces = 0;
  for (char c : body) {
    if (c == '{') braces++;
    if (c == '}') braces--;
  }
  check(braces == 0, "braces balance");
}

static void testZeroEventsIsStillValidJson() {
  printf("empty batch\n");
  const std::string body = buildEventsJson(nullptr, 0, BatchMeta{"r", 1, 0});
  check(contains(body, "\"events\":[]"), "empty array rather than null");
}

static void testAckParsing() {
  printf("ack_through parsing\n");
  const char* ok = "{\"ack_through\":42,\"accepted\":[41,42],\"duplicates\":[],\"rejected\":[],\"server_time_ms\":1755500000000}";
  check(parseAckThrough(ok) == 42, "reads the value");

  // A rejected event still advances the ack, because it is still stored.
  // Refusing to truncate here is what wedges a buffer behind a poison event.
  const char* rejected = "{\"ack_through\":9,\"accepted\":[],\"duplicates\":[],\"rejected\":[{\"seq\":9,\"reason\":\"unknown_slot\"}]}";
  check(parseAckThrough(rejected) == 9, "advances past a rejected event");

  check(parseAckThrough("{\"accepted\":[]}") == -1, "absent key reports -1, never 0");
  check(parseAckThrough("") == -1, "empty body reports -1");
  check(parseAckThrough("{\"ack_through\":0}") == 0, "an explicit zero is not confused with absence");

  // "ack_through" must not be matched inside some other key's name or value.
  check(parseAckThrough("{\"last_ack_through_seen\":5,\"ack_through\":8}") == 8, "matches the whole key only");
  check(parseAckThrough("{\"note\":\"ack_through\",\"ack_through\":3}") == 3, "ignores the name appearing as a value");
}

static void testServerTimeParsingForClockSkew() {
  printf("clock skew recovery\n");
  // A 401 carries the server's clock so a terminal with a dead RTC can
  // correct itself and retry rather than being locked out forever.
  const char* problem = "{\"title\":\"Unauthorized\",\"status\":401,\"code\":\"clock_skew\","
                        "\"detail\":\"timestamp outside accepted window\",\"server_time_ms\":1755500000000}";
  int64_t out = 0;
  check(parseJsonInt(problem, "server_time_ms", &out) && out == 1755500000000LL, "server_time_ms recovered from a 401");
  check(!parseJsonInt("{\"status\":401}", "server_time_ms", &out), "missing key reports failure");
}

int main() {
  printf("PunchRecord = %zu bytes\n\n", sizeof(PunchRecord));
  testCanonicalString();
  testCrcDetectsCorruption();
  testAppendAndPeek();
  testAckOnlyDropsAcknowledged();
  testCorruptRecordIsSkipped();
  testFailedWriteIsReported();
  testOverflowDropsOldest();
  testCursorsSurviveReboot();
  testRingCapacitySizing();
  testCorruptCursorsDoNotUnderflowDepth();
  testCursorsBeyondCapacityAreClamped();
  testAppendOnUnstartedBufferFails();
  testRecordsSurviveProcessRestart();
  testAckStateSurvivesRestart();
  testTornRecordInFileIsSkippedAfterRestart();
  testRingFileIsPreallocatedToFullSize();
  testRfc3339Formatting();
  testUuidFormatting();
  testBatchWireShape();
  testEnumMappings();
  testDeadRtcOmitsCapturedAt();
  testMultipleEvents();
  testZeroEventsIsStillValidJson();
  testAckParsing();
  testServerTimeParsingForClockSkew();

  printf("\n%s\n", failures == 0 ? "all firmware host tests passed" : "FAILURES");
  return failures == 0 ? 0 : 1;
}
