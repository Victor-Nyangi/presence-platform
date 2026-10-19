// Host-side tests for the parts of the firmware that must agree with the
// gateway or survive power loss. Runs with plain g++, no ESP32 toolchain:
//
//     make firmware-test
//
// What is NOT covered here: anything touching the sensor, Wi-Fi, or real
// flash. Those need hardware. The OTA gate (ota_verify.h) IS covered: the
// same Monocypher sources the terminal links are compiled in here. So is the
// OTA downgrade and rollback state machine (ota_guard.h), against a
// simulated two-slot flash, bootloader and file-backed NVS. And the Wi-Fi
// setup portal (wifi_provision.h): everything but the radio and sockets,
// including the WPA2 setup key, the fall-back to the portal and the
// provisioning token, plus the terminal's side of /provision (provision.h).

#include <cassert>
#include <cstdio>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "../src/canonical.h"
#include "../src/events_json.h"
#include "../src/ota_guard.h"
#include "../src/ota_pubkey.h"
#include "../src/ota_verify.h"
#include "../src/provision.h"
#include "../src/ring_buffer.h"
#include "../src/terminal_state.h"
#include "../src/wifi_provision.h"
#include "rfc8032_vectors.h"

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
// The device sizes its ring file from the LittleFS geometry rather than a
// magic number, so that enlarging the partition later grows the buffer with
// no code change. The arithmetic is pure and lives here because getting it
// wrong is silent until the first punch: a ring sized at all of the free
// space preallocates fine, then copy-on-write runs out of blocks on the
// first append and the terminal faults.
// ---------------------------------------------------------------------

static const size_t kBlock = 4096;     // esp_littlefs: one flash sector per block
static const size_t kFreshUsed = 2 * kBlock;  // superblock/root pair after format
static const size_t kSlack = 2;        // kRingSlackBlocks in littlefs_storage.h
static const size_t kMinRecs = 256;    // kRingMinRecords

// Exact littlefs CTZ geometry, as an independent model to test the formula's
// bound against: block n >= 1 carries ctz(n)+1 pointers, and the sum of
// ctz(1..m) is m - popcount(m).
static size_t ctzCapacity(size_t blocks, size_t blockSize) {
  if (blocks == 0) return 0;
  const size_t m = blocks - 1;
  const size_t pointers = 2 * m - static_cast<size_t>(__builtin_popcountll(m));
  return blocks * blockSize - 4 * pointers;
}

static size_t ctzBlocks(size_t bytes, size_t blockSize) {
  size_t n = bytes / blockSize;
  while (ctzCapacity(n, blockSize) < bytes) n++;
  return n;
}

struct Scheme {
  const char* name;
  size_t fsBytes;
  size_t expected;   // records the formula gives with kSlack
  size_t emulated;   // largest ring that survived rewriting offset 0 in
                     // firmware/tools/littlefs_ring_sim.py (docs/firmware-build.md)
};

static const Scheme kSchemes[] = {
    {"min_spiffs.csv, 128 KiB", 0x20000, 953, 1022},
    {"custom 2 x 0x180000, 896 KiB", 0xE0000, 7494, 7563},
    {"default.csv, 1408 KiB", 0x160000, 11855, 11923},
};

static void testRingCapacityPerPartitionScheme() {
  printf("ring sizing per partition scheme\n");
  const size_t rec = sizeof(PunchRecord);
  for (const Scheme& sc : kSchemes) {
    const size_t blocks = sc.fsBytes / kBlock;
    const size_t cap = ringCapacityBytes(kBlock, blocks, kFreshUsed, 0, kSlack, kMinRecs);
    const size_t records = cap / rec;
    const std::string d = std::string(sc.name) + ": " + std::to_string(records) + " records";
    printf("  %s -> %zu records (%zu B)\n", sc.name, records, cap);

    check(records == sc.expected, "matches the documented capacity", d);
    check(records <= sc.emulated, "at or below the largest ring that survives an in-place rewrite", d);
    // Not so conservative that it gives away a real chunk of the buffer.
    check(records * 100 >= sc.emulated * 90, "within 10% of the emulated limit", d);
    check(cap * 2 <= sc.fsBytes, "leaves at least the file's size free for copy-on-write", d);

    // With no slack the formula should land on the emulated boundary itself
    // (the CTZ bound costs at most a record), which is what says the
    // derivation models littlefs rather than merely being small enough.
    const size_t edge = ringCapacityBytes(kBlock, blocks, kFreshUsed, 0, 0, kMinRecs) / rec;
    check(edge <= sc.emulated && edge + 1 >= sc.emulated,
          "with zero slack it reproduces the emulated boundary",
          std::to_string(edge) + " vs " + std::to_string(sc.emulated));

    // After create(), the file this produced must pass the rewritable check
    // that begin() applies to an existing file -- or a terminal would throw
    // away its own ring on every boot.
    const size_t used = kFreshUsed + ctzBlocks(cap, kBlock) * kBlock;
    check(ringFileRewritable(kBlock, blocks, used, cap, kSlack),
          "the file it sizes is judged rewritable after a reboot", d);
  }
}

static void testRingCapacitySizing() {
  printf("ring sizing\n");
  const size_t rec = sizeof(PunchRecord);

  // 10 blocks, no metadata, no slack: 5 ring blocks of (4096 - 8) bytes is
  // 20,440 B, which is 340 whole records and 40 stray bytes.
  check(ringCapacityBytes(kBlock, 10, 0, 0, 0, 1) == 340 * rec,
        "rounds down to a whole number of records");

  check(ringCapacityBytes(kBlock, 10, 2 * kBlock, 0, 0, 1) == ringCapacityBytes(kBlock, 8, 0, 0, 0, 1),
        "blocks already in use come out of the budget before it is halved");
  check(ringCapacityBytes(kBlock, 10, 0, 0, 2, 1) == ringCapacityBytes(kBlock, 8, 0, 0, 0, 1),
        "slack blocks come out of the budget before it is halved");

  // The old formula: everything free bar 8 KiB, which under min_spiffs was
  // 1,911 records and faulted on the first append.
  const size_t old = ((0x20000 - kFreshUsed) - 8 * 1024) / rec;
  check(ringCapacityBytes(kBlock, 32, kFreshUsed, 0, kSlack, kMinRecs) / rec * 2 <= old,
        "is at most half of what all-of-free-space sizing gave");

  // The second boot is the one that catches people out: usedBytes now
  // includes the ring file itself, so ignoring it would halve the buffer
  // again on every restart. The file is reclaimed by whole blocks rounded
  // down, so a stale file can shrink the result but never inflate it.
  {
    const size_t fresh = ringCapacityBytes(kBlock, 32, kFreshUsed, 0, kSlack, 1);
    const size_t used = kFreshUsed + ctzBlocks(fresh, kBlock) * kBlock;
    const size_t again = ringCapacityBytes(kBlock, 32, used, fresh, kSlack, 1);
    const size_t naive = ringCapacityBytes(kBlock, 32, used, 0, kSlack, 1);
    check(again > naive, "reclaims an existing ring file's blocks");
    check(again <= fresh, "never sizes past what a fresh partition gives");
  }

  check(ringCapacityBytes(kBlock, 32, kFreshUsed, 0, kSlack, 2000) == 0,
        "refuses a partition too small to hold the minimum");
  check(ringCapacityBytes(kBlock, 4, 9 * kBlock, 0, 0, 1) == 0,
        "returns zero rather than underflowing when used exceeds total");
  check(ringCapacityBytes(kBlock, 4, 0, 0, 4, 1) == 0,
        "returns zero when the slack takes every block");
  check(ringCapacityBytes(kBlock, 4, 2 * kBlock, 0, 2, 1) == 0,
        "returns zero when metadata and slack leave nothing to halve");
  check(ringCapacityBytes(8, 1000, 0, 0, 0, 1) == 0 && ringCapacityBytes(kBlock, 0, 0, 0, 0, 1) == 0,
        "returns zero for a nonsensical geometry");

  // Sweep: for every partition size the formula's file, laid out the way
  // littlefs really lays it out, leaves a full copy's worth of blocks free.
  bool budgetHolds = true, rewritable = true;
  for (size_t blocks = 4; blocks <= 1024; blocks++) {
    const size_t cap = ringCapacityBytes(kBlock, blocks, kFreshUsed, 0, kSlack, 1);
    if (cap == 0) continue;
    const size_t fileBlocks = ctzBlocks(cap, kBlock);
    if (2 * fileBlocks + 2 + kSlack > blocks) budgetHolds = false;
    if (!ringFileRewritable(kBlock, blocks, kFreshUsed + fileBlocks * kBlock, cap, kSlack)) {
      rewritable = false;
    }
  }
  check(budgetHolds, "4..1024 blocks: file + copy + metadata + slack always fits");
  check(rewritable, "4..1024 blocks: every sized file passes ringFileRewritable");
}

static void testOversizedRingFileIsNotRewritable() {
  printf("ring file rewritable\n");
  // What the pre-fix build created under min_spiffs: 1,911 records in 29
  // blocks, leaving one block free of 32. Its first append ran out of space.
  const size_t old = 1911 * sizeof(PunchRecord);
  const size_t oldUsed = kFreshUsed + ctzBlocks(old, kBlock) * kBlock;
  check(!ringFileRewritable(kBlock, 32, oldUsed, old, kSlack),
        "a ring sized at all of the free space is not rewritable");
  check(!ringFileRewritable(kBlock, 32, oldUsed, old, 0),
        "not even with zero slack");

  // The emulated boundary: 1,022 records in 15 blocks, 15 free.
  const size_t edge = 1022 * sizeof(PunchRecord);
  const size_t edgeUsed = kFreshUsed + ctzBlocks(edge, kBlock) * kBlock;
  check(ringFileRewritable(kBlock, 32, edgeUsed, edge, 0), "the emulated boundary passes with zero slack");
  check(!ringFileRewritable(kBlock, 32, edgeUsed, edge, kSlack), "but not once slack is required");

  check(!ringFileRewritable(kBlock, 4, 9 * kBlock, 0, 0), "used past total is not rewritable");
  check(!ringFileRewritable(8, 32, 0, 0, 0), "a nonsensical block size is not rewritable");
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

// ---------------------------------------------------------------------
// OTA: Ed25519 over the image (ota_verify.h)
// ---------------------------------------------------------------------

// A signing key generated for this run only. Nothing here is persisted: the
// seed comes from the OS RNG, Monocypher wipes it, and the secret key dies
// with the process. The private release key never touches a test.
struct TestKey {
  uint8_t sk[64];
  uint8_t pk[32];
};

static TestKey makeTestKey() {
  std::random_device rd;
  uint8_t seed[32];
  for (auto& b : seed) b = static_cast<uint8_t>(rd());
  TestKey k;
  crypto_ed25519_key_pair(k.sk, k.pk, seed);
  return k;
}

static std::vector<uint8_t> makeImage(size_t n) {
  std::vector<uint8_t> img(n);
  std::mt19937 rng(static_cast<unsigned>(n) * 2654435761u);
  for (auto& b : img) b = static_cast<uint8_t>(rng());
  return img;
}

// What fwsign signs: the preamble for (version, size), then the image.
static std::vector<uint8_t> signedMessage(const std::string& version, const std::vector<uint8_t>& img) {
  const std::string pre = otaSignedPreamble(version, img.size());
  std::vector<uint8_t> msg(pre.begin(), pre.end());
  msg.insert(msg.end(), img.begin(), img.end());
  return msg;
}

static const char* kTestVersion = "0.2.0";

static std::vector<uint8_t> signImage(const TestKey& k, const std::vector<uint8_t>& img,
                                      const std::string& version = kTestVersion) {
  const std::vector<uint8_t> msg = signedMessage(version, img);
  std::vector<uint8_t> sig(64);
  crypto_ed25519_sign(sig.data(), k.sk, msg.data(), msg.size());
  return sig;
}

// Streams img through an ImageVerifier in `chunk`-sized pieces, as main.cpp
// does when it reads the OTA partition back.
static OtaVerdict verifyStreamed(const uint8_t* pk, const uint8_t* sig, size_t expected,
                                 const uint8_t* img, size_t len, size_t chunk,
                                 const std::string& version = kTestVersion) {
  ImageVerifier v(pk, sig, version, expected);
  for (size_t off = 0; off < len; off += chunk) {
    v.update(img + off, len - off < chunk ? len - off : chunk);
  }
  return v.finish();
}

// The raw primitive, streamed: what the RFC vectors run through.
static bool streamRaw(const uint8_t* pk, const uint8_t* sig, const uint8_t* msg, size_t len, size_t chunk) {
  Ed25519Stream v(pk, sig);
  for (size_t off = 0; off < len; off += chunk) {
    v.update(msg + off, len - off < chunk ? len - off : chunk);
  }
  return v.finish();
}

static OtaVerdict verifyImage(const TestKey& k, const std::vector<uint8_t>& sig,
                              const std::vector<uint8_t>& img, const std::string& version = kTestVersion) {
  return verifyStreamed(k.pk, sig.data(), img.size(), img.data(), img.size(), 4096, version);
}

static void testRfc8032Vectors() {
  printf("\nOTA: RFC 8032 section 7.1 Ed25519 vectors\n");
  for (const auto& v : rfc8032::kVectors) {
    const std::string name = v.name;
    check(ed25519Verify(v.sig, v.pk, v.msg, v.msgLen), (name + " verifies").c_str());

    uint8_t sig[64];
    memcpy(sig, v.sig, 64);
    sig[0] ^= 0x01;
    check(!ed25519Verify(sig, v.pk, v.msg, v.msgLen), (name + " with a flipped R bit is rejected").c_str());
    memcpy(sig, v.sig, 64);
    sig[40] ^= 0x01;
    check(!ed25519Verify(sig, v.pk, v.msg, v.msgLen), (name + " with a flipped S bit is rejected").c_str());

    if (v.msgLen > 0) {
      std::vector<uint8_t> msg(v.msg, v.msg + v.msgLen);
      msg[msg.size() / 2] ^= 0x80;
      check(!ed25519Verify(v.sig, v.pk, msg.data(), msg.size()),
            (name + " with a flipped message bit is rejected").c_str());
      // The streaming path must agree with the one-shot primitive whatever
      // the chunking -- byte at a time, an odd size, and one big chunk.
      bool allChunkings = true;
      for (size_t chunk : {static_cast<size_t>(1), static_cast<size_t>(7), static_cast<size_t>(4096)}) {
        allChunkings = allChunkings && streamRaw(v.pk, v.sig, v.msg, v.msgLen, chunk);
      }
      check(allChunkings, (name + " streams through Ed25519Stream at chunk 1/7/4096").c_str());
    }
  }
}

static void testValidImageSignatureAccepted() {
  printf("\nOTA: a signed image is accepted\n");
  const TestKey k = makeTestKey();
  // Deliberately not a multiple of the 4 KB read-back chunk.
  const std::vector<uint8_t> img = makeImage(150 * 1024 + 123);
  const std::vector<uint8_t> sig = signImage(k, img);
  check(verifyImage(k, sig, img) == OtaVerdict::Ok, "image signed with a test-time key verifies");
  check(verifyStreamed(k.pk, sig.data(), img.size(), img.data(), img.size(), 1000) == OtaVerdict::Ok,
        "and verifies at a different chunk size");
  const std::vector<uint8_t> msg = signedMessage(kTestVersion, img);
  check(ed25519Verify(sig.data(), k.pk, msg.data(), msg.size()),
        "streaming agrees with one-shot verification over preamble + image");

  const std::vector<uint8_t> one = makeImage(1);
  check(verifyImage(k, signImage(k, one), one) == OtaVerdict::Ok, "a 1-byte image verifies");
}

static void testTamperedImageRejected() {
  printf("\nOTA: a tampered image is rejected\n");
  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(64 * 1024);
  const std::vector<uint8_t> sig = signImage(k, img);

  const size_t positions[] = {0, 1, img.size() / 2, img.size() - 1};
  const char* names[] = {"first byte flipped is rejected", "second byte flipped is rejected",
                         "middle byte flipped is rejected", "last byte flipped is rejected"};
  for (size_t i = 0; i < 4; i++) {
    std::vector<uint8_t> bad = img;
    bad[positions[i]] ^= 0x01;
    check(verifyImage(k, sig, bad) == OtaVerdict::BadSignature, names[i]);
  }

  std::vector<uint8_t> extended = img;
  extended.push_back(0x00);
  check(verifyStreamed(k.pk, sig.data(), img.size(), extended.data(), extended.size(), 4096) ==
            OtaVerdict::SizeMismatch,
        "an appended byte is rejected against the manifest size");
  check(verifyImage(k, sig, extended) == OtaVerdict::BadSignature,
        "an appended byte is rejected even when the manifest size is changed to match");

  std::vector<uint8_t> shortened(img.begin(), img.end() - 1);
  check(verifyStreamed(k.pk, sig.data(), img.size(), shortened.data(), shortened.size(), 4096) ==
            OtaVerdict::SizeMismatch,
        "a truncated image is rejected against the manifest size");
  check(verifyImage(k, sig, shortened) == OtaVerdict::BadSignature,
        "a truncated image is rejected even when the manifest size is changed to match");
}

static void testWrongKeyRejected() {
  printf("\nOTA: a signature from another key is rejected\n");
  const TestKey release = makeTestKey();
  const TestKey other = makeTestKey();
  const std::vector<uint8_t> img = makeImage(32 * 1024);
  check(verifyImage(release, signImage(other, img), img) == OtaVerdict::BadSignature,
        "image signed by a different key is rejected");

  TestKey nearMiss = release;
  nearMiss.pk[31] ^= 0x01;
  check(verifyImage(nearMiss, signImage(release, img), img) == OtaVerdict::BadSignature,
        "a public key one bit off is rejected");
}

static void testMalformedSignatureRejected() {
  printf("\nOTA: truncated and malformed signatures are rejected\n");
  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(8 * 1024);
  const std::vector<uint8_t> sig = signImage(k, img);
  const std::string hex = toHex(sig.data(), sig.size());
  uint8_t decoded[64];

  check(decodeHexExact(hex, decoded, 64) && memcmp(decoded, sig.data(), 64) == 0,
        "the full 128-hex signature decodes");
  check(!decodeHexExact(hex.substr(0, 127), decoded, 64), "a signature one hex digit short does not decode");
  check(!decodeHexExact(hex.substr(0, 126), decoded, 64), "a signature one byte short does not decode");
  check(!decodeHexExact(hex.substr(0, 64), decoded, 64), "half a signature does not decode");
  check(!decodeHexExact(hex + "00", decoded, 64), "a signature with a trailing byte does not decode");
  check(!decodeHexExact(std::string(127, 'a') + "g", decoded, 64), "a non-hex digit does not decode");
  check(!decodeHexExact("", decoded, 64), "an empty signature does not decode");

  // A signature truncated and then zero-padded back to 64 bytes.
  std::vector<uint8_t> padded = sig;
  for (size_t i = 32; i < 64; i++) padded[i] = 0;
  check(verifyImage(k, padded, img) == OtaVerdict::BadSignature, "a zero-padded truncated signature is rejected");
  check(verifyImage(k, std::vector<uint8_t>(64, 0), img) == OtaVerdict::BadSignature,
        "an all-zero signature is rejected");

  // S + L verifies the same equation, so a lax verifier would accept it.
  // Monocypher refuses S >= L; this pins that we did not lose it.
  static const uint8_t kL[32] = {0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
                                 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};
  std::vector<uint8_t> malleable = sig;
  unsigned carry = 0;
  for (size_t i = 0; i < 32; i++) {
    const unsigned t = malleable[32 + i] + kL[i] + carry;
    malleable[32 + i] = static_cast<uint8_t>(t);
    carry = t >> 8;
  }
  check(verifyImage(k, malleable, img) == OtaVerdict::BadSignature,
        "a non-canonical S (S + L) is rejected");
}

static void testEmptyImageRejected() {
  printf("\nOTA: an empty image is rejected\n");
  // RFC 8032 TEST 1 is a VALID signature over the empty message. The
  // primitive accepts it; the OTA policy must not.
  const rfc8032::Vector& empty = rfc8032::kVectors[0];
  check(empty.msgLen == 0 && ed25519Verify(empty.sig, empty.pk, empty.msg, 0),
        "TEST 1 is a valid signature over an empty message");
  check(verifyStreamed(empty.pk, empty.sig, 0, empty.msg, 0, 4096) == OtaVerdict::EmptyImage,
        "the same signature as an OTA image is rejected as empty");
  // And a key that signs the preamble for size 0 still gets nothing.
  const TestKey k0 = makeTestKey();
  const std::vector<uint8_t> none;
  check(verifyImage(k0, signImage(k0, none), none) == OtaVerdict::EmptyImage,
        "a validly signed zero-byte image is rejected as empty");

  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(4096);
  const std::vector<uint8_t> sig = signImage(k, img);
  check(verifyStreamed(k.pk, sig.data(), img.size(), img.data(), 0, 4096) == OtaVerdict::EmptyImage,
        "a download that delivered no bytes is rejected");
}

static void testUnprovisionedKeyRefusesEverything() {
  printf("\nOTA: no release key compiled in\n");
  const uint8_t zero[32] = {0};
  check(isSentinelKey(zero) && isUnusableKey(zero), "the all-zero key is the sentinel, and unusable");
  const TestKey k = makeTestKey();
  check(!isSentinelKey(k.pk) && !isUnusableKey(k.pk), "a real key is neither");

  const std::vector<uint8_t> img = makeImage(4096);
  const std::vector<uint8_t> sig = signImage(k, img);
  check(verifyStreamed(zero, sig.data(), img.size(), img.data(), img.size(), 4096) == OtaVerdict::NoKey,
        "the sentinel refuses an image before any curve arithmetic");

  // The committed key must be either the sentinel or a real key; either way
  // it refuses an image signed by a key generated here.
  const OtaVerdict committed =
      verifyStreamed(kOtaReleasePublicKey, sig.data(), img.size(), img.data(), img.size(), 4096);
  check(committed == OtaVerdict::NoKey || committed == OtaVerdict::BadSignature,
        "the committed release key refuses a test-key image");
}

// Every encoding of a point of order 1, 2, 4 or 8: the 8 canonical ones and
// the 6 non-canonical ones (x = 0 with the sign bit set; y = p and y = p+1).
// Recomputed from the curve equation, not copied from ota_verify.h, so a
// typo in the blocklist fails here.
static const char* kSmallOrderKeys[] = {
    "0000000000000000000000000000000000000000000000000000000000000000",  // y=0, order 4
    "0000000000000000000000000000000000000000000000000000000000000080",  // y=0, other x, order 4
    "0100000000000000000000000000000000000000000000000000000000000000",  // identity
    "0100000000000000000000000000000000000000000000000000000000000080",  // identity, non-canonical sign
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",  // order 8
    "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",  // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",  // order 8
    "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",  // order 8
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  // y=p-1, order 2
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // order 2, non-canonical sign
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  // y=p (=0), non-canonical
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // y=p, non-canonical
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",  // y=p+1 (=1), non-canonical
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",  // y=p+1, non-canonical
};

// Monocypher's check is cofactored, so under a small-order key the signature
// R = identity, S = 0 verifies on any message. The gate must refuse every
// such key before the arithmetic runs.
static void testSmallOrderKeysAreRefused() {
  printf("\nOTA: small-order keys are unusable\n");
  uint8_t forged[64] = {0};
  forged[0] = 0x01;  // R = the identity (y = 1), S = 0
  const std::vector<uint8_t> img = makeImage(4096);
  const std::vector<uint8_t> msg = signedMessage(kTestVersion, img);

  size_t refused = 0, primitiveForged = 0, streamRefused = 0, imageRefused = 0;
  for (const char* hex : kSmallOrderKeys) {
    uint8_t pk[32];
    if (!decodeHexExact(hex, pk, 32)) continue;
    if (isUnusableKey(pk) && isSmallOrderKey(pk)) refused++;
    if (ed25519Verify(forged, pk, msg.data(), msg.size())) primitiveForged++;
    if (!streamRaw(pk, forged, msg.data(), msg.size(), 4096)) streamRefused++;
    if (verifyStreamed(pk, forged, img.size(), img.data(), img.size(), 4096) == OtaVerdict::NoKey) imageRefused++;
  }
  const size_t n = sizeof(kSmallOrderKeys) / sizeof(kSmallOrderKeys[0]);
  check(n == 14 && refused == n, "all 14 small-order encodings are unusable keys");
  check(primitiveForged == n,
        "the raw primitive accepts the (R=identity, S=0) forgery under each (why the gate exists)");
  check(streamRefused == n, "Ed25519Stream refuses the forgery under each");
  check(imageRefused == n, "ImageVerifier refuses the forgery under each, as NoKey");

  // Near misses and real keys are not caught by the blocklist.
  uint8_t near[32];
  decodeHexExact(kSmallOrderKeys[4], near, 32);
  near[0] ^= 0x01;
  bool realOk = !isUnusableKey(near);
  for (int i = 0; i < 200; i++) realOk = realOk && !isUnusableKey(makeTestKey().pk);
  check(realOk, "a key one bit off an order-8 point, and 200 real keys, are usable");
}

// The key every build trusts. Today it is the sentinel; the moment someone
// pastes a key, this fails unless it is a real one.
static void testCompiledInKeyIsNotSmallOrder() {
  printf("\nOTA: the compiled-in key\n");
  check(isSentinelKey(kOtaReleasePublicKey) || !isSmallOrderKey(kOtaReleasePublicKey),
        "kOtaReleasePublicKey is the sentinel or not a small-order point");
  uint8_t forged[64] = {0};
  forged[0] = 0x01;
  const std::vector<uint8_t> img = makeImage(1024);
  check(verifyStreamed(kOtaReleasePublicKey, forged, img.size(), img.data(), img.size(), 4096) != OtaVerdict::Ok,
        "and the (R=identity, S=0) forgery does not verify against it");
}

static void testVerifierIsSingleUse() {
  printf("\nOTA: a verdict cannot be reused\n");
  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(1024);
  const std::vector<uint8_t> sig = signImage(k, img);
  ImageVerifier v(k.pk, sig.data(), kTestVersion, img.size());
  v.update(img.data(), img.size());
  check(v.finish() == OtaVerdict::Ok, "first finish() is ok");
  check(v.finish() == OtaVerdict::BadSignature, "a second finish() is not");
}

// The golden vector pinning the signing tool to the firmware, the way the
// HMAC golden vector pins the gateway to the device. The same values are in
// gateway/internal/fwsign/fwsign_test.go. They were produced once with a key
// generated in memory and never written anywhere; only the public half
// exists. The message is otaSignedPreamble("1.2.3", 4099) followed by the
// image. If the tool ever signs something else (the bare image, a hash, a
// prehash variant, a different preamble), one side of this fails.
static std::vector<uint8_t> goldenImage() {
  std::vector<uint8_t> img(4099);
  for (size_t i = 0; i < img.size(); i++) img[i] = static_cast<uint8_t>((i * 167 + 13) ^ (i >> 8));
  return img;
}
static const char* kGoldenVersion = "1.2.3";
static const char* kGoldenPublicKey = "084dbbdd1f539f42a53792f892b2b6fd3d876c5ff6689420bb7d402ae51a28d9";
static const char* kGoldenSignature =
    "0a44e507c61010f4416b476813bb337b4cbcdd9f7845067a8c90a1401bf3bb1a"
    "11bfa94df02146f193932a021f506229479b024911a4930b590e9acebfcd2f0e";

static void testSigningToolGoldenVector() {
  printf("\nOTA: signing tool golden vector\n");
  uint8_t pk[32], sig[64];
  check(decodeHexExact(kGoldenPublicKey, pk, 32) && decodeHexExact(kGoldenSignature, sig, 64),
        "golden key and signature decode");
  const std::vector<uint8_t> img = goldenImage();
  check(verifyStreamed(pk, sig, img.size(), img.data(), img.size(), 4096, kGoldenVersion) == OtaVerdict::Ok,
        "an image signed by Go crypto/ed25519 verifies on the firmware path");
  std::vector<uint8_t> bad = img;
  bad[4098] ^= 0x01;
  check(verifyStreamed(pk, sig, bad.size(), bad.data(), bad.size(), 4096, kGoldenVersion) ==
            OtaVerdict::BadSignature,
        "and the same image with its last byte flipped does not");
  check(verifyStreamed(pk, sig, img.size(), img.data(), img.size(), 4096, "1.2.4") == OtaVerdict::BadSignature,
        "and the same image under another version does not");
}

static void testManifestParsing() {
  printf("\nOTA: manifest parsing\n");
  const std::string sha(64, 'a');
  const std::string sig = std::string(kGoldenSignature);
  auto manifest = [&](const std::string& shaV, const std::string& sigV, const std::string& size) {
    return std::string("{\"available\":true,\"version\":\"0.2.0\",\"url\":\"https:\\/\\/fw.example.com/p.bin?a=1&b=2\",") +
           "\"size\":" + size + ",\"sha256\":\"" + shaV + "\",\"signature\":\"" + sigV + "\"}";
  };

  OtaManifest m;
  check(parseOtaManifest(manifest(sha, sig, "4099").c_str(), &m) && m.available && m.size == 4099 &&
            m.version == "0.2.0" && m.url == "https://fw.example.com/p.bin?a=1&b=2" && m.sha256[0] == 0xaa &&
            m.signature[0] == 0x0a && m.signature[63] == 0x0e,
        "a complete manifest parses");

  OtaManifest none;
  check(parseOtaManifest("{\"available\": false}", &none) && !none.available,
        "available:false parses as no update");
  check(!parseOtaManifest("{}", &m), "a manifest without available is refused");
  check(!parseOtaManifest(manifest(sha, sig.substr(0, 126), "4099").c_str(), &m),
        "a truncated signature is refused");
  check(!parseOtaManifest(manifest(sha, sig + "00", "4099").c_str(), &m), "an over-long signature is refused");
  check(!parseOtaManifest(manifest(sha.substr(0, 63), sig, "4099").c_str(), &m), "a short sha256 is refused");
  check(!parseOtaManifest(manifest(sha, sig, "0").c_str(), &m), "size 0 is refused");
  check(!parseOtaManifest(manifest(sha, sig, "-5").c_str(), &m), "a negative size is refused");
  check(!parseOtaManifest(manifest(sha, sig, "\"4099\"").c_str(), &m), "a quoted size is refused");

  const std::string noSig = "{\"available\":true,\"version\":\"0.2.0\",\"url\":\"https://x/p.bin\",\"size\":10,"
                            "\"sha256\":\"" + sha + "\"}";
  check(!parseOtaManifest(noSig.c_str(), &m), "a manifest without a signature is refused");

  const std::string ftp = "{\"available\":true,\"version\":\"0.2.0\",\"url\":\"ftp://x/p.bin\",\"size\":10,"
                          "\"sha256\":\"" + sha + "\",\"signature\":\"" + sig + "\"}";
  check(!parseOtaManifest(ftp.c_str(), &m), "a non-http(s) URL is refused");

  const std::string unicode = "{\"available\":true,\"version\":\"0.2.0\",\"url\":\"https://x/p?a=1\\u0026b=2\","
                              "\"size\":10,\"sha256\":\"" + sha + "\",\"signature\":\"" + sig + "\"}";
  check(!parseOtaManifest(unicode.c_str(), &m), "a \\u escape is refused rather than guessed at");

  std::string out;
  check(parseJsonString("{\"note\":\"signature\",\"signature\":\"ab\"}", "signature", &out, 8) && out == "ab",
        "a key name appearing as a value is skipped");
  check(!parseJsonString("{\"v\":\"abcdefghi\"}", "v", &out, 8), "a string over maxLen is refused");
  check(!parseJsonString("{\"v\":\"abc", "v", &out, 8), "an unterminated string is refused");
  bool b = true;
  check(parseJsonBool("{\"firmware_available\": false}", "firmware_available", &b) && !b,
        "firmware_available:false parses");
  check(!parseJsonBool("{\"firmware_available\": 1}", "firmware_available", &b), "a non-boolean is refused");
}

// ---------------------------------------------------------------------
// OTA versions and downgrade protection
// ---------------------------------------------------------------------

// The same table as gateway/internal/fwversion/fwversion_test.go. If the two
// grammars drift, the gateway can offer an image the terminal cannot
// compare, or call a build newer that the terminal calls older.
static void testVersionGrammar() {
  printf("\nOTA: version grammar (shared with the gateway)\n");
  struct Case {
    const char* in;
    size_t len;  // explicit, so an embedded NUL can be tested
    bool ok;
    uint64_t code;
  };
  const Case cases[] = {
      {"0.0.0", 5, true, 0},
      {"0.1.0", 5, true, 1ull << 16},
      {"1.2.3", 5, true, (1ull << 32) | (2ull << 16) | 3},
      {"65535.65535.65535", 17, true, (65535ull << 32) | (65535ull << 16) | 65535},
      {"10.0.1", 6, true, (10ull << 32) | 1},
      {"", 0, false, 0},
      {"1", 1, false, 0},
      {"1.2", 3, false, 0},
      {"1.2.3.4", 7, false, 0},
      {"01.2.3", 6, false, 0},
      {"1.02.3", 6, false, 0},
      {"1.2.03", 6, false, 0},
      {"65536.0.0", 9, false, 0},
      {"1.2.3-dev", 9, false, 0},
      {"0.0.0-dev", 9, false, 0},
      {"v1.2.3", 6, false, 0},
      {"+1.2.3", 6, false, 0},
      {"-1.2.3", 6, false, 0},
      {"1..3", 4, false, 0},
      {"1.2.", 4, false, 0},
      {".1.2", 4, false, 0},
      {" 1.2.3", 6, false, 0},
      {"1.2.3 ", 6, false, 0},
      {"123456.0.0", 10, false, 0},
      {"1.2.3\0", 6, false, 0},
  };
  bool all = true;
  for (const Case& c : cases) {
    uint64_t code = 0;
    const bool ok = parseOtaVersion(std::string(c.in, c.len), &code);
    if (ok != c.ok || (ok && code != c.code) || (ok && formatOtaVersion(code) != std::string(c.in, c.len))) {
      printf("        mismatch on \"%s\"\n", c.in);
      all = false;
    }
  }
  check(all, "all 25 grammar cases agree with the gateway's table");

  static_assert(otaVersionCodeLiteral("0.1.0") == (1ull << 16), "constexpr parse");
  static_assert(otaVersionCodeLiteral("0.0.0-dev") == kInvalidOtaVersion, "a dev suffix does not compile");
  check(otaVersionCodeLiteral("0.2.0") > otaVersionCodeLiteral("0.1.65535") &&
            otaVersionCodeLiteral("0.10.0") > otaVersionCodeLiteral("0.9.0") &&
            otaVersionCodeLiteral("1.0.0") > otaVersionCodeLiteral("0.65535.65535"),
        "codes order the way versions do, not the way strings do");
}

static void testPreambleBytes() {
  printf("\nOTA: signed preamble\n");
  check(otaSignedPreamble("0.2.0", 770992) == "presence-ota-image/v1\nversion=0.2.0\nsize=770992\n",
        "preamble is byte-identical to fwsign.Preamble");
}

// The version is part of the signed message. A validly signed OLD image
// cannot be presented as a newer one, and a signature over the bare image
// (the scheme before versions were signed) is worthless.
static void testVersionIsBoundIntoTheSignature() {
  printf("\nOTA: the version is signed\n");
  const TestKey k = makeTestKey();
  const std::vector<uint8_t> old = makeImage(20 * 1024);
  const std::vector<uint8_t> sig = signImage(k, old, "0.1.0");
  check(verifyImage(k, sig, old, "0.1.0") == OtaVerdict::Ok, "an image verifies under the version it was signed as");
  check(verifyImage(k, sig, old, "0.9.0") == OtaVerdict::BadSignature,
        "the same image and signature claimed as a newer version is rejected");
  check(verifyImage(k, sig, old, "0.0.9") == OtaVerdict::BadSignature,
        "and claimed as an older version");

  std::vector<uint8_t> bare(64);
  crypto_ed25519_sign(bare.data(), k.sk, old.data(), old.size());
  check(verifyImage(k, bare, old, "0.1.0") == OtaVerdict::BadSignature,
        "a signature over the bare image does not verify");
  check(verifyImage(k, signImage(k, old, "0.1.0-dev"), old, "0.1.0-dev") == OtaVerdict::BadVersion,
        "an unparseable version is refused even when it was signed");
}

static void testManifestUrlForms() {
  printf("\nOTA: manifest URL forms and versions\n");
  const std::string sha(64, 'b');
  const std::string sig(128, 'c');
  auto manifest = [&](const std::string& version, const std::string& url) {
    return "{\"available\":true,\"version\":\"" + version + "\",\"url\":\"" + url +
           "\",\"size\":4099,\"sha256\":\"" + sha + "\",\"signature\":\"" + sig + "\"}";
  };
  OtaManifest m;
  check(parseOtaManifest(manifest("0.2.0", "/v1/device/firmware/images/" + sha).c_str(), &m) &&
            otaUrlIsGatewayPath(m.url),
        "a gateway-relative image path parses");
  check(!parseOtaManifest(manifest("0.2.0", "/v1/device/firmware/images/" + sha + "?x=1").c_str(), &m),
        "a gateway path with a query is refused (the path is signed verbatim)");
  check(!parseOtaManifest(manifest("0.2.0", "/v1/device/firmware/images/../../time").c_str(), &m),
        "a gateway path with .. is refused");
  check(!parseOtaManifest(manifest("0.2.0", "/etc/passwd").c_str(), &m), "any other relative path is refused");
  check(!parseOtaManifest(manifest("0.2.0", "").c_str(), &m), "an empty URL is refused");
  check(!parseOtaManifest(manifest("0.2.0-rc1", "https://x/p.bin").c_str(), &m),
        "a pre-release version is refused");
  check(!parseOtaManifest(manifest("0.2", "https://x/p.bin").c_str(), &m), "a two-part version is refused");
}

// ---- the guard against a simulated terminal --------------------------

// NVS stand-in: the OTA blob in a file, replaced atomically (write a temp
// file, rename) the way an NVS entry is. A "reboot" builds a new store and a
// new OtaGuard over the same file, so nothing survives in RAM.
class FileOtaStore : public OtaStateStore {
 public:
  explicit FileOtaStore(std::string path) : path_(std::move(path)) {}
  bool load(OtaPersistedState* out) override {
    FILE* f = fopen(path_.c_str(), "rb");
    if (!f) return false;
    const size_t n = fread(out, 1, sizeof(*out), f);
    const bool extra = fgetc(f) != EOF;
    fclose(f);
    return n == sizeof(*out) && !extra;
  }
  bool save(const OtaPersistedState& s) override {
    if (failWrites) return false;
    const std::string tmp = path_ + ".tmp";
    FILE* f = fopen(tmp.c_str(), "wb");
    if (!f) return false;
    const bool ok = fwrite(&s, 1, sizeof(s), f) == sizeof(s);
    fclose(f);
    return ok && rename(tmp.c_str(), path_.c_str()) == 0;
  }
  bool failWrites = false;

 private:
  std::string path_;
};

// Two app slots, otadata and the IDF 4.4 bootloader's rollback rules
// (bootloader_utility_get_selected_boot_partition with
// CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE), reduced to what the guard sees.
enum class ImgState { None, New, PendingVerify, Valid, Invalid, Aborted };

class SimDevice : public OtaBootControl {
 public:
  struct Slot {
    std::string version;  // what the image in this slot was built as
    uint8_t sha[kSha256Bytes] = {};
    bool hasEntry = false;  // otadata names this slot
    uint32_t seq = 0;
    ImgState state = ImgState::None;
  };
  Slot slot[2];
  int running = 0;
  int markValidCalls = 0;
  int rollbackCalls = 0;
  int restartCalls = 0;
  bool failMarkValid = false;
  // The esp_timer one-shot: armed for how long, and whether it is live.
  bool timerArmed = false;
  uint32_t timerMs = 0;
  bool failArm = false;
  std::function<void()> onMarkValid;

  // `pio run -t upload`: app0 written, otadata reset. NVS is untouched.
  void usbFlash(const std::string& version, uint8_t shaByte) {
    slot[0] = Slot{};
    slot[0].version = version;
    memset(slot[0].sha, shaByte, kSha256Bytes);
    slot[1].hasEntry = false;
    slot[1].state = ImgState::None;
    running = 0;
  }
  int idle() const { return 1 - running; }

  // esp_ota_end + esp_ota_set_boot_partition on the idle slot.
  void setBootIdle(const std::string& version, const uint8_t sha[kSha256Bytes]) {
    Slot& s = slot[idle()];
    s.version = version;
    memcpy(s.sha, sha, kSha256Bytes);
    s.hasEntry = true;
    s.seq = std::max(slot[0].seq, slot[1].seq) + 1;
    s.state = ImgState::New;
  }

  static bool selectable(const Slot& s) {
    return s.hasEntry && s.state != ImgState::Invalid && s.state != ImgState::Aborted;
  }

  // Power on.
  void bootloader() {
    for (Slot& s : slot) {
      if (s.hasEntry && s.state == ImgState::PendingVerify) s.state = ImgState::Aborted;
    }
    int pick = -1;
    for (int i = 0; i < 2; i++) {
      if (selectable(slot[i]) && (pick < 0 || slot[i].seq > slot[pick].seq)) pick = i;
    }
    if (pick < 0) pick = 0;  // no factory partition: "trying OTA 0"
    running = pick;
    if (slot[pick].hasEntry && slot[pick].state == ImgState::New) slot[pick].state = ImgState::PendingVerify;
  }
  bool runningPending() const { return slot[running].hasEntry && slot[running].state == ImgState::PendingVerify; }
  const std::string& runningVersion() const { return slot[running].version; }

  bool markValid() override {
    markValidCalls++;
    if (onMarkValid) onMarkValid();
    if (failMarkValid) return false;
    if (slot[running].hasEntry) slot[running].state = ImgState::Valid;
    return true;
  }
  // esp_ota_mark_app_invalid_rollback_and_reboot(), then esp_restart() if
  // that refused. The API refuses when otadata has no entry for the other
  // slot (the first update after a USB flash), and the image stays
  // PENDING_VERIFY, which the bootloader turns into the same fallback.
  void rollback() override {
    rollbackCalls++;
    if (selectable(slot[idle()])) slot[running].state = ImgState::Invalid;
  }
  bool armConfirmDeadline(uint32_t ms) override {
    if (failArm) return false;
    timerArmed = true;
    timerMs = ms;
    return true;
  }
  void cancelConfirmDeadline() override { timerArmed = false; }
  // esp_restart(): nothing is written; the next bootloader() pass decides.
  void restartUnconfirmed() override { restartCalls++; }
};

static const char* kOtaNvsPath = "/tmp/presence_fwtest_ota_state.bin";

struct SimTerminal {
  SimDevice dev;
  std::unique_ptr<FileOtaStore> store;
  std::unique_ptr<OtaGuard> guard;
  uint32_t confirmMs = 600000;

  SimTerminal() { remove(kOtaNvsPath); }
  ~SimTerminal() {
    remove(kOtaNvsPath);
    remove((std::string(kOtaNvsPath) + ".tmp").c_str());
  }

  OtaBootKind boot(uint32_t nowMs = 0) {
    dev.timerArmed = false;  // timers do not survive a reset
    dev.bootloader();
    store.reset(new FileOtaStore(kOtaNvsPath));
    guard.reset(new OtaGuard(store.get(), &dev, confirmMs));
    return guard->begin(dev.runningVersion(), dev.runningPending(), nowMs);
  }

  // applyOta's order once the image has verified: downgrade check, pending
  // record, then the commit.
  OtaCandidate install(const std::string& version, uint8_t shaByte) {
    uint8_t sha[kSha256Bytes];
    memset(sha, shaByte, sizeof(sha));
    const OtaCandidate c = guard->check(version, sha);
    if (c != OtaCandidate::Accept) return c;
    if (!guard->notePending(version, sha)) return OtaCandidate::Unconfirmed;
    dev.setBootIdle(version, sha);
    return c;
  }
  OtaCandidate check(const std::string& version, uint8_t shaByte) const {
    uint8_t sha[kSha256Bytes];
    memset(sha, shaByte, sizeof(sha));
    return guard->check(version, sha);
  }
  uint64_t storedFloor() {
    OtaPersistedState st;
    FileOtaStore f(kOtaNvsPath);
    return f.load(&st) ? st.floor : 0;
  }
};

static uint64_t V(const char* s) {
  uint64_t v = 0;
  parseOtaVersion(s, &v);
  return v;
}

// A replayed older signed image, an equal one, a newer one -- through both
// layers, the signature and the guard.
static void testDowngradeIsRefused() {
  printf("\nOTA guard: downgrade protection\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  check(t.boot() == OtaBootKind::Normal, "a USB-flashed image boots as normal, not pending");

  const TestKey k = makeTestKey();
  const std::vector<uint8_t> oldImg = makeImage(16 * 1024);
  const std::vector<uint8_t> oldSig = signImage(k, oldImg, "0.1.0");
  check(verifyImage(k, oldSig, oldImg, "0.1.0") == OtaVerdict::Ok, "the replayed 0.1.0 image is validly signed");
  check(t.check("0.1.0", 0x10) == OtaCandidate::NotNewer, "and is still refused: older than the running 0.2.0");
  check(verifyImage(k, oldSig, oldImg, "0.3.0") == OtaVerdict::BadSignature,
        "relabelling it 0.3.0 to get past the guard breaks the signature");
  check(t.check("0.2.0", 0x20) == OtaCandidate::NotNewer, "an equal version is refused");
  check(t.check("0.2.0", 0x21) == OtaCandidate::NotNewer, "an equal version with different bytes is refused");
  check(t.check("0.2.1", 0x21) == OtaCandidate::Accept, "a newer version is accepted");
  check(t.check("1.0.0", 0x30) == OtaCandidate::Accept, "a newer major version is accepted");
  check(t.check("0.2.1-rc1", 0x21) == OtaCandidate::BadVersion, "a candidate version that does not parse is refused");

  SimTerminal dev;
  dev.dev.usbFlash("0.0.0-dev", 0x01);  // what the old default would have been
  dev.boot();
  check(dev.check("9.9.9", 0x99) == OtaCandidate::RunningUnversioned,
        "a build without a comparable version refuses every update");
}

static void testConfirmedUpdateRaisesTheFloor() {
  printf("\nOTA guard: a healthy update is confirmed\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  check(t.install("0.3.0", 0x30) == OtaCandidate::Accept, "0.3.0 installs");
  check(t.boot(1000) == OtaBootKind::AwaitingConfirm && t.dev.runningVersion() == "0.3.0",
        "it boots pending verification");
  check(t.check("0.4.0", 0x40) == OtaCandidate::Unconfirmed,
        "no further update is taken while this one is unconfirmed");

  uint64_t floorWhenMarked = 1;
  t.dev.onMarkValid = [&] { floorWhenMarked = t.storedFloor(); };
  t.guard->tick(1000 + t.confirmMs - 1);
  check(t.dev.rollbackCalls == 0, "no rollback inside the window");
  t.guard->onHealthy();
  check(t.dev.markValidCalls == 1 && !t.guard->awaitingConfirm() && t.dev.slot[t.dev.running].state == ImgState::Valid,
        "the first heartbeat marks it valid");
  check(floorWhenMarked == 0, "it is marked valid BEFORE the floor is raised");
  check(t.storedFloor() == V("0.3.0") && t.guard->floor() == V("0.3.0"), "the floor is raised to 0.3.0 in NVS");
  t.guard->onHealthy();
  check(t.dev.markValidCalls == 1, "later heartbeats do not repeat it");
  t.guard->tick(1000 + 10 * t.confirmMs);
  check(t.dev.rollbackCalls == 0, "a confirmed image is never rolled back by the timer");
  check(t.check("0.4.0", 0x40) == OtaCandidate::Accept, "and updates are taken again");
}

static void testFloorSurvivesReboot() {
  printf("\nOTA guard: the floor survives a reboot\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.boot();
  t.guard->onHealthy();

  check(t.boot() == OtaBootKind::Normal && t.guard->floor() == V("0.3.0"),
        "after a reboot the floor is read back from NVS");
  check(t.check("0.3.0", 0x30) == OtaCandidate::NotNewer, "the running version is still refused");

  // The terminal ends up on an older build with its NVS intact: a USB
  // reflash, or the bootloader falling back past a corrupt slot.
  t.dev.usbFlash("0.1.0", 0x10);
  t.boot();
  check(t.guard->floor() == V("0.3.0"), "an older build on the same NVS keeps the floor");
  check(t.check("0.2.0", 0x20) == OtaCandidate::BelowFloor, "0.2.0 is newer than the running 0.1.0 but below the floor");
  check(t.check("0.3.0", 0x30) == OtaCandidate::BelowFloor, "the floor version itself is refused");
  check(t.check("0.3.1", 0x31) == OtaCandidate::Accept, "above the floor is accepted");
  t.guard->onHealthy();
  check(t.storedFloor() == V("0.3.0"), "a healthy older build never lowers the floor");
}

static void rollbackScenario(bool firstUpdateAfterUsbFlash) {
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  if (!firstUpdateAfterUsbFlash) {
    // One confirmed update first, so otadata names both slots.
    t.install("0.2.5", 0x25);
    t.boot();
    t.guard->onHealthy();
    t.boot();
  }
  const std::string before = t.dev.runningVersion();
  const int beforeSlot = t.dev.running;
  const uint64_t floorBefore = t.guard->floor();
  const int markedBefore = t.dev.markValidCalls;

  t.install("0.3.0", 0x30);
  t.boot(5000);
  check(t.guard->awaitingConfirm(), "the new image boots pending");
  t.guard->tick(5000 + t.confirmMs - 1);
  check(t.dev.rollbackCalls == 0, "nothing happens one millisecond before the deadline");
  t.guard->tick(5000 + t.confirmMs);
  check(t.dev.rollbackCalls == 1, "no heartbeat inside the window: rollback");
  check(t.dev.markValidCalls == markedBefore, "it was never marked valid");
  t.guard->tick(5000 + 2 * t.confirmMs);
  check(t.dev.rollbackCalls == 1, "rollback is requested once");

  check(t.boot() == OtaBootKind::RolledBack, "the next boot reports the rollback");
  check(t.dev.runningVersion() == before && t.dev.running == beforeSlot, "and runs the previous image from its slot");
  check(t.guard->floor() == floorBefore, "the floor did not move");
  check(t.check("0.3.0", 0x30) == OtaCandidate::KnownBad, "the rolled-back image is never retried");
  check(t.check("0.3.0", 0x31) == OtaCandidate::Accept, "a different 0.3.0 build may be");
  check(t.check("0.3.1", 0x31) == OtaCandidate::Accept, "and so may a newer release");
  t.guard->onHealthy();
  check(t.storedFloor() == floorBefore || t.storedFloor() == V(before.c_str()),
        "the old image's heartbeat raises the floor no higher than itself");
}

static void testUnconfirmedImageRollsBack() {
  printf("\nOTA guard: no heartbeat in time rolls back (first update after a USB flash)\n");
  rollbackScenario(true);
  printf("\nOTA guard: no heartbeat in time rolls back (both slots in otadata)\n");
  rollbackScenario(false);
}

static void testPowerCutInTheConfirmWindow() {
  printf("\nOTA guard: a reboot before confirmation rolls back\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.boot();
  check(t.guard->awaitingConfirm(), "pending after the update");
  // Power cut, crash or watchdog: no tick, no rollback() call.
  check(t.boot() == OtaBootKind::RolledBack && t.dev.runningVersion() == "0.2.0",
        "the bootloader aborts the unconfirmed image and boots the old one");
  check(t.check("0.3.0", 0x30) == OtaCandidate::KnownBad, "and the guard learns it from NVS alone");
}

static void testMarkValidFailureIsRetried() {
  printf("\nOTA guard: a failed mark-valid is retried\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.boot();
  t.dev.failMarkValid = true;
  t.guard->onHealthy();
  check(t.guard->awaitingConfirm() && t.storedFloor() == 0, "still pending, floor untouched");
  t.dev.failMarkValid = false;
  t.guard->onHealthy();
  check(!t.guard->awaitingConfirm() && t.storedFloor() == V("0.3.0"), "the next heartbeat confirms it");
}

static void testPendingRecordFailureBlocksTheCommit() {
  printf("\nOTA guard: no pending record, no commit\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.store->failWrites = true;
  uint8_t sha[kSha256Bytes];
  memset(sha, 0x30, sizeof(sha));
  check(t.guard->check("0.3.0", sha) == OtaCandidate::Accept && !t.guard->notePending("0.3.0", sha),
        "notePending reports an NVS failure, so applyOta never sets the boot partition");
}

static void testCorruptOtaStateStartsClean() {
  printf("\nOTA guard: unreadable NVS state\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  FILE* f = fopen(kOtaNvsPath, "wb");
  fputs("garbage", f);
  fclose(f);
  check(t.boot() == OtaBootKind::Normal && t.guard->floor() == 0, "a short blob is ignored");
  OtaPersistedState st;
  memset(&st, 0xAB, sizeof(st));
  FileOtaStore(kOtaNvsPath).save(st);
  check(t.boot() == OtaBootKind::Normal && t.guard->floor() == 0, "a blob with the wrong magic is ignored");
  check(t.check("0.2.1", 0x21) == OtaCandidate::Accept, "and updates still work");
}

static void testConfirmWindowAcrossMillisWrap() {
  printf("\nOTA guard: the confirm window across a millis() wrap\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  const uint32_t start = 0xFFFFFFFFu - 1000;
  t.boot(start);
  t.guard->tick(start + 2000);  // wrapped, 2 s elapsed
  check(t.dev.rollbackCalls == 0, "a wrap does not look like an expired window");
  t.guard->tick(start + t.confirmMs);
  check(t.dev.rollbackCalls == 1, "the window still expires on time");
}

// A broken image's likeliest failure is a network task that hangs, and then
// tick() never runs. The esp_timer deadline does not need that task.
static void testHungNetworkTaskStillRollsBack() {
  printf("\nOTA guard: the confirm deadline does not depend on the network task\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  check(t.boot() == OtaBootKind::Normal && !t.dev.timerArmed, "no timer for an image that is not pending");
  t.install("0.3.0", 0x30);
  t.boot();
  check(t.dev.timerArmed && t.dev.timerMs == t.confirmMs && t.guard->confirmDeadlineArmed(),
        "a pending image arms a one-shot timer for the whole window");

  // The network task is hung: no tick(), no heartbeat. Only the timer fires.
  t.guard->onConfirmDeadline();
  check(t.dev.restartCalls == 1 && t.dev.rollbackCalls == 0, "the timer restarts the chip, nothing more");
  check(t.boot() == OtaBootKind::RolledBack && t.dev.runningVersion() == "0.2.0",
        "the restart lands on the previous image");
  check(t.check("0.3.0", 0x30) == OtaCandidate::KnownBad, "and the image is blacklisted from NVS on that boot");
}

static void testConfirmCancelsTheDeadline() {
  printf("\nOTA guard: confirming cancels the deadline\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.boot();
  t.guard->onHealthy();
  check(!t.dev.timerArmed && !t.guard->confirmDeadlineArmed(), "the first heartbeat cancels the timer");
  t.guard->onConfirmDeadline();  // a callback already queued when it was cancelled
  check(t.dev.restartCalls == 0, "a late callback after the confirm does nothing");

  SimTerminal f;
  f.dev.usbFlash("0.2.0", 0x20);
  f.boot();
  f.install("0.3.0", 0x30);
  f.dev.failMarkValid = true;
  f.boot();
  f.guard->onHealthy();
  check(f.dev.timerArmed, "a failed mark-valid leaves the deadline armed");
}

// The race the timer cannot avoid: it fires after markValid() but before the
// guard has raised the floor. A restart then must keep the new image.
static void testDeadlineRestartAfterMarkValidKeepsTheImage() {
  printf("\nOTA guard: a deadline restart just after mark-valid\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.boot();
  t.dev.markValid();  // the guard's markValid ran; nothing else did
  check(t.boot() == OtaBootKind::Normal && t.dev.runningVersion() == "0.3.0",
        "the restart boots the now-valid image, not the previous one");
  t.guard->onHealthy();
  check(t.storedFloor() == V("0.3.0") && t.check("0.3.0", 0x31) == OtaCandidate::NotNewer,
        "the next heartbeat raises the floor and clears the pending record");
  OtaPersistedState st;
  FileOtaStore(kOtaNvsPath).load(&st);
  check(!st.hasPending && !st.hasBad, "and nothing was blacklisted");
}

static void testUnarmableTimerFallsBackToTick() {
  printf("\nOTA guard: no timer, the network task still enforces the window\n");
  SimTerminal t;
  t.dev.usbFlash("0.2.0", 0x20);
  t.boot();
  t.install("0.3.0", 0x30);
  t.dev.failArm = true;
  t.boot();
  check(!t.guard->confirmDeadlineArmed(), "the guard knows the timer is not armed (main.cpp warns)");
  t.guard->tick(t.confirmMs);
  check(t.dev.rollbackCalls == 1, "tick() still rolls back at the deadline");
}

// ---------------------------------------------------------------------
// Wi-Fi provisioning (wifi_provision.h): the SoftAP captive portal's
// validation, NVS record, form and HTTP parsing, routing, state machine and
// the BOOT-button reset trigger. The radio, DNS and sockets (wifi_softap.h)
// need a board; docs/wifi-provisioning.md has the bench checklist.
// ---------------------------------------------------------------------
class MemWifiStore : public WifiCredentialStore {
 public:
  bool load(WifiCredentials* out) override {
    if (!has) return false;
    *out = rec;
    if (corruptOnLoad) out->password[0] ^= 0x01;
    return true;
  }
  bool save(const WifiCredentials& c) override {
    saves++;
    if (failSave) return false;
    rec = c;
    has = true;
    return true;
  }
  bool erase() override {
    has = false;
    memset(&rec, 0, sizeof(rec));
    return true;
  }
  WifiCredentials rec{};
  bool has = false;
  bool failSave = false;
  bool corruptOnLoad = false;  // a read-back that does not match the write
  int saves = 0;
};

static std::string statusLine(const std::string& resp) { return resp.substr(0, resp.find("\r\n")); }

static std::string bodyOf(const std::string& resp) {
  const size_t p = resp.find("\r\n\r\n");
  return p == std::string::npos ? std::string() : resp.substr(p + 4);
}

static std::string post(const std::string& path, const std::string& body) {
  return "POST " + path + " HTTP/1.1\r\nHost: 192.168.4.1\r\nContent-Type: application/x-www-form-urlencoded\r\n" +
         "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

static std::string get(const std::string& path, const char* method = "GET") {
  return std::string(method) + " " + path + " HTTP/1.1\r\nHost: connectivitycheck.gstatic.com\r\n\r\n";
}

// Feed a raw request through the parser and the portal, as serveOne does.
static std::string ask(WifiPortal& p, const std::string& raw, uint32_t nowMs = 1000) {
  HttpRequest req;
  const HttpParse parsed = parseHttpRequest(raw.data(), raw.size(), &req);
  return p.handle(parsed, req, nowMs);
}

static const char* kOrigin = "http://192.168.4.1/";

static void testWifiFieldValidation() {
  printf("\nWi-Fi provisioning: SSID and password validation\n");
  check(validateSsid("", 0) == WifiFieldError::SsidMissing, "an empty SSID is refused");
  const std::string s32(32, 'a'), s33(33, 'a');
  check(validateSsid(s32.data(), 32) == WifiFieldError::Ok, "a 32-byte SSID is accepted");
  check(validateSsid(s33.data(), 33) == WifiFieldError::SsidTooLong, "a 33-byte SSID is refused");
  check(validateSsid("ab\ncd", 5) == WifiFieldError::SsidBadByte, "an SSID with a control character is refused");
  check(validateSsid("a\x7f", 2) == WifiFieldError::SsidBadByte, "an SSID with DEL is refused");
  const std::string utf8 = "Caf\xc3\xa9 Wi-Fi";
  check(validateSsid(utf8.data(), utf8.size()) == WifiFieldError::Ok, "a UTF-8 SSID is accepted");
  check(validateSsid(" spaced ", 8) == WifiFieldError::Ok, "leading and trailing spaces are kept, not refused");

  check(validatePassword("", 0) == WifiFieldError::Ok, "an empty password means an open network");
  check(validatePassword("1234567", 7) == WifiFieldError::PasswordTooShort, "a 7-character password is refused");
  check(validatePassword("12345678", 8) == WifiFieldError::Ok, "an 8-character passphrase is accepted");
  const std::string p63(63, 'x'), p65(65, 'x'), hex64(64, 'a'), notHex64(64, 'g');
  check(validatePassword(p63.data(), 63) == WifiFieldError::Ok, "a 63-character passphrase is accepted");
  check(validatePassword(hex64.data(), 64) == WifiFieldError::Ok, "a 64-digit hex key is accepted");
  check(validatePassword(notHex64.data(), 64) == WifiFieldError::PasswordBadHex,
        "64 characters that are not hex are refused");
  check(validatePassword(p65.data(), 65) == WifiFieldError::PasswordTooLong, "a 65-character password is refused");
  check(validatePassword("passw\xc3\xb6rd", 10) == WifiFieldError::PasswordBadByte,
        "a non-ASCII passphrase is refused (WPA2 passphrases are printable ASCII)");
  check(validatePassword("pass\tword", 9) == WifiFieldError::PasswordBadByte, "a tab in a passphrase is refused");
  check(validatePassword("pa ss wo rd", 11) == WifiFieldError::Ok, "spaces in a passphrase are allowed");
}

static void testWifiCredentialRecord() {
  printf("\nWi-Fi provisioning: the NVS record\n");
  check(sizeof(WifiCredentials) == 102, "WifiCredentials is 102 bytes (a layout change needs a new magic)");
  WifiCredentials c;
  check(makeCredentials("school", "correct horse", &c) == WifiFieldError::Ok, "valid input makes a record");
  check(c.magic == kWifiCredentialsMagic && strcmp(c.ssid, "school") == 0 && strcmp(c.password, "correct horse") == 0,
        "the record carries the magic, SSID and password");
  check(credentialsUsable(c), "a record this build wrote is usable");

  WifiCredentials bad;
  memset(&bad, 0x55, sizeof(bad));
  check(makeCredentials("school", "short", &bad) == WifiFieldError::PasswordTooShort, "invalid input is refused");
  bool allZero = true;
  for (size_t i = 0; i < sizeof(bad); i++) allZero = allZero && reinterpret_cast<uint8_t*>(&bad)[i] == 0;
  check(allZero, "a refused record is left all zero");

  WifiCredentials m = c;
  m.magic ^= 1;
  check(!credentialsUsable(m), "a record with the wrong magic is not usable");
  m = c;
  memset(m.ssid, 'a', sizeof(m.ssid));
  check(!credentialsUsable(m), "an SSID with no terminator is not usable");
  m = c;
  memset(m.password, 'a', sizeof(m.password));
  check(!credentialsUsable(m), "a password with no terminator is not usable");
  m = c;
  m.ssid[0] = '\0';
  check(!credentialsUsable(m), "an empty stored SSID is not usable");
  m = c;
  strcpy(m.password, "abc");
  check(!credentialsUsable(m), "a stored password that would not validate is not usable");
}

static void testWifiBootDecision() {
  printf("\nWi-Fi provisioning: the boot decision\n");
  MemWifiStore store;
  WifiCredentials out;
  check(!loadUsableCredentials(&store, &out), "nothing stored: open the portal");
  check(!loadUsableCredentials(nullptr, &out), "no store at all: open the portal");

  makeCredentials("ward-3", "nightshift", &store.rec);
  store.has = true;
  check(loadUsableCredentials(&store, &out) && strcmp(out.ssid, "ward-3") == 0, "stored credentials: station mode");

  store.rec.ssid[0] = '\0';  // torn or foreign entry
  memset(&out, 0x55, sizeof(out));
  check(!loadUsableCredentials(&store, &out), "an unusable stored entry opens the portal");
  check(out.magic == 0 && out.password[0] == '\0', "and the rejected entry is zeroed, not left in memory");

  store.erase();
  check(!loadUsableCredentials(&store, &out), "after the BOOT-button erase: the portal opens again");
}

static void testWifiFormParsing() {
  printf("\nWi-Fi provisioning: form parsing\n");
  WifiForm f;
  const std::string b1 = "ssid=My+School&password=p%40ss%26w%3Drd%25";
  check(parseWifiForm(b1.data(), b1.size(), &f) == FormError::Ok, "a form with escapes parses");
  check(f.ssid == "My School", "'+' decodes to a space");
  check(f.password == "p@ss&w=rd%", "%XX escapes decode, including & = and %");

  WifiForm g;
  const std::string b2 = "password=12345678&ssid=net&submit=Save";
  check(parseWifiForm(b2.data(), b2.size(), &g) == FormError::Ok && g.ssid == "net" && g.password == "12345678",
        "field order does not matter and unknown fields are ignored");

  WifiForm open;
  const std::string b3 = "ssid=cafe&password=";
  check(parseWifiForm(b3.data(), b3.size(), &open) == FormError::Ok && open.password.empty(),
        "an empty password field is an open network");

  struct Case {
    const char* body;
    FormError want;
    const char* name;
  } cases[] = {
      {"ssid=net", FormError::Missing, "no password field at all is refused, not taken as an open network"},
      {"password=12345678", FormError::Missing, "no ssid field is refused"},
      {"", FormError::Missing, "an empty body is refused"},
      {"ssid=a&ssid=b&password=12345678", FormError::Duplicate, "a duplicated ssid is refused"},
      {"ssid=a&password=12345678&password=x", FormError::Duplicate, "a duplicated password is refused"},
      {"ssid=a%zz&password=12345678", FormError::Malformed, "a bad escape is refused"},
      {"ssid=a&password=1234567%", FormError::Malformed, "a truncated escape at the end is refused"},
      {"ssid=a&password=1234567%4", FormError::Malformed, "a one-digit escape is refused"},
  };
  for (const Case& c : cases) {
    WifiForm h;
    const FormError got = parseWifiForm(c.body, strlen(c.body), &h);
    check(got == c.want, c.name);
    check(got == FormError::Ok || (h.ssid.empty() && h.password.empty()), "  and nothing is kept from it");
  }

  WifiForm big;
  const std::string longBody = "ssid=a&password=" + std::string(200, 'x');
  check(parseWifiForm(longBody.data(), longBody.size(), &big) == FormError::FieldTooLong,
        "an over-long value is refused without growing past the cap");

  WifiForm amp;
  const std::string b4 = "&&ssid=a&&password=12345678&";
  check(parseWifiForm(b4.data(), b4.size(), &amp) == FormError::Ok, "empty pairs between '&' are skipped");
}

static void testHttpRequestParsing() {
  printf("\nWi-Fi provisioning: HTTP request parsing\n");
  HttpRequest r;
  std::string raw = get("/generate_204?x=1");
  check(parseHttpRequest(raw.data(), raw.size(), &r) == HttpParse::Ok && r.method == "GET" &&
            r.path == "/generate_204" && r.body.empty(),
        "a GET parses and the query string is dropped from the path");

  raw = post("/save", "ssid=a&password=12345678");
  check(parseHttpRequest(raw.data(), raw.size(), &r) == HttpParse::Ok && r.method == "POST" && r.path == "/save" &&
            r.body == "ssid=a&password=12345678",
        "a POST parses with exactly Content-Length bytes of body");

  check(parseHttpRequest(raw.data(), raw.size() - 3, &r) == HttpParse::Incomplete,
        "a body still arriving is Incomplete, not truncated");
  check(parseHttpRequest(raw.data(), 20, &r) == HttpParse::Incomplete, "a head still arriving is Incomplete");

  const std::string lower = "POST /save HTTP/1.1\r\ncontent-LENGTH: 3\r\n\r\nabcEXTRA";
  check(parseHttpRequest(lower.data(), lower.size(), &r) == HttpParse::Ok && r.body == "abc",
        "header names are case-insensitive, and bytes past Content-Length are ignored");

  struct Case {
    std::string raw;
    HttpParse want;
    const char* name;
  } cases[] = {
      {"POST /save HTTP/1.1\r\nContent-Length: 513\r\n\r\n", HttpParse::TooLarge, "a body over 512 bytes is refused"},
      {"POST /save HTTP/1.1\r\nContent-Length: 99999999999999999999\r\n\r\n", HttpParse::TooLarge,
       "a huge Content-Length does not overflow"},
      {"GET / HTTP/1.1\r\nX: " + std::string(1100, 'a') + "\r\n\r\n", HttpParse::TooLarge, "a head over 1 KB is refused"},
      {"GET / HTTP/1.1\r\nX: " + std::string(1100, 'a'), HttpParse::TooLarge,
       "an over-long head is refused before its end arrives"},
      {"POST /save HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", HttpParse::Bad, "chunked bodies are refused"},
      {"POST /save HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\na", HttpParse::Bad,
       "two Content-Length headers are refused"},
      {"POST /save HTTP/1.1\r\nContent-Length: 1x\r\n\r\na", HttpParse::Bad, "a non-numeric Content-Length is refused"},
      {"get / HTTP/1.1\r\n\r\n", HttpParse::Bad, "a lower-case method is refused"},
      {"GET http://evil/ HTTP/1.1\r\n\r\n", HttpParse::Bad, "an absolute-form target is refused"},
      {"GET / HTTP/2.0\r\n\r\n", HttpParse::Bad, "a non-HTTP/1 version is refused"},
      {"GET /\r\n\r\n", HttpParse::Bad, "a request line without a version is refused"},
      {"GET / HTTP/1.1\r\nNoColon\r\n\r\n", HttpParse::Bad, "a header without a colon is refused"},
      {"GET /a\x01 HTTP/1.1\r\n\r\n", HttpParse::Bad, "a control byte in the target is refused"},
  };
  for (const Case& c : cases) {
    HttpRequest q;
    check(parseHttpRequest(c.raw.data(), c.raw.size(), &q) == c.want, c.name);
  }
}

static void testPortalServesNothingElse() {
  printf("\nWi-Fi provisioning: the portal's whole surface\n");
  check(routePortal("GET", "/") == PortalRoute::Form, "GET / is the form");
  check(routePortal("HEAD", "/") == PortalRoute::Form, "HEAD / is the form");
  check(routePortal("POST", "/save") == PortalRoute::Save, "POST /save saves");
  check(routePortal("POST", "/") == PortalRoute::MethodNotAllowed, "POST / is 405");
  check(routePortal("PUT", "/save") == PortalRoute::MethodNotAllowed, "PUT /save is 405");
  check(routePortal("GET", "/save") == PortalRoute::Redirect, "GET /save goes back to the form");
  for (const char* probe : {"/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/ncsi.txt"}) {
    check(routePortal("GET", probe) == PortalRoute::Redirect, (std::string("captive probe redirects: ") + probe).c_str());
  }

  MemWifiStore store;
  makeCredentials("stored-net", "stored-secret", &store.rec);
  store.has = true;
  WifiPortal p(&store, "presence-ABCDEF", 600000);
  p.begin(0, kOrigin);
  // The device API, OTA, and anything that might hold punch data or the
  // stored credentials: none of it exists on the portal.
  const char* sensitive[] = {"/v1/device/firmware", "/v1/device/events", "/v1/device/heartbeat", "/update",
                             "/ota",                "/firmware",         "/punches",             "/status",
                             "/wifi",               "/config",           "/save/../update"};
  for (const char* path : sensitive) {
    const std::string g = ask(p, get(path));
    check(statusLine(g) == "HTTP/1.1 302 Found" && contains(g, "Location: http://192.168.4.1/\r\n") &&
              bodyOf(g).empty(),
          (std::string("GET ") + path + " is only a redirect to the form, with no body").c_str());
    const std::string q = ask(p, post(path, "x=1"));
    check(statusLine(q) == "HTTP/1.1 404 Not Found" && bodyOf(q).empty(),
          (std::string("POST ") + path + " is 404 with no body").c_str());
  }
  const std::string form = ask(p, get("/"));
  check(!contains(form, "stored-net") && !contains(form, "stored-secret"),
        "the form never shows the credentials already stored");
  check(contains(form, "Content-Security-Policy: default-src 'none'") && !contains(form, "<script"),
        "the page carries no script and a CSP that forbids one");
}

static void testPortalSaveFlow() {
  printf("\nWi-Fi provisioning: save, read back, restart\n");
  MemWifiStore store;
  WifiPortal p(&store, "presence-0A0B0C", 600000, 1500);
  check(p.state() == PortalState::Idle, "the portal starts idle");
  p.begin(1000, kOrigin);
  check(p.state() == PortalState::Open, "begin opens it");

  const std::string form = ask(p, get("/"));
  check(statusLine(form) == "HTTP/1.1 200 OK" && contains(form, "name=\"ssid\"") &&
            contains(form, "name=\"password\" type=\"password\"") && contains(form, "presence-0A0B0C"),
        "GET / serves the SSID and password form, naming the terminal");
  const std::string headResp = ask(p, get("/", "HEAD"));
  check(statusLine(headResp) == "HTTP/1.1 200 OK" && bodyOf(headResp).empty() &&
            !contains(headResp, "Content-Length: 0\r\n"),
        "HEAD / sends the headers and no body");

  const std::string saved = ask(p, post("/save", "ssid=Clinic+Main&password=s3cret-Pass%21"), 5000);
  check(statusLine(saved) == "HTTP/1.1 200 OK" && contains(saved, "Clinic Main"), "a valid form is saved");
  check(!contains(saved, "s3cret-Pass"), "the saved page never echoes the password");
  check(store.has && strcmp(store.rec.ssid, "Clinic Main") == 0 && strcmp(store.rec.password, "s3cret-Pass!") == 0,
        "the credentials are in the store");
  check(p.state() == PortalState::Saved, "the portal is Saved");
  check(p.tick(6499) == PortalAction::None, "no restart before the response has had time to reach the phone");
  check(p.tick(6500) == PortalAction::Reboot, "then restart into station mode");

  const std::string again = ask(p, post("/save", "ssid=Other&password=different1"), 6000);
  check(strcmp(store.rec.ssid, "Clinic Main") == 0 && store.saves == 1,
        "a second submission after a save does not overwrite it");
  check(contains(again, "Clinic Main") && contains(ask(p, get("/")), "Clinic Main"),
        "and the portal keeps answering with the saved page");

  WifiCredentials boot;
  check(loadUsableCredentials(&store, &boot) && strcmp(boot.ssid, "Clinic Main") == 0,
        "the next boot finds the saved network and joins it");
}

static void testPortalRejectsBadInput() {
  printf("\nWi-Fi provisioning: bad input keeps the portal open\n");
  MemWifiStore store;
  WifiPortal p(&store, "presence-000001", 600000);
  p.begin(0, kOrigin);

  const std::string shortPw = ask(p, post("/save", "ssid=Ward+7&password=abc1234"));
  check(statusLine(shortPw) == "HTTP/1.1 400 Bad Request" && contains(shortPw, "at least 8 characters"),
        "a short password is refused with a reason");
  check(contains(shortPw, "value=\"Ward 7\"") && !contains(shortPw, "abc1234"),
        "the SSID is filled back in and the password is not");
  check(!store.has && store.saves == 0 && p.state() == PortalState::Open, "nothing is stored and the portal stays open");

  const std::string xss = ask(p, post("/save", "ssid=%3Cscript%3E%22x&password=1"));
  check(contains(xss, "value=\"&lt;script&gt;&quot;x\"") && !contains(xss, "<script>"),
        "an SSID echoed back is HTML-escaped");
  const std::string ctl = ask(p, post("/save", "ssid=a%0Ab&password=12345678"));
  check(contains(ctl, "control character") && contains(ctl, "value=\"\""),
        "an SSID with a control byte is refused and not echoed");
  const std::string dup = ask(p, post("/save", "ssid=a&ssid=b&password=12345678"));
  check(statusLine(dup) == "HTTP/1.1 400 Bad Request" && !store.has, "a duplicated field is refused");

  check(statusLine(p.handle(HttpParse::Incomplete, HttpRequest(), 0)) == "HTTP/1.1 408 Request Timeout",
        "a request that never finished arriving is 408");
  check(statusLine(p.handle(HttpParse::Bad, HttpRequest(), 0)) == "HTTP/1.1 400 Bad Request",
        "an unparseable request is 400");
  check(statusLine(p.handle(HttpParse::TooLarge, HttpRequest(), 0)) == "HTTP/1.1 413 Content Too Large",
        "an oversized request is 413");

  const std::string ok = ask(p, post("/save", "ssid=Ward+7&password=abcd1234"));
  check(statusLine(ok) == "HTTP/1.1 200 OK" && store.has, "a corrected submission then saves");
}

static void testPortalStoreFailure() {
  printf("\nWi-Fi provisioning: \"saved\" only after the write reads back\n");
  MemWifiStore store;
  store.failSave = true;
  WifiPortal p(&store, "presence-000002", 600000);
  p.begin(0, kOrigin);
  const std::string r = ask(p, post("/save", "ssid=net&password=12345678"));
  check(statusLine(r) == "HTTP/1.1 500 Internal Server Error" && contains(r, "could not store"),
        "a failed NVS write is reported, not confirmed");
  check(p.state() == PortalState::Open && p.tick(10'000) == PortalAction::None,
        "and the portal stays open rather than restarting");
  check(!contains(r, "12345678"), "the failure page does not echo the password");

  MemWifiStore liar;
  liar.corruptOnLoad = true;
  WifiPortal q(&liar, "presence-000003", 600000);
  q.begin(0, kOrigin);
  const std::string r2 = ask(q, post("/save", "ssid=net&password=12345678"));
  check(statusLine(r2) == "HTTP/1.1 500 Internal Server Error" && q.state() == PortalState::Open,
        "a write that does not read back the same is a failure too");
}

static void testPortalTimeout() {
  printf("\nWi-Fi provisioning: the window is bounded\n");
  MemWifiStore store;
  WifiPortal p(&store, "presence-000004", 600000);
  p.begin(5000, kOrigin);
  check(p.tick(604'999) == PortalAction::None, "open until the window has passed");
  check(p.tick(605'000) == PortalAction::Close, "closed at the timeout");
  check(p.state() == PortalState::Closed && p.tick(700'000) == PortalAction::None, "Close is reported once");
  const std::string late = ask(p, post("/save", "ssid=net&password=12345678"), 606'000);
  check(statusLine(late) == "HTTP/1.1 503 Service Unavailable" && !store.has,
        "a submission after the window is refused and stores nothing");

  WifiPortal w(&store, "presence-000005", 600000);
  w.begin(0xFFFF0000u, kOrigin);  // millis() is about to wrap
  check(w.tick(0x00010000u) == PortalAction::None, "the window survives a millis() wrap");
  check(w.tick(0xFFFF0000u + 600000u) == PortalAction::Close, "and still closes on time across it");

  WifiPortal idle(&store, "presence-000006", 600000);
  check(idle.tick(10'000'000) == PortalAction::None, "a portal never begun never closes or restarts");
  check(statusLine(ask(idle, get("/"))) == "HTTP/1.1 503 Service Unavailable", "and serves nothing");
}

static void testPasswordNeverLogged() {
  printf("\nWi-Fi provisioning: the password never reaches a log line\n");
  WifiCredentials c;
  makeCredentials("hospital", "Very-Secret-1", &c);
  const std::string d = describeWifi(c);
  check(d == "\"hospital\" (WPA2, passphrase)", "describeWifi names the network and the security");
  check(!contains(d, "Very-Secret-1") && !contains(d, "13"), "but not the password, nor its length");
  makeCredentials("open-cafe", "", &c);
  check(describeWifi(c) == "\"open-cafe\" (open network)", "an open network says so");
  makeCredentials("psk", std::string(64, 'f'), &c);
  check(describeWifi(c) == "\"psk\" (WPA2, raw key)" && !contains(describeWifi(c), "ffff"),
        "a raw key is described, not printed");

  std::string s = "hunter22";
  secureZero(&s);
  check(s.empty(), "secureZero empties a string");
}

static void testSoftApSsid() {
  printf("\nWi-Fi provisioning: device-unique setup network name\n");
  const uint8_t a[6] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC3};
  const uint8_t b[6] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC4};
  check(softApSsid(a) == "presence-A1B2C3", "the SSID is presence- plus the last three MAC bytes");
  check(softApSsid(a) != softApSsid(b), "two terminals side by side get different names");
  check(softApSsid(a).size() <= kWifiSsidMaxBytes, "and the name fits in an SSID");
}

static void testWifiResetTrigger() {
  printf("\nWi-Fi provisioning: the BOOT-button reset\n");
  HoldTrigger t(10'000);
  check(!t.update(true, 0) && !t.update(true, 20'000), "a button held since boot never fires (stuck button)");
  check(!t.update(false, 20'050), "released: now armed");
  check(!t.update(true, 21'000), "pressed");
  check(!t.update(true, 30'999), "not yet at 9.999 s");
  check(t.update(true, 31'000), "fires at 10 s");
  check(!t.update(true, 45'000), "only once per hold");
  check(!t.update(false, 45'050) && !t.update(true, 46'000), "release and press again");
  check(!t.update(false, 50'000) && !t.update(true, 50'050) && !t.update(true, 60'049),
        "a release part-way through restarts the count");
  check(t.update(true, 60'050), "a full second hold fires again");

  HoldTrigger w(10'000);
  w.update(false, 0xFFFFF000u);
  w.update(true, 0xFFFFF000u);
  check(!w.update(true, 0x00001000u), "the hold survives a millis() wrap");
  check(w.update(true, 0xFFFFF000u + 10'000u), "and fires on time across it");
}


// ---------------------------------------------------------------------
// 2026-10-19 follow-up: the WPA2 setup key, the fall-back to the portal,
// and the provisioning token (wifi_provision.h, provision.h).
// ---------------------------------------------------------------------
class MemSetupKeyStore : public SetupKeyStore {
 public:
  bool load(SetupApKey* out) override {
    if (!has) return false;
    *out = rec;
    return true;
  }
  bool save(const SetupApKey& k) override {
    rec = k;
    has = true;
    return true;
  }
  SetupApKey rec{};
  bool has = false;
};

class MemTokenStore : public ProvisionTokenStore {
 public:
  bool load(ProvisionTokenRecord* out) override {
    if (!has) return false;
    *out = rec;
    if (corruptOnLoad) out->token[0] = out->token[0] == 'a' ? 'b' : 'a';
    return true;
  }
  bool save(const ProvisionTokenRecord& r) override {
    saves++;
    if (failSave) return false;
    rec = r;
    has = true;
    return true;
  }
  bool erase() override {
    has = false;
    memset(&rec, 0, sizeof(rec));
    return true;
  }
  ProvisionTokenRecord rec{};
  bool has = false;
  bool failSave = false;
  bool corruptOnLoad = false;
  int saves = 0;
};

// The golden vector from firmware/tools/setup_label.py (derive() with the
// test key 00..1f and MAC 24:6F:28:A1:B2:C3; `make firmware-test` runs that
// tool's self-test too). Asserted here only as a key the terminal accepts:
// the terminal never derives one.
static const char* kGoldenSetupKey = "usty-qc6e-hs6z-52yd";
// Test tokens. Not real.
static const std::string kTokenA(64, 'a');
static const std::string kTokenMixed = "0123456789ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef";

static void testSetupKeyFormat() {
  printf("\nWi-Fi setup key: format and record\n");
  check(validSetupKey(kGoldenSetupKey, strlen(kGoldenSetupKey)), "setup_label.py's golden vector is a valid key");
  struct Case {
    const char* key;
    const char* name;
  } bad[] = {
      {"", "an empty key is refused"},
      {"usty-qc6e-hs6z-52y", "18 characters are refused"},
      {"usty-qc6e-hs6z-52ydd", "20 characters are refused"},
      {"USTY-QC6E-HS6Z-52YD", "upper case is refused (WPA2 passwords are case-sensitive; the label is lower case)"},
      {"usty-qc6e-hs6z-52y0", "0 is not in the alphabet"},
      {"usty-qc6e-hs6z-52yo", "o is not in the alphabet"},
      {"usty-qc6e-hs6z-52y1", "1 is not in the alphabet"},
      {"usty-qc6e-hs6z-52yl", "l is not in the alphabet"},
      {"ustyqc6e-hs6z-52yd-", "dashes in the wrong place are refused"},
      {"usty qc6e hs6z 52yd", "spaces instead of dashes are refused"},
  };
  for (const Case& c : bad) check(!validSetupKey(c.key, strlen(c.key)), c.name);
  const char withNul[] = "usty-qc6e\0hs6z-52yd";
  check(!validSetupKey(withNul, 19), "an embedded NUL is refused");

  SetupApKey k;
  check(makeSetupKey(kGoldenSetupKey, &k) && setupKeyUsable(k) && strcmp(k.key, kGoldenSetupKey) == 0,
        "a valid key makes a usable record");
  check(sizeof(SetupApKey) == 24, "SetupApKey is 24 bytes (a layout change needs a new magic)");
  SetupApKey z;
  memset(&z, 0x55, sizeof(z));
  check(!makeSetupKey("not-a-key", &z) && z.magic == 0 && z.key[0] == '\0', "a refused key leaves the record zeroed");
  SetupApKey m = k;
  m.magic ^= 1;
  check(!setupKeyUsable(m), "a wrong magic is not usable");
  m = k;
  m.key[19] = 'x';
  check(!setupKeyUsable(m), "a missing terminator is not usable");

  MemSetupKeyStore store;
  SetupApKey out;
  memset(&out, 0x55, sizeof(out));
  check(!loadUsableSetupKey(&store, &out) && out.magic == 0, "no key stored: no setup network (and the buffer is zeroed)");
  check(!loadUsableSetupKey(nullptr, &out), "no store: no setup network");
  store.rec = k;
  store.rec.key[3] = 'O';
  store.has = true;
  check(!loadUsableSetupKey(&store, &out), "a corrupted stored key is treated as none, never as an open network");
  store.rec = k;
  check(loadUsableSetupKey(&store, &out) && strcmp(out.key, kGoldenSetupKey) == 0, "a stored key is loaded");
  check(validatePassword(out.key, strlen(out.key)) == WifiFieldError::Ok,
        "the key is also a valid WPA2 passphrase (8..63 printable ASCII)");
}

static void testSetupSerialCommands() {
  printf("\nWi-Fi setup key: the USB serial commands\n");
  std::string key;
  auto parse = [&key](const char* line) { return parseSetupCommand(line, strlen(line), &key); };
  check(parse("SETUP-ID") == SetupCommand::Id, "SETUP-ID asks for the identity");
  check(parse("SETUP-KEY usty-qc6e-hs6z-52yd") == SetupCommand::SetKey && key == kGoldenSetupKey,
        "SETUP-KEY carries the key");
  check(parse("SETUP-KEY bogus") == SetupCommand::SetKey && key == "bogus",
        "a malformed key is still a SETUP-KEY (refused by makeSetupKey, with a reason)");
  check(parse("SETUP-KEY") == SetupCommand::Malformed && key.empty(), "SETUP-KEY with no key is malformed");
  check(parse("SETUP-KEY ") == SetupCommand::Malformed, "SETUP-KEY with an empty key is malformed");
  check(parse("SETUP-IDX") == SetupCommand::Malformed, "an unknown SETUP- command is malformed");
  check(parse("OTA STATUS") == SetupCommand::None, "OTA lines are left to the bench loader");
  check(parse("") == SetupCommand::None && parse("SETUP") == SetupCommand::None, "anything else is not ours");

  const uint8_t mac[6] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC3};
  check(setupIdLine(mac, true) == "SETUP-ID mac=246F28A1B2C3 ssid=presence-A1B2C3 key=present",
        "SETUP-ID reports the MAC, the setup SSID and whether a key is stored");
  check(setupIdLine(mac, false) == "SETUP-ID mac=246F28A1B2C3 ssid=presence-A1B2C3 key=absent",
        "and says when none is -- never the key itself");
}

static void testStationFallback() {
  printf("\nWi-Fi fall-back: the saved network, then the portal, alternating\n");
  StationFallback f(300'000);
  check(!f.portalDue(false, 10'000'000) && f.msUntilDue(0) == UINT32_MAX, "never begun: never due");
  f.begin(1'000);
  check(!f.portalDue(false, 300'999) && f.msUntilDue(300'000) == 1'000, "not due within 5 minutes of boot");
  check(f.portalDue(false, 301'000) && f.msUntilDue(301'000) == 0, "due once the saved network has not joined in 5 minutes");
  check(f.portalDue(false, 302'000), "and stays due until the portal has run (level, not edge)");
  f.restart(900'000);  // the portal ran its window and closed unused
  check(!f.portalDue(false, 1'199'999), "after the portal closes, the saved network gets a fresh window");
  check(f.portalDue(false, 1'200'000), "then the portal comes due again");
  f.restart(1'800'000);
  check(!f.portalDue(true, 1'850'000) && f.joined(), "joining the saved network disarms the fall-back");
  check(!f.portalDue(false, 99'000'000) && f.msUntilDue(99'000'000) == UINT32_MAX,
        "for good: a later outage is retried, not turned into a setup network");

  StationFallback early(300'000);
  early.begin(0);
  check(!early.portalDue(true, 5'000) && !early.portalDue(false, 400'000), "joined quickly after boot: never due");

  StationFallback late(300'000);
  late.begin(0);
  check(!late.portalDue(true, 300'000), "connected at the deadline itself: not due");

  StationFallback w(300'000);
  w.begin(0xFFFF0000u);
  check(!w.portalDue(false, 0x00010000u), "the window survives a millis() wrap");
  check(w.portalDue(false, 0xFFFF0000u + 300'000u), "and comes due on time across it");
}

static void testProvisionTokenRecord() {
  printf("\nProvisioning token: validation and record\n");
  ProvisionTokenRecord r;
  check(makeTokenRecord(kTokenA, &r) == TokenError::Ok && tokenRecordUsable(r) && kTokenA == r.token,
        "64 hex digits make a usable record");
  check(makeTokenRecord(kTokenMixed, &r) == TokenError::Ok &&
            std::string(r.token) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "upper-case hex is stored lower-cased (the terminal sends it as stored)");
  check(makeTokenRecord("  " + kTokenA + "\r\n", &r) == TokenError::Ok && kTokenA == r.token,
        "spaces and line breaks around a pasted token are dropped");
  check(makeTokenRecord("", &r) == TokenError::Missing, "an empty token is missing");
  check(makeTokenRecord("   ", &r) == TokenError::Missing, "a blank token is missing");
  check(makeTokenRecord(std::string(63, 'a'), &r) == TokenError::BadLength, "63 digits are refused");
  check(makeTokenRecord(std::string(65, 'a'), &r) == TokenError::BadLength, "65 digits are refused");
  check(makeTokenRecord(std::string(63, 'a') + "g", &r) == TokenError::BadHex, "a non-hex digit is refused");
  check(makeTokenRecord(std::string(32, 'a') + " " + std::string(31, 'a'), &r) == TokenError::BadHex,
        "a space inside the token is refused");
  check(r.magic == 0 && r.token[0] == '\0', "a refused token leaves the record zeroed");
  check(sizeof(ProvisionTokenRecord) == 69, "ProvisionTokenRecord is 69 bytes (a layout change needs a new magic)");

  makeTokenRecord(kTokenA, &r);
  ProvisionTokenRecord m = r;
  m.magic ^= 1;
  check(!tokenRecordUsable(m), "a wrong magic is not usable");
  m = r;
  m.token[5] = 'A';
  check(!tokenRecordUsable(m), "a stored upper-case digit is not usable (this build never writes one)");
  m = r;
  m.token[64] = 'a';
  check(!tokenRecordUsable(m), "a missing terminator is not usable");

  MemTokenStore store;
  ProvisionTokenRecord out;
  memset(&out, 0x55, sizeof(out));
  check(!loadUsableToken(&store, &out) && out.magic == 0, "no token stored: none, and the buffer is zeroed");
  store.rec = r;
  store.has = true;
  check(loadUsableToken(&store, &out) && kTokenA == out.token, "a stored token is loaded");
}

static std::string formBody(const std::string& ssid, const std::string& password, const char* token = nullptr) {
  std::string b = "ssid=" + ssid + "&password=" + password;
  if (token != nullptr) b += std::string("&token=") + token;
  return b;
}

static void testPortalTokenField() {
  printf("\nProvisioning token: collected by the setup page\n");
  {
    MemWifiStore wifi;
    MemTokenStore tokens;
    WifiPortal p(&wifi, "presence-00000A", 600000);
    p.setTokenField(&tokens, TokenField::Hidden);
    p.begin(0, kOrigin);
    check(!contains(ask(p, get("/")), "name=\"token\""), "a provisioned terminal's page has no token field");
    const std::string r = ask(p, post("/save", formBody("net", "12345678", kTokenA.c_str())));
    check(statusLine(r) == "HTTP/1.1 200 OK" && wifi.has && !tokens.has && tokens.saves == 0,
          "and a token sent anyway is ignored, not stored");
  }
  {
    MemWifiStore wifi;
    MemTokenStore tokens;
    WifiPortal p(&wifi, "presence-00000B", 600000);
    p.setTokenField(&tokens, TokenField::Required);
    p.begin(0, kOrigin);
    const std::string form = ask(p, get("/"));
    check(contains(form, "name=\"token\" type=\"password\"") && contains(form, "spellcheck=\"false\" required>"),
          "an unprovisioned terminal's page asks for the token, as a required password-type field");

    const std::string none = ask(p, post("/save", formBody("Ward+7", "12345678")));
    check(statusLine(none) == "HTTP/1.1 400 Bad Request" && contains(none, "Enter the provisioning token"),
          "no token is refused with a reason");
    check(!wifi.has && !tokens.has && p.state() == PortalState::Open,
          "and nothing is stored -- not even the Wi-Fi, which would close the portal for good");
    check(contains(none, "value=\"Ward 7\""), "the SSID is filled back in");

    const std::string shortTok = std::string(40, 'c');
    const std::string bad = ask(p, post("/save", formBody("net", "12345678", shortTok.c_str())));
    check(statusLine(bad) == "HTTP/1.1 400 Bad Request" && contains(bad, "64 characters") && !contains(bad, shortTok),
          "a malformed token is refused and not echoed back");
    check(!wifi.has && !tokens.has, "and nothing is stored");

    const std::string dup = ask(p, post("/save", formBody("net", "12345678", "a") + "&token=b"));
    check(statusLine(dup) == "HTTP/1.1 400 Bad Request" && !wifi.has, "a duplicated token field is refused");

    const std::string ok = ask(p, post("/save", formBody("net", "12345678", kTokenMixed.c_str())), 2000);
    check(statusLine(ok) == "HTTP/1.1 200 OK" && wifi.has && tokens.has &&
              std::string(tokens.rec.token) == "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
          "a valid token is stored, lower-cased, with the Wi-Fi");
    check(!contains(ok, "0123456789") && !contains(ok, "12345678"), "the saved page echoes neither token nor password");
  }
  {
    MemWifiStore wifi;
    MemTokenStore tokens;
    makeTokenRecord(kTokenA, &tokens.rec);
    tokens.has = true;
    WifiPortal p(&wifi, "presence-00000C", 600000);
    p.setTokenField(&tokens, TokenField::Optional);
    p.begin(0, kOrigin);
    const std::string form = ask(p, get("/"));
    check(contains(form, "name=\"token\"") && !contains(form, "spellcheck=\"false\" required>") &&
              contains(form, "already stored") && !contains(form, kTokenA),
          "with a token already stored the field is optional and the stored one is not shown");
    const std::string keep = ask(p, post("/save", formBody("net", "12345678", "")));
    check(statusLine(keep) == "HTTP/1.1 200 OK" && wifi.has && tokens.saves == 0 && kTokenA == tokens.rec.token,
          "an empty token keeps the stored one");
  }
  {
    MemWifiStore wifi;
    MemTokenStore tokens;
    makeTokenRecord(kTokenA, &tokens.rec);
    tokens.has = true;
    WifiPortal p(&wifi, "presence-00000D", 600000);
    p.setTokenField(&tokens, TokenField::Optional);
    p.begin(0, kOrigin);
    const std::string fresh(64, 'b');
    ask(p, post("/save", formBody("net", "12345678", fresh.c_str())));
    check(fresh == tokens.rec.token && wifi.has, "a new token replaces the stored one");
  }
  {
    MemWifiStore wifi;
    MemTokenStore tokens;
    tokens.failSave = true;
    WifiPortal p(&wifi, "presence-00000E", 600000);
    p.setTokenField(&tokens, TokenField::Required);
    p.begin(0, kOrigin);
    const std::string r = ask(p, post("/save", formBody("net", "12345678", kTokenA.c_str())));
    check(statusLine(r) == "HTTP/1.1 500 Internal Server Error" && !wifi.has && p.state() == PortalState::Open,
          "a token that cannot be stored is a failure, and the Wi-Fi (the commit) is not written");
    MemTokenStore liar;
    liar.corruptOnLoad = true;
    MemWifiStore wifi2;
    WifiPortal q(&wifi2, "presence-00000F", 600000);
    q.setTokenField(&liar, TokenField::Required);
    q.begin(0, kOrigin);
    const std::string r2 = ask(q, post("/save", formBody("net", "12345678", kTokenA.c_str())));
    check(statusLine(r2) == "HTTP/1.1 500 Internal Server Error" && !wifi2.has,
          "so is a token that does not read back the same");
  }
  {
    MemWifiStore wifi;
    WifiPortal p(&wifi, "presence-000010", 600000);
    p.setTokenField(nullptr, TokenField::Required);
    p.begin(0, kOrigin);
    const std::string r = ask(p, post("/save", formBody("net", "12345678", kTokenA.c_str())));
    check(statusLine(r) == "HTTP/1.1 500 Internal Server Error" && !wifi.has, "a required token with no store fails safe");
  }
}

static void testProvisionExchange() {
  printf("\nProvisioning: the terminal's side of /v1/device/provision\n");
  const uint8_t mac[6] = {0x24, 0x6F, 0x28, 0xA1, 0xB2, 0xC3};
  check(deviceSerial(mac) == "246F28A1B2C3", "the serial is the station MAC as 12 hex digits");
  check(buildProvisionBody(deviceSerial(mac), "0.1.0") == "{\"serial\":\"246F28A1B2C3\",\"firmware_version\":\"0.1.0\"}",
        "the body carries serial and firmware_version (openapi.yaml's required fields)");

  check(classifyProvisionStatus(200) == ProvisionStatus::Ok, "200: provisioned");
  check(classifyProvisionStatus(409) == ProvisionStatus::Refused, "409 (token consumed): forget the token");
  check(classifyProvisionStatus(401) == ProvisionStatus::Refused && classifyProvisionStatus(403) == ProvisionStatus::Refused,
        "401/403: forget the token");
  for (int code : {501, 500, 503, 404, 429, -1, 0}) {
    check(classifyProvisionStatus(code) == ProvisionStatus::Retry,
          ("HTTP " + std::to_string(code) + ": keep the token and retry (501 is today's gateway)").c_str());
  }

  uint8_t raw[32];
  check(decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", raw, 32), "base64 of 00..1f decodes");
  bool seq = true;
  for (int i = 0; i < 32; i++) seq = seq && raw[i] == i;
  check(seq, "to exactly those bytes");
  check(!decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", raw, 32), "unpadded is refused");
  check(!decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh==", raw, 32), "wrong padding is refused");
  check(!decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=", raw, 32),
        "non-zero trailing bits are refused (one secret, one encoding)");
  check(!decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdH*8=", raw, 32), "a character outside the alphabet is refused");
  check(!decodeBase64Exact("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd", raw, 32), "the wrong length is refused");

  const std::string good =
      "{\"device_id\":\"6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f\","
      "\"device_secret\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"key_version\":1,"
      "\"org_id\":\"00000000-0000-0000-0000-000000000001\",\"config\":{\"config_version\":1},"
      "\"server_time_ms\":1760000000000}";
  ProvisionResult r;
  check(parseProvisionResponse(good.c_str(), &r) && r.deviceId == "6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f" &&
            r.keyVersion == 1 && r.serverTimeMs == 1760000000000LL && memcmp(r.secret, raw, 32) == 0,
        "a 200 body yields device_id, the 32-byte secret, key_version and server_time_ms");

  struct Case {
    std::string body;
    const char* name;
  } bad[] = {
      {"{}", "an empty object is refused"},
      {"{\"device_secret\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"key_version\":1,\"server_time_ms\":1}",
       "no device_id is refused"},
      {"{\"device_id\":\"not-a-uuid\",\"device_secret\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\","
       "\"key_version\":1,\"server_time_ms\":1}",
       "a device_id that is not a UUID is refused"},
      {"{\"device_id\":\"6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f\",\"device_secret\":\"AAEC\",\"key_version\":1,"
       "\"server_time_ms\":1}",
       "a short secret is refused"},
      {"{\"device_id\":\"6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f\","
       "\"device_secret\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"key_version\":0,\"server_time_ms\":1}",
       "key_version 0 is refused"},
      {"{\"device_id\":\"6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f\","
       "\"device_secret\":\"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\",\"key_version\":1}",
       "no server_time_ms is refused"},
      {"{\"note\":\"device_secret\",\"device_id\":\"6f1c2b9e-1d2a-4c3b-9e8f-0a1b2c3d4e5f\",\"key_version\":1,"
       "\"server_time_ms\":1}",
       "the key name appearing only as a value is not a secret"},
  };
  for (const Case& c : bad) {
    ProvisionResult q;
    const bool parsed = parseProvisionResponse(c.body.c_str(), &q);
    bool zero = true;
    for (uint8_t b : q.secret) zero = zero && b == 0;
    check(!parsed && zero, c.name);
  }
}

// ---------------------------------------------------------------------
// The terminal's state (terminal_state.h). On main before this, setup()
// ASSIGNED the state line by line -- a sensor FAULT was then overwritten by
// PROVISION or TIME_SYNC -- and nothing ever set READY, so the scan loop
// never ran. These walk setup()'s own order of checks.
// ---------------------------------------------------------------------
static void bootLikeSetup(TerminalStatus* t, bool sensorOk, bool bufferOk, bool secretInNvs) {
  t->beginSelfTest();
  t->setSensorOk(sensorOk);      // g_finger.verifyPassword()
  t->setBufferOpened(bufferOk);  // storage + ring begin()
  t->setProvisioned(secretInNvs);
  t->selfTestDone();
}

static TerminalState bootState(bool sensorOk, bool bufferOk, bool secretInNvs) {
  TerminalStatus t;
  bootLikeSetup(&t, sensorOk, bufferOk, secretInNvs);
  return t.state();
}

static void testFaultWinsOverSetupStates() {
  printf("\nTerminal state: a fault found in setup() is not overwritten\n");
  check(bootState(false, true, false) == TerminalState::Fault,
        "sensor down, no secret: FAULT, not PROVISION");
  check(bootState(false, true, true) == TerminalState::Fault, "sensor down, secret stored: FAULT, not TIME_SYNC");
  check(bootState(true, false, false) == TerminalState::Fault, "buffer unusable, no secret: FAULT");
  check(bootState(true, false, true) == TerminalState::Fault, "buffer unusable, secret stored: FAULT");

  TerminalStatus t;  // any order of facts gives the same answer
  t.beginSelfTest();
  t.setProvisioned(true);
  t.setBufferOpened(true);
  t.setSensorOk(false);
  t.selfTestDone();
  check(t.state() == TerminalState::Fault, "whatever order the checks run in");
  t.setProvisioned(true);
  check(t.state() == TerminalState::Fault, "and provisioning later does not clear it");
}

static void testHealthyTerminalReachesReady() {
  printf("\nTerminal state: READY is reached\n");
  TerminalStatus fresh;
  check(fresh.state() == TerminalState::Boot, "before setup(): BOOT");
  fresh.beginSelfTest();
  fresh.setSensorOk(true);
  fresh.setBufferOpened(true);
  fresh.setProvisioned(true);
  check(fresh.state() == TerminalState::SelfTest, "during setup(): SELFTEST, even when every check has passed");

  check(bootState(true, true, true) == TerminalState::Ready,
        "sensor, buffer and secret all good: READY, so the scan loop runs");

  TerminalStatus t;
  bootLikeSetup(&t, true, true, false);
  check(t.state() == TerminalState::Provision, "no device secret: PROVISION");
  t.setProvisioned(true);  // /provision answered and the secret is stored
  check(t.state() == TerminalState::Ready, "then READY once the secret is stored");
  // There is no clock input at all: a dead RTC and no network still punch
  // (uptime_only, SPEC §4), so time sync never holds READY.
}

static void testSensorLossAndRecovery() {
  printf("\nTerminal state: losing the sensor, and getting it back\n");
  TerminalStatus t;
  bootLikeSetup(&t, true, true, true);
  for (int i = 0; i < kSensorLostAfter - 1; i++) check(!t.noteSensorCommError(), "a few comm errors are noise");
  check(t.state() == TerminalState::Ready, "still READY after 4 in a row");
  t.noteSensorReplied();
  for (int i = 0; i < kSensorLostAfter - 1; i++) t.noteSensorCommError();
  check(t.state() == TerminalState::Ready, "a good reply restarts the count");
  check(t.noteSensorCommError(), "the 5th in a row marks the sensor lost, reported once");
  check(t.state() == TerminalState::Fault && !t.sensorOk(), "and the terminal is in FAULT");
  check(!t.noteSensorCommError(), "further errors do not report it again");

  const uint32_t want[] = {2'000, 4'000, 8'000, 16'000, 32'000, 60'000, 60'000};
  bool backoff = true;
  for (uint32_t w : want) {
    backoff = backoff && t.sensorProbeDelayMs() == w;
    t.noteSensorProbe(false);
  }
  check(backoff, "failed probes back off 2 s, 4 s, ... capped at 60 s");
  for (int i = 0; i < 40; i++) t.noteSensorProbe(false);
  check(t.sensorProbeDelayMs() == 60'000 && t.state() == TerminalState::Fault, "and stay capped however many fail");
  t.noteSensorProbe(true);
  check(t.state() == TerminalState::Ready && t.sensorProbeDelayMs() == 2'000,
        "one good probe returns it to READY and resets the backoff");

  TerminalStatus u;
  bootLikeSetup(&u, false, true, false);
  u.noteSensorProbe(true);
  check(u.state() == TerminalState::Provision, "a sensor that recovers on an unprovisioned terminal goes to PROVISION");
}

static void testBufferFaultIsLatched() {
  printf("\nTerminal state: a failed punch write is latched\n");
  TerminalStatus t;
  bootLikeSetup(&t, true, true, true);
  t.noteBufferWriteFailed();
  check(t.state() == TerminalState::Fault && !t.bufferOk(), "a failed buffer write is FAULT");
  t.setBufferOpened(true);
  t.noteSensorProbe(true);
  t.setProvisioned(true);
  check(t.state() == TerminalState::Fault, "and nothing short of a reboot clears it");
  check(t.provisioned(), "the net task still sees whether it is provisioned (it can still upload)");
  check(strcmp(terminalStateName(TerminalState::Ready), "READY") == 0 &&
            strcmp(terminalStateName(TerminalState::Fault), "FAULT") == 0,
        "states have the SPEC's names on the console");
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
  testRingCapacityPerPartitionScheme();
  testOversizedRingFileIsNotRewritable();
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
  testRfc8032Vectors();
  testValidImageSignatureAccepted();
  testTamperedImageRejected();
  testWrongKeyRejected();
  testMalformedSignatureRejected();
  testEmptyImageRejected();
  testUnprovisionedKeyRefusesEverything();
  testVerifierIsSingleUse();
  testSigningToolGoldenVector();
  testManifestParsing();
  testVersionGrammar();
  testPreambleBytes();
  testVersionIsBoundIntoTheSignature();
  testManifestUrlForms();
  testDowngradeIsRefused();
  testConfirmedUpdateRaisesTheFloor();
  testFloorSurvivesReboot();
  testUnconfirmedImageRollsBack();
  testPowerCutInTheConfirmWindow();
  testMarkValidFailureIsRetried();
  testPendingRecordFailureBlocksTheCommit();
  testCorruptOtaStateStartsClean();
  testConfirmWindowAcrossMillisWrap();
  testSmallOrderKeysAreRefused();
  testCompiledInKeyIsNotSmallOrder();
  testHungNetworkTaskStillRollsBack();
  testConfirmCancelsTheDeadline();
  testDeadlineRestartAfterMarkValidKeepsTheImage();
  testUnarmableTimerFallsBackToTick();
  testWifiFieldValidation();
  testWifiCredentialRecord();
  testWifiBootDecision();
  testWifiFormParsing();
  testHttpRequestParsing();
  testPortalServesNothingElse();
  testPortalSaveFlow();
  testPortalRejectsBadInput();
  testPortalStoreFailure();
  testPortalTimeout();
  testPasswordNeverLogged();
  testSoftApSsid();
  testWifiResetTrigger();
  testSetupKeyFormat();
  testSetupSerialCommands();
  testStationFallback();
  testProvisionTokenRecord();
  testPortalTokenField();
  testProvisionExchange();
  testFaultWinsOverSetupStates();
  testHealthyTerminalReachesReady();
  testSensorLossAndRecovery();
  testBufferFaultIsLatched();

  printf("\n%s\n", failures == 0 ? "all firmware host tests passed" : "FAILURES");
  return failures == 0 ? 0 : 1;
}
