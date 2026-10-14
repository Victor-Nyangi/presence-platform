// Host-side tests for the parts of the firmware that must agree with the
// gateway or survive power loss. Runs with plain g++, no ESP32 toolchain:
//
//     make firmware-test
//
// What is NOT covered here: anything touching the sensor, Wi-Fi, or real
// flash. Those need hardware. The OTA gate (ota_verify.h) IS covered: the
// same Monocypher sources the terminal links are compiled in here.

#include <cassert>
#include <cstdio>
#include <cstring>
#include <random>
#include <string>
#include <vector>

#include "../src/canonical.h"
#include "../src/events_json.h"
#include "../src/ota_pubkey.h"
#include "../src/ota_verify.h"
#include "../src/ring_buffer.h"
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

static std::vector<uint8_t> signImage(const TestKey& k, const std::vector<uint8_t>& img) {
  std::vector<uint8_t> sig(64);
  crypto_ed25519_sign(sig.data(), k.sk, img.data(), img.size());
  return sig;
}

// Streams img through an ImageVerifier in `chunk`-sized pieces, as main.cpp
// does when it reads the OTA partition back.
static OtaVerdict verifyStreamed(const uint8_t* pk, const uint8_t* sig, size_t expected,
                                 const uint8_t* img, size_t len, size_t chunk) {
  ImageVerifier v(pk, sig, expected);
  for (size_t off = 0; off < len; off += chunk) {
    v.update(img + off, len - off < chunk ? len - off : chunk);
  }
  return v.finish();
}

static OtaVerdict verifyImage(const TestKey& k, const std::vector<uint8_t>& sig,
                              const std::vector<uint8_t>& img) {
  return verifyStreamed(k.pk, sig.data(), img.size(), img.data(), img.size(), 4096);
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
        allChunkings = allChunkings &&
                       verifyStreamed(v.pk, v.sig, v.msgLen, v.msg, v.msgLen, chunk) == OtaVerdict::Ok;
      }
      check(allChunkings, (name + " streams through ImageVerifier at chunk 1/7/4096").c_str());
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
  check(ed25519Verify(sig.data(), k.pk, img.data(), img.size()),
        "streaming agrees with one-shot verification");

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

  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(4096);
  const std::vector<uint8_t> sig = signImage(k, img);
  check(verifyStreamed(k.pk, sig.data(), img.size(), img.data(), 0, 4096) == OtaVerdict::EmptyImage,
        "a download that delivered no bytes is rejected");
}

static void testUnprovisionedKeyRefusesEverything() {
  printf("\nOTA: no release key compiled in\n");
  const uint8_t zero[32] = {0};
  check(isUnprovisionedKey(zero), "the all-zero key is the unprovisioned sentinel");
  const TestKey k = makeTestKey();
  check(!isUnprovisionedKey(k.pk), "a real key is not");

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

static void testVerifierIsSingleUse() {
  printf("\nOTA: a verdict cannot be reused\n");
  const TestKey k = makeTestKey();
  const std::vector<uint8_t> img = makeImage(1024);
  const std::vector<uint8_t> sig = signImage(k, img);
  ImageVerifier v(k.pk, sig.data(), img.size());
  v.update(img.data(), img.size());
  check(v.finish() == OtaVerdict::Ok, "first finish() is ok");
  check(v.finish() == OtaVerdict::BadSignature, "a second finish() is not");
}

// The golden vector pinning the signing tool to the firmware, the way the
// HMAC golden vector pins the gateway to the device. The same values are in
// gateway/internal/fwsign/fwsign_test.go. They were produced once with a key
// generated in memory and never written anywhere; only the public half
// exists. If the tool ever signs something other than the raw image bytes
// (a hash, hex, a prehash variant), one side of this fails.
static std::vector<uint8_t> goldenImage() {
  std::vector<uint8_t> img(4099);
  for (size_t i = 0; i < img.size(); i++) img[i] = static_cast<uint8_t>((i * 167 + 13) ^ (i >> 8));
  return img;
}
static const char* kGoldenPublicKey = "3cd093728d823e9acc0bff6a7d13fa56ebb1ec74919534be98cb7a0621dd1858";
static const char* kGoldenSignature =
    "5c4bcc9ae75f0e50435e512ff754ba38ba074890774fff7eabe74be5963b3415"
    "f7627f50e35ee73fb7b80137a92228bbaf3b864592b325064ba881bd8c247d08";

static void testSigningToolGoldenVector() {
  printf("\nOTA: signing tool golden vector\n");
  uint8_t pk[32], sig[64];
  check(decodeHexExact(kGoldenPublicKey, pk, 32) && decodeHexExact(kGoldenSignature, sig, 64),
        "golden key and signature decode");
  const std::vector<uint8_t> img = goldenImage();
  check(verifyStreamed(pk, sig, img.size(), img.data(), img.size(), 4096) == OtaVerdict::Ok,
        "an image signed by Go crypto/ed25519 verifies on the firmware path");
  std::vector<uint8_t> bad = img;
  bad[4098] ^= 0x01;
  check(verifyStreamed(pk, sig, bad.size(), bad.data(), bad.size(), 4096) == OtaVerdict::BadSignature,
        "and the same image with its last byte flipped does not");
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
            m.signature[0] == 0x5c && m.signature[63] == 0x08,
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

  printf("\n%s\n", failures == 0 ? "all firmware host tests passed" : "FAILURES");
  return failures == 0 ? 0 : 1;
}
