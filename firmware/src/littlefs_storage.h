// littlefs_storage.h — the on-device Storage backing the punch ring buffer.
//
// This is the one piece of the buffer that cannot be tested on the host: it
// is a binding onto LittleFS and NVS, both of which need real hardware. It
// is deliberately thin for exactly that reason. Everything with a decision
// in it — the capacity arithmetic, the ring geometry, cursor validation —
// lives in ring_buffer.h, which compiles under plain g++ and is covered by
// firmware/test/host_test.cpp. What is left here is seek, read, write.
//
// FileStorage in host_test.cpp is the same shape against stdio, and the
// persistence tests there exercise this structure end to end.
#pragma once

#include <LittleFS.h>
#include <Preferences.h>

#include "ring_buffer.h"

namespace presence {

// LittleFS spends flash on block metadata and its own bookkeeping, so the
// whole of the reported free space is never actually available to one file.
// Holding back a slice keeps preallocation from failing at the last block.
static const size_t kRingReserveBytes = 8 * 1024;

// Below this the buffer cannot cover a meaningful outage, and booting with
// it would be worse than refusing: the terminal would look healthy and
// quietly drop punches. The caller faults instead.
static const size_t kRingMinRecords = 256;

class LittleFsStorage : public Storage {
 public:
  // nvs must already be begun; main.cpp opens the "presence" namespace at
  // startup and this shares it rather than opening a second handle.
  LittleFsStorage(Preferences* nvs, const char* path = "/punches.bin")
      : nvs_(nvs), path_(path) {}

  ~LittleFsStorage() override {
    if (file_) file_.close();
  }

  // begin returns false when the filesystem cannot give us a usable buffer.
  // Callers must treat that as a fault, not carry on.
  bool begin() {
    const size_t existing = LittleFS.exists(path_) ? existingSize() : 0;

    // An existing file keeps its own size, even if the partition now has
    // room for more. RingBuffer indexes modulo the slot count, so changing
    // capacity under buffered records would scatter them. This costs
    // nothing in practice: growing the partition means reflashing the
    // partition table, which erases LittleFS, so the grow path always
    // starts from no file at all.
    if (existing >= kRingMinRecords * sizeof(PunchRecord)) {
      capacity_ = (existing / sizeof(PunchRecord)) * sizeof(PunchRecord);
      file_ = LittleFS.open(path_, "r+");
      return static_cast<bool>(file_);
    }

    capacity_ = ringCapacityBytes(LittleFS.totalBytes(), LittleFS.usedBytes(),
                                  existing, kRingReserveBytes, kRingMinRecords);
    if (capacity_ == 0) return false;
    return create();
  }

  size_t capacityBytes() const override { return capacity_; }
  size_t records() const { return capacity_ / sizeof(PunchRecord); }

  bool readAt(size_t offset, uint8_t* dst, size_t len) override {
    if (!file_ || offset + len > capacity_) return false;
    if (!file_.seek(offset, SeekSet)) return false;
    return file_.read(dst, len) == len;
  }

  bool writeAt(size_t offset, const uint8_t* src, size_t len) override {
    if (!file_ || offset + len > capacity_) return false;
    if (!file_.seek(offset, SeekSet)) return false;
    if (file_.write(src, len) != len) return false;
    // Flush before returning: append() only reports success once this call
    // does, and the caller lights the green LED on that. A buffered write
    // would confirm a punch that flash has not taken yet.
    file_.flush();
    return true;
  }

  // Both cursors go in one NVS entry. Two keys can tear against each other
  // on a power cut, and the resulting pair is not merely stale — a tail
  // past the head underflows depth(). One entry makes that unrepresentable.
  // (RingBuffer::begin still validates, since NVS corruption has other
  // causes, but this keeps the common path from producing it at all.)
  bool saveCursors(uint64_t head, uint64_t tail) override {
    uint64_t pair[2] = {head, tail};
    return nvs_->putBytes(kCursorKey, pair, sizeof(pair)) == sizeof(pair);
  }

  bool loadCursors(uint64_t* head, uint64_t* tail) override {
    uint64_t pair[2] = {0, 0};
    if (nvs_->getBytes(kCursorKey, pair, sizeof(pair)) != sizeof(pair)) {
      return false;
    }
    *head = pair[0];
    *tail = pair[1];
    return true;
  }

 private:
  static constexpr const char* kCursorKey = "ring_cursors";

  size_t existingSize() {
    File f = LittleFS.open(path_, "r");
    if (!f) return 0;
    const size_t n = f.size();
    f.close();
    return n;
  }

  // Create the ring file at full size up front rather than letting it grow
  // as punches arrive. A write past the high-water mark can fail for want
  // of space, and it would do so mid-outage — the one moment the buffer is
  // the only copy of the data. Preallocating moves that failure to startup,
  // where it is visible and recoverable.
  bool create() {
    File f = LittleFS.open(path_, "w");
    if (!f) return false;
    uint8_t zeros[sizeof(PunchRecord) * 8] = {0};
    size_t remaining = capacity_;
    while (remaining > 0) {
      const size_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
      if (f.write(zeros, chunk) != chunk) {
        f.close();
        return false;
      }
      remaining -= chunk;
    }
    f.close();

    // A fresh ring file means the old cursors describe records that no
    // longer exist. Clearing them keeps begin() from resuming into a file
    // full of zeros, whose CRCs will not match anyway.
    nvs_->remove(kCursorKey);

    file_ = LittleFS.open(path_, "r+");
    return static_cast<bool>(file_);
  }

  Preferences* nvs_;
  const char* path_;
  File file_;
  size_t capacity_ = 0;
};

}  // namespace presence
