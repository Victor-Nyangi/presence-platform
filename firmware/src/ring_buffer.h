// ring_buffer.h — the offline punch buffer.
//
// This is the part of the firmware that decides whether the product works.
// Wi-Fi at a school or a hospital ward drops constantly; if a punch taken
// during an outage is lost, the system is worthless. So:
//
//   - Fixed-size records. O(1) append, no fragmentation, no compaction pass
//     that could be interrupted by a power cut halfway through.
//   - CRC32 per record. A write interrupted by power loss leaves a corrupt
//     tail record, which is skipped on read rather than crashing the boot.
//   - Head/tail offsets live in NVS, not in the data file, so a torn write
//     to the data file cannot lose the whole buffer.
//   - Records are only dropped after the server acknowledges them.
//
// Storage is abstracted so the logic is testable on a host without LittleFS.
#pragma once

#include <stdint.h>
#include <string.h>

#include <cstddef>

namespace presence {

// One buffered punch, 60 bytes. Keeping this a POD with no pointers means it
// can be memcpy'd straight to flash.
struct __attribute__((packed)) PunchRecord {
  uint64_t seq;              // 8   monotonic, from NVS, never reused
  uint64_t capturedEpochMs;  // 8   RTC belief; 0 when the RTC is unusable
  uint64_t capturedUptimeMs; // 8   always set, lets the server recover time
  uint8_t  uuid[16];         // 16  event_uuid
  uint16_t slotNo;           // 2   on-module template slot
  uint16_t matchScore;       // 2
  uint8_t  credentialKind;   // 1   0=fingerprint 1=rfid 2=nfc 3=pin 4=qr
  uint8_t  timeSource;       // 1   0=rtc_synced 1=rtc_unsynced 2=uptime_only
  uint8_t  directionHint;    // 1   0=unknown 1=in 2=out
  uint8_t  reserved[9];      // 9   pad to 56, room to grow without a format bump
  uint32_t crc32;            // 4   over the preceding 56 bytes
};                           // = 60 bytes

static_assert(sizeof(PunchRecord) == 60, "PunchRecord layout changed; bump the format version");

uint32_t crc32(const uint8_t* data, size_t len);

// Storage is the seam for testing: LittleFS on device, a plain file or memory
// on the host.
class Storage {
 public:
  virtual ~Storage() = default;
  virtual bool readAt(size_t offset, uint8_t* dst, size_t len) = 0;
  virtual bool writeAt(size_t offset, const uint8_t* src, size_t len) = 0;
  virtual size_t capacityBytes() const = 0;
  // Persisted outside the data file so a torn data write cannot orphan it.
  virtual bool saveCursors(uint64_t head, uint64_t tail) = 0;
  virtual bool loadCursors(uint64_t* head, uint64_t* tail) = 0;
};

// ringCapacityBytes decides how large the ring file should be, given what
// the filesystem reports. Sizing at runtime rather than hard-coding a number
// means that enlarging the LittleFS partition later grows the buffer with no
// code change -- which matters, because the partition table is the binding
// constraint on how long an outage the terminal can ride out, not the flash
// size.
//
// existingRingBytes is added back because usedBytes already counts the ring
// file we are about to reopen. Leaving it out shrinks the buffer to nothing
// on the second boot.
//
// Returns 0 when the partition cannot hold minRecords, so the caller can
// fault loudly at startup instead of booting with a buffer too small to
// cover an outage.
inline size_t ringCapacityBytes(size_t totalBytes, size_t usedBytes,
                                size_t existingRingBytes, size_t reserveBytes,
                                size_t minRecords) {
  if (usedBytes > totalBytes) return 0;
  const size_t available = (totalBytes - usedBytes) + existingRingBytes;
  if (available <= reserveBytes) return 0;
  const size_t records = (available - reserveBytes) / sizeof(PunchRecord);
  if (records < minRecords) return 0;
  return records * sizeof(PunchRecord);
}

class RingBuffer {
 public:
  explicit RingBuffer(Storage* storage) : storage_(storage) {}

  bool begin() {
    slots_ = storage_->capacityBytes() / sizeof(PunchRecord);
    if (slots_ == 0) return false;
    if (!storage_->loadCursors(&head_, &tail_)) {
      head_ = tail_ = 0;
    }
    // Cursors come back from NVS, where a power cut or a corrupt entry can
    // leave a pair the API itself could never produce. Neither case is
    // survivable unchecked, because depth() is unsigned subtraction: a tail
    // past the head does not fault, it underflows to ~1.8e19 and pins full()
    // true, so every later punch silently evicts a good record. A head
    // further ahead than the ring holds is the same kind of lie in the other
    // direction -- those records have already been overwritten.
    //
    // Clamping costs at most one buffer of already-unrecoverable records;
    // trusting the pair corrupts every punch from here on.
    if (tail_ > head_) tail_ = head_;
    if (head_ - tail_ > slots_) tail_ = head_ - slots_;
    return true;
  }

  size_t depth() const { return static_cast<size_t>(head_ - tail_); }
  bool empty() const { return head_ == tail_; }
  bool full() const { return depth() >= slots_; }

  // append writes the record and only then returns true. The caller must not
  // give the user a green light before this succeeds — confirming a punch
  // that was never persisted is worse than a slow beep.
  bool append(PunchRecord rec) {
    // begin() never succeeded, so there is nowhere to put this. Returning
    // false makes the caller withhold the green light, which is the right
    // answer; indexing by "head % slots" with no slots would instead take
    // the terminal down with a divide-by-zero on every punch.
    if (slots_ == 0) return false;

    rec.crc32 = crc32(reinterpret_cast<const uint8_t*>(&rec), sizeof(PunchRecord) - 4);

    // A full buffer means a very long outage. Dropping the OLDEST record is
    // the lesser evil: recent presence data is what anyone will act on, and
    // silently refusing new punches would look like a broken reader.
    if (full()) {
      tail_++;
    }
    const size_t offset = static_cast<size_t>(head_ % slots_) * sizeof(PunchRecord);
    if (!storage_->writeAt(offset, reinterpret_cast<const uint8_t*>(&rec), sizeof(PunchRecord))) {
      return false;
    }
    head_++;
    return storage_->saveCursors(head_, tail_);
  }

  // peek fills up to max records from the tail without consuming them. They
  // are only dropped once the server acknowledges them, so a lost response
  // costs a retry rather than the data.
  size_t peek(PunchRecord* out, size_t max) {
    size_t n = 0;
    for (uint64_t i = tail_; i < head_ && n < max; i++) {
      const size_t offset = static_cast<size_t>(i % slots_) * sizeof(PunchRecord);
      PunchRecord rec{};
      if (!storage_->readAt(offset, reinterpret_cast<uint8_t*>(&rec), sizeof(PunchRecord))) {
        continue;
      }
      const uint32_t want = crc32(reinterpret_cast<const uint8_t*>(&rec), sizeof(PunchRecord) - 4);
      if (want != rec.crc32) {
        // Torn write from a power cut. Skip it; do not abort the drain, or
        // one bad record wedges the buffer exactly like a poison event
        // wedges the server queue.
        continue;
      }
      out[n++] = rec;
    }
    return n;
  }

  // ackThrough drops every record up to and including seq. Called only with
  // the value the server returned, never optimistically.
  size_t ackThrough(uint64_t seq) {
    size_t dropped = 0;
    while (tail_ < head_) {
      const size_t offset = static_cast<size_t>(tail_ % slots_) * sizeof(PunchRecord);
      PunchRecord rec{};
      if (!storage_->readAt(offset, reinterpret_cast<uint8_t*>(&rec), sizeof(PunchRecord))) break;
      const uint32_t want = crc32(reinterpret_cast<const uint8_t*>(&rec), sizeof(PunchRecord) - 4);
      // Corrupt records are dropped too: they can never be uploaded, so
      // keeping them would stall the tail forever.
      if (want == rec.crc32 && rec.seq > seq) break;
      tail_++;
      dropped++;
    }
    storage_->saveCursors(head_, tail_);
    return dropped;
  }

 private:
  Storage* storage_;
  size_t slots_ = 0;
  uint64_t head_ = 0;  // next write position
  uint64_t tail_ = 0;  // oldest unacknowledged
};

}  // namespace presence
