#include "ring_buffer.h"

namespace presence {

// Standard CRC-32 (IEEE 802.3), table-free. A few hundred bytes of flash and
// microseconds per 60-byte record — the point is detecting torn writes after
// a power cut, not speed.
uint32_t crc32(const uint8_t* data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++) {
      const uint32_t mask = -(crc & 1u);
      crc = (crc >> 1) ^ (0xEDB88320u & mask);
    }
  }
  return ~crc;
}

}  // namespace presence
