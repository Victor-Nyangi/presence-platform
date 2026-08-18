// canonical.h — request signing string, byte-identical to the Go gateway's
// auth.CanonicalString.
//
// Deliberately free of Arduino/ESP-IDF headers so it compiles on a host and
// can be diffed against the server implementation in CI. A signing mismatch
// between firmware and gateway is invisible until every device in the field
// starts returning 401, so this file is tested, not trusted.
#pragma once

#include <stdint.h>
#include <string>

namespace presence {

// Lowercase hex of a byte buffer.
inline std::string toHex(const uint8_t* data, size_t len) {
  static const char* kHex = "0123456789abcdef";
  std::string out;
  out.reserve(len * 2);
  for (size_t i = 0; i < len; i++) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 0x0F]);
  }
  return out;
}

inline std::string toUpper(const std::string& s) {
  std::string out = s;
  for (auto& c : out) {
    if (c >= 'a' && c <= 'z') c -= 32;
  }
  return out;
}

// canonicalString builds:
//
//   v1
//   {METHOD}
//   {PATH}
//   {timestamp_ms}
//   {nonce}
//   {sha256_hex(body)}
//
// bodySha256Hex must already be the lowercase hex digest of the exact bytes
// that will be sent. path must exclude the query string — the server signs
// r.URL.Path, so including "?since=0" here would break every roster fetch.
inline std::string canonicalString(const std::string& method,
                                   const std::string& path,
                                   int64_t timestampMs,
                                   const std::string& nonce,
                                   const std::string& bodySha256Hex) {
  return "v1\n" + toUpper(method) + "\n" + path + "\n" +
         std::to_string(timestampMs) + "\n" + nonce + "\n" + bodySha256Hex;
}

}  // namespace presence
