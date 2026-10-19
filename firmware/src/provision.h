// provision.h — the terminal's side of POST /v1/device/provision.
//
// A terminal with no device secret in NVS exchanges a one-time provisioning
// token for one (SPEC §3, docs/openapi.yaml). The installer types the token
// into the Wi-Fi setup page (wifi_provision.h), which stores it here; once the
// terminal is on the network the net task presents it in X-Provision-Token
// and stores what comes back. docs/wifi-provisioning.md has the flow and what
// the gateway still has to implement: today the endpoint is a deliberate 501,
// so this side is built and host-tested but has never completed against a
// gateway.
//
// Rules, in the spirit of the rest of the firmware:
//
// - THE TOKEN IS A BEARER SECRET. It is never logged, never echoed into the
//   setup page, and buffers that held it are zeroed (best effort).
// - ONE NVS ENTRY for the token, like the Wi-Fi credentials, so a record is
//   either whole or treated as absent.
// - THE DEVICE SECRET IS THE COMMIT. device_id and key_version are written
//   first and device_secret last, because "is device_secret in NVS" is the
//   boot decision. Only then is the token erased; a token left behind next
//   to a secret is erased at boot.
// - A REFUSED TOKEN IS FORGOTTEN. 401, 403 and 409 (already consumed) cannot
//   be fixed by retrying, so the token is erased and the installer is told to
//   enter a new one. Anything else (501 included) is retried with backoff.
//
// Free of Arduino headers so the host tests run it.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "events_json.h"

namespace presence {

// Best effort: the compiler may not elide a write through volatile.
inline void secureZero(void* p, size_t n) {
  volatile uint8_t* v = static_cast<volatile uint8_t*>(p);
  while (n--) *v++ = 0;
}
inline void secureZero(std::string* s) {
  if (!s->empty()) secureZero(&(*s)[0], s->size());
  s->clear();
}

// --------------------------------------------------------------------
// The token: 32 bytes of CSPRNG output (cryptobox.HashToken's comment), carried
// as 64 hex digits. The SPEC does not fix an encoding; hex is the one the rest
// of the repo uses for 32-byte secrets (seed -secret, cryptobox.NewSecret).
// The terminal stores and sends it lower-cased, exactly as below.
// --------------------------------------------------------------------
constexpr size_t kProvisionTokenHexChars = 64;

struct __attribute__((packed)) ProvisionTokenRecord {
  uint32_t magic;
  char token[kProvisionTokenHexChars + 1];  // NUL-terminated, lower-case hex
};
static_assert(sizeof(ProvisionTokenRecord) == 4 + 65, "ProvisionTokenRecord layout changed");
constexpr uint32_t kProvisionTokenMagic = 0x314B4F54u;  // "TOK1"

enum class TokenError : uint8_t { Ok, Missing, BadLength, BadHex };

inline const char* tokenErrorText(TokenError e) {
  switch (e) {
    case TokenError::Ok: return "";
    case TokenError::Missing: return "Enter the provisioning token from the installation sheet.";
    case TokenError::BadLength: return "The provisioning token is 64 characters long.";
    case TokenError::BadHex: return "The provisioning token uses only the characters 0-9 and a-f.";
  }
  return "Invalid provisioning token.";
}

inline bool tokenHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// trimSpaces drops leading and trailing spaces, tabs and line breaks, which a
// phone may add when pasting the token from a QR scan. A space can never be
// part of a hex token, so this cannot change what a valid token means.
inline void trimSpaces(std::string* s) {
  size_t b = 0, e = s->size();
  auto space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
  while (b < e && space((*s)[b])) b++;
  while (e > b && space((*s)[e - 1])) e--;
  if (b == 0 && e == s->size()) return;
  std::string kept = s->substr(b, e - b);
  secureZero(s);
  s->swap(kept);
}

inline TokenError validateProvisionToken(const char* s, size_t n) {
  if (n == 0) return TokenError::Missing;
  if (n != kProvisionTokenHexChars) return TokenError::BadLength;
  for (size_t i = 0; i < n; i++) {
    if (!tokenHexDigit(s[i])) return TokenError::BadHex;
  }
  return TokenError::Ok;
}

// makeTokenRecord validates (after trimming) and fills *out, lower-cased. On
// any error *out is all zero.
inline TokenError makeTokenRecord(std::string token, ProvisionTokenRecord* out) {
  memset(out, 0, sizeof(*out));
  trimSpaces(&token);
  const TokenError e = validateProvisionToken(token.data(), token.size());
  if (e == TokenError::Ok) {
    out->magic = kProvisionTokenMagic;
    for (size_t i = 0; i < token.size(); i++) {
      const char c = token[i];
      out->token[i] = (c >= 'A' && c <= 'F') ? static_cast<char>(c - 'A' + 'a') : c;
    }
  }
  secureZero(&token);
  return e;
}

inline bool tokenRecordUsable(const ProvisionTokenRecord& r) {
  if (r.magic != kProvisionTokenMagic) return false;
  if (r.token[kProvisionTokenHexChars] != '\0') return false;
  for (size_t i = 0; i < kProvisionTokenHexChars; i++) {
    const char c = r.token[i];
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
  }
  return true;
}

class ProvisionTokenStore {
 public:
  virtual ~ProvisionTokenStore() = default;
  virtual bool load(ProvisionTokenRecord* out) = 0;
  virtual bool save(const ProvisionTokenRecord& r) = 0;
  // true when nothing is stored afterwards, including when nothing was
  virtual bool erase() = 0;
};

// loadUsableToken: true with *out filled, or false with *out zeroed.
inline bool loadUsableToken(ProvisionTokenStore* store, ProvisionTokenRecord* out) {
  if (store != nullptr && store->load(out) && tokenRecordUsable(*out)) return true;
  secureZero(out, sizeof(*out));
  return false;
}

// --------------------------------------------------------------------
// The request
// --------------------------------------------------------------------

// deviceSerial: the station MAC as 12 upper-case hex digits, the same bytes
// esptool prints at flash time and the setup network's name ends in. The
// gateway matches this against the device row the token was issued for.
inline std::string deviceSerial(const uint8_t mac[6]) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string s;
  for (int i = 0; i < 6; i++) {
    s += kHex[mac[i] >> 4];
    s += kHex[mac[i] & 0x0F];
  }
  return s;
}

// buildProvisionBody: both values are fixed grammars (hex; MAJOR.MINOR.PATCH,
// static_assert-ed in main.cpp), so neither needs JSON escaping.
inline std::string buildProvisionBody(const std::string& serial, const char* firmwareVersion) {
  std::string b = "{\"serial\":\"";
  b += serial;
  b += "\",\"firmware_version\":\"";
  b += firmwareVersion;
  b += "\"}";
  return b;
}

// --------------------------------------------------------------------
// The response
// --------------------------------------------------------------------
enum class ProvisionStatus : uint8_t {
  Ok,       // 200: parse the body
  Refused,  // the token will never work: forget it
  Retry,    // transport error, 5xx, 501 (not enabled yet), anything else
};

inline ProvisionStatus classifyProvisionStatus(int httpStatus) {
  if (httpStatus == 200) return ProvisionStatus::Ok;
  if (httpStatus == 401 || httpStatus == 403 || httpStatus == 409) return ProvisionStatus::Refused;
  return ProvisionStatus::Retry;
}

constexpr size_t kDeviceSecretBytes = 32;

struct ProvisionResult {
  std::string deviceId;  // a UUID
  uint8_t secret[kDeviceSecretBytes] = {};
  int64_t keyVersion = 0;
  int64_t serverTimeMs = 0;
  ~ProvisionResult() { secureZero(secret, sizeof(secret)); }
};

inline int base64Value(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

// decodeBase64Exact: standard alphabet, padded (what Go's
// base64.StdEncoding writes), exactly outLen bytes, and canonical -- unused
// trailing bits must be zero -- so one secret has one encoding.
inline bool decodeBase64Exact(const std::string& in, uint8_t* out, size_t outLen) {
  const size_t want = (outLen + 2) / 3 * 4;
  if (in.size() != want || outLen == 0) return false;
  const size_t pad = outLen % 3 == 0 ? 0 : 3 - outLen % 3;
  for (size_t i = 0; i < want; i++) {
    const bool padSlot = i >= want - pad;
    if (padSlot != (in[i] == '=')) return false;
  }
  size_t o = 0;
  for (size_t i = 0; i < want; i += 4) {
    uint32_t acc = 0;
    int bits = 0;
    for (size_t j = 0; j < 4; j++) {
      if (in[i + j] == '=') break;
      const int v = base64Value(in[i + j]);
      if (v < 0) return false;
      acc = (acc << 6) | static_cast<uint32_t>(v);
      bits += 6;
    }
    while (bits >= 8) {
      bits -= 8;
      if (o >= outLen) return false;
      out[o++] = static_cast<uint8_t>(acc >> bits);
    }
    if (bits > 0 && (acc & ((1u << bits) - 1)) != 0) return false;  // non-canonical
  }
  return o == outLen;
}

inline bool isUuidText(const std::string& s) {
  if (s.size() != 36) return false;
  for (size_t i = 0; i < s.size(); i++) {
    const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
    if (dash ? s[i] != '-' : !tokenHexDigit(s[i])) return false;
  }
  return true;
}

// parseProvisionResponse reads a 200 body. Every field openapi.yaml marks
// required for the device's own use must be present and well-formed, or the
// whole response is refused and nothing is stored.
inline bool parseProvisionResponse(const char* json, ProvisionResult* out) {
  if (json == nullptr || out == nullptr) return false;
  std::string id, secret;
  if (!parseJsonString(json, "device_id", &id, 36) || !isUuidText(id)) return false;
  if (!parseJsonString(json, "device_secret", &secret, 64)) return false;
  const bool decoded = decodeBase64Exact(secret, out->secret, sizeof(out->secret));
  secureZero(&secret);
  if (!decoded) {
    secureZero(out->secret, sizeof(out->secret));
    return false;
  }
  int64_t kv = 0, ts = 0;
  if (!parseJsonInt(json, "key_version", &kv) || kv < 1 || kv > INT32_MAX ||
      !parseJsonInt(json, "server_time_ms", &ts) || ts <= 0) {
    secureZero(out->secret, sizeof(out->secret));
    return false;
  }
  out->deviceId = id;
  out->keyVersion = kv;
  out->serverTimeMs = ts;
  return true;
}

}  // namespace presence
