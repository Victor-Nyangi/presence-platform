// bench_secret.h — the bench-only BENCH-SECRET serial command.
//
// A bench terminal cannot obtain a device secret on its own: the gateway's
// POST /v1/device/provision is still a deliberate 501, so a terminal sits in
// PROVISION forever and never signs a request. `make seed` creates a device
// row and prints its id and secret once; this command writes them into NVS in
// exactly the layout provisionDevice() leaves behind (decided 2026-10-19):
//
//   host:   BENCH-SECRET <device_id> <secret> [<key_version>]\n
//             device_id    the UUID make seed prints on its "device" line
//             secret       DEVICE_SECRET: 64 hex digits, either case
//             key_version  1 to 2147483647; omitted means 1, which is what
//                          make seed issues
//   device: BENCH-SECRET OK device=<id> key_version=<n> fingerprint=<8 hex>
//           then restarts, so the secret is loaded the way a provisioned one is
//   device: BENCH-SECRET REJECT <reason>   nothing was written
//
// NVS (namespace "presence"), the same three keys storeDeviceIdentity()
// writes: device_id (string, lower case), key_version (int32), device_secret
// (32 bytes), with device_secret last because its presence is the boot
// decision.
//
// BENCH ONLY. main.cpp includes this header and calls the handler only under
// PRESENCE_BENCH_SERIAL_OTA, which only esp32dev-debug defines, and
// firmware/tools/check_bench_only.py (run by `make firmware-test`) fails if
// that ever stops being true. Anyone at the USB port can already reflash or
// erase the terminal, so on a bench board it grants nothing new; on a
// deployed one it would let anyone with a cable re-key it, which is why the
// release build does not carry it.
//
// THE SECRET IS NEVER ECHOED. A rejection names the field, never its value;
// success reports only benchSecretFingerprint(), which the operator compares
// with the fingerprint make seed prints. Buffers that held it are zeroed.
//
// Free of Arduino headers so the host tests run it.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "canonical.h"
#include "monocypher-ed25519.h"
#include "ota_verify.h"
#include "provision.h"

namespace presence {

enum class BenchSecretParse : uint8_t {
  NotOurs,        // the line is not a BENCH-SECRET command
  Ok,             // *out holds the device id, the secret and the key version
  MissingFields,  // fewer than two arguments
  ExtraFields,    // more than three
  BadDeviceId,    // not a UUID
  BadSecretLength,
  BadSecretHex,
  BadKeyVersion,
};

inline const char* benchSecretParseText(BenchSecretParse p) {
  switch (p) {
    case BenchSecretParse::NotOurs: return "not a BENCH-SECRET command";
    case BenchSecretParse::Ok: return "";
    case BenchSecretParse::MissingFields: return "usage: BENCH-SECRET <device_id> <secret> [<key_version>]";
    case BenchSecretParse::ExtraFields: return "too many fields";
    case BenchSecretParse::BadDeviceId: return "device_id is not a UUID";
    case BenchSecretParse::BadSecretLength: return "the secret is not 64 hex digits";
    case BenchSecretParse::BadSecretHex: return "the secret is not hex";
    case BenchSecretParse::BadKeyVersion: return "key_version is not 1 to 2147483647";
  }
  return "malformed";
}

// parseBenchSecretCommand reads one serial line (already trimmed). On
// anything but Ok, *out holds no secret. Fields are separated by single or
// repeated spaces.
inline BenchSecretParse parseBenchSecretCommand(const char* line, size_t n, ProvisionResult* out) {
  static const char kVerb[] = "BENCH-SECRET";
  constexpr size_t kVerbLen = sizeof(kVerb) - 1;
  secureZero(out->secret, sizeof(out->secret));
  out->deviceId.clear();
  out->keyVersion = 0;
  if (line == nullptr || n < kVerbLen || memcmp(line, kVerb, kVerbLen) != 0) return BenchSecretParse::NotOurs;
  if (n > kVerbLen && line[kVerbLen] != ' ') return BenchSecretParse::NotOurs;  // BENCH-SECRETX

  // Split the rest on spaces. At most three fields are kept; a fourth is an
  // error, not ignored, so a pasted line with junk after it is refused.
  std::string field[3];
  size_t count = 0;
  bool extra = false;
  size_t i = kVerbLen;
  while (i < n) {
    while (i < n && line[i] == ' ') i++;
    if (i >= n) break;
    size_t j = i;
    while (j < n && line[j] != ' ') j++;
    if (count < 3) {
      field[count].assign(line + i, j - i);
    } else {
      extra = true;
    }
    count++;
    i = j;
  }
  auto wipe = [&field]() {
    for (auto& f : field) secureZero(&f);
  };

  BenchSecretParse result = BenchSecretParse::Ok;
  if (count < 2) {
    result = BenchSecretParse::MissingFields;
  } else if (extra) {
    result = BenchSecretParse::ExtraFields;
  } else if (!isUuidText(field[0])) {
    result = BenchSecretParse::BadDeviceId;
  } else if (field[1].size() != 2 * kDeviceSecretBytes) {
    result = BenchSecretParse::BadSecretLength;
  } else if (!decodeHexExact(field[1], out->secret, sizeof(out->secret))) {
    result = BenchSecretParse::BadSecretHex;
  }

  int64_t kv = 1;
  if (result == BenchSecretParse::Ok && count == 3) {
    const std::string& v = field[2];
    // 1..2147483647, decimal, no sign, no leading zero.
    bool ok = !v.empty() && v.size() <= 10 && v[0] != '0';
    kv = 0;
    for (size_t k = 0; ok && k < v.size(); k++) {
      if (v[k] < '0' || v[k] > '9') {
        ok = false;
      } else {
        kv = kv * 10 + (v[k] - '0');
      }
    }
    if (!ok || kv < 1 || kv > INT32_MAX) result = BenchSecretParse::BadKeyVersion;
  }

  if (result != BenchSecretParse::Ok) {
    secureZero(out->secret, sizeof(out->secret));
    wipe();
    return result;
  }
  out->deviceId = field[0];
  for (auto& c : out->deviceId) {
    if (c >= 'A' && c <= 'F') c = static_cast<char>(c - 'A' + 'a');
  }
  out->keyVersion = kv;
  wipe();
  return BenchSecretParse::Ok;
}

// benchSecretFingerprint: the first 4 bytes of SHA-512 over the 32 raw secret
// bytes, as 8 lower-case hex digits. Enough to tell two secrets apart on a
// bench, nowhere near enough to recover one. make seed prints the same value
// (cryptobox.SecretFingerprint, pinned by the same golden vector in both test
// suites), and so does
//   printf %s "$DEVICE_SECRET" | xxd -r -p | sha512sum | cut -c1-8
inline std::string benchSecretFingerprint(const uint8_t secret[kDeviceSecretBytes]) {
  uint8_t digest[64];
  crypto_sha512(digest, secret, kDeviceSecretBytes);
  const std::string fp = toHex(digest, 4);
  secureZero(digest, sizeof(digest));
  return fp;
}

inline std::string benchSecretOkLine(const std::string& deviceId, int64_t keyVersion,
                                     const uint8_t secretReadBack[kDeviceSecretBytes]) {
  return "BENCH-SECRET OK device=" + deviceId + " key_version=" + std::to_string(keyVersion) +
         " fingerprint=" + benchSecretFingerprint(secretReadBack);
}

}  // namespace presence
