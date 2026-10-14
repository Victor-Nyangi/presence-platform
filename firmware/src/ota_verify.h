// ota_verify.h — the OTA security gate: Ed25519 over a signed preamble and
// the firmware image.
//
// SPEC §3 "OTA is a security boundary": an unsigned OTA channel is a remote
// code execution channel into every site the terminal is deployed to. The
// manifest from GET /v1/device/firmware carries the image's sha256 and a
// detached Ed25519 signature (RFC 8032, pure Ed25519). The terminal checks
// that signature against a public key compiled into the firmware
// (ota_pubkey.h) before it marks the new partition bootable. Anything else --
// a bad signature, a different key, a size that does not match, an empty
// image, no key compiled in -- keeps the running image.
//
// WHAT IS SIGNED is the preamble below followed by the EXACT BYTES of the
// image:
//
//     presence-ota-image/v1\n
//     version=<MAJOR.MINOR.PATCH>\n
//     size=<image bytes, decimal>\n
//     <image bytes>
//
// The preamble is never stored or transmitted as such; both sides rebuild it
// from the manifest's version and size. Signing it is what makes the version
// trustworthy: a validly signed OLD image cannot be replayed under a newer
// version number, because changing the number breaks the signature. The
// downgrade decision itself (newer than the running image and the floor in
// NVS) is in ota_guard.h. gateway/internal/fwsign builds the same bytes and a
// golden vector pins the two together.
//
// Free of Arduino headers, like canonical.h and events_json.h, so the host
// tests exercise exactly the code the terminal runs. The flash and HTTP side
// lives in main.cpp.
//
// The arithmetic is Monocypher 4.0.2 (firmware/lib/monocypher, vendored
// unmodified; see VENDORED there). Pure Ed25519 hashes R || A || M, and R and
// A are known before the first image byte arrives, so the message is streamed
// through SHA-512 a chunk at a time. That is what makes "signature over the
// image" workable on a device with 320 KB of RAM and a 750 KB image: nothing
// is ever buffered whole, and the signer needs no prehash variant.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "events_json.h"
#include "monocypher-ed25519.h"
#include "monocypher.h"

namespace presence {

constexpr size_t kEd25519PublicKeyBytes = 32;
constexpr size_t kEd25519SignatureBytes = 64;
constexpr size_t kSha256Bytes = 32;

// decodeHexExact decodes exactly outLen bytes from a hex string of exactly
// 2*outLen characters. Short, long, odd-length or non-hex input fails, so a
// truncated signature can never be zero-padded into something that parses.
inline bool decodeHexExact(const std::string& hex, uint8_t* out, size_t outLen) {
  if (out == nullptr || hex.size() != outLen * 2) return false;
  auto nibble = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (size_t i = 0; i < outLen; i++) {
    const int hi = nibble(hex[2 * i]);
    const int lo = nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<uint8_t>((hi << 4) | lo);
  }
  return true;
}

// isUnprovisionedKey: the all-zero key is the "no release key compiled in"
// sentinel. It must never reach the curve arithmetic -- zero decodes as a
// small-order point, and a small-order public key lets an attacker forge a
// signature by guessing among a handful of candidates. Refused outright.
inline bool isUnprovisionedKey(const uint8_t publicKey[kEd25519PublicKeyBytes]) {
  uint8_t acc = 0;
  for (size_t i = 0; i < kEd25519PublicKeyBytes; i++) acc |= publicKey[i];
  return acc == 0;
}

// ed25519Verify is the one-shot form, used for the RFC 8032 vectors. It is
// the raw primitive and accepts an empty message; the OTA policy (no empty
// images) lives in ImageVerifier.
inline bool ed25519Verify(const uint8_t signature[kEd25519SignatureBytes],
                          const uint8_t publicKey[kEd25519PublicKeyBytes], const uint8_t* msg,
                          size_t len) {
  return crypto_ed25519_check(signature, publicKey, msg, len) == 0;
}

// --------------------------------------------------------------------
// Versions
//
// A firmware version is exactly MAJOR.MINOR.PATCH: decimal, 0-65535 each, no
// leading zeros, no sign, no pre-release suffix. That strictness is the point.
// The version is signed and compared, and two spellings of one number, or a
// suffix one side ignores, would let the signer and the terminal disagree
// about which image is newer. It packs into a uint64 that orders the same way
// the versions do, so the comparison is plain integer arithmetic.
// --------------------------------------------------------------------
constexpr uint64_t kInvalidOtaVersion = UINT64_MAX;
constexpr size_t kOtaVersionMaxLen = 17;  // "65535.65535.65535"

constexpr uint64_t otaVersionCode(const char* s, size_t len) {
  if (s == nullptr || len == 0 || len > kOtaVersionMaxLen) return kInvalidOtaVersion;
  uint64_t code = 0;
  size_t i = 0;
  for (int part = 0; part < 3; part++) {
    if (i >= len || s[i] < '0' || s[i] > '9') return kInvalidOtaVersion;
    if (s[i] == '0' && i + 1 < len && s[i + 1] >= '0' && s[i + 1] <= '9') return kInvalidOtaVersion;
    uint32_t v = 0;
    size_t digits = 0;
    while (i < len && s[i] >= '0' && s[i] <= '9') {
      v = v * 10 + static_cast<uint32_t>(s[i] - '0');
      i++;
      if (++digits > 5) return kInvalidOtaVersion;
    }
    if (v > 65535) return kInvalidOtaVersion;
    code = (code << 16) | v;
    if (part < 2) {
      if (i >= len || s[i] != '.') return kInvalidOtaVersion;
      i++;
    }
  }
  return i == len ? code : kInvalidOtaVersion;
}

// For string literals, so main.cpp can static_assert on FIRMWARE_VERSION: a
// build whose version does not parse could never be compared, so it does not
// compile.
template <size_t N>
constexpr uint64_t otaVersionCodeLiteral(const char (&s)[N]) {
  return otaVersionCode(s, N - 1);
}

inline bool parseOtaVersion(const std::string& s, uint64_t* out) {
  const uint64_t code = otaVersionCode(s.data(), s.size());
  if (code == kInvalidOtaVersion) return false;
  if (out) *out = code;
  return true;
}

inline std::string formatOtaVersion(uint64_t code) {
  if (code == kInvalidOtaVersion) return "invalid";
  return jsonInt(static_cast<int64_t>((code >> 32) & 0xFFFF)) + "." +
         jsonInt(static_cast<int64_t>((code >> 16) & 0xFFFF)) + "." +
         jsonInt(static_cast<int64_t>(code & 0xFFFF));
}

// otaSignedPreamble is the part of the signed message that precedes the image
// bytes. gateway/internal/fwsign.Preamble must produce the same bytes.
constexpr const char* kOtaPreambleTag = "presence-ota-image/v1\n";

inline std::string otaSignedPreamble(const std::string& version, uint64_t size) {
  std::string p = kOtaPreambleTag;
  p += "version=";
  p += version;
  p += "\nsize=";
  p += jsonInt(static_cast<int64_t>(size));
  p += "\n";
  return p;
}

enum class OtaVerdict : uint8_t {
  Ok,
  NoKey,         // the compiled-in key is the unprovisioned sentinel
  EmptyImage,    // zero bytes expected or zero bytes seen
  SizeMismatch,  // bytes seen != size the manifest promised
  BadVersion,    // the version is not MAJOR.MINOR.PATCH, so it cannot be signed for
  BadSignature,  // the equation failed, or finish() was called twice
};

inline const char* otaVerdictName(OtaVerdict v) {
  switch (v) {
    case OtaVerdict::Ok: return "ok";
    case OtaVerdict::NoKey: return "no release key compiled in";
    case OtaVerdict::EmptyImage: return "empty image";
    case OtaVerdict::SizeMismatch: return "image size does not match manifest";
    case OtaVerdict::BadVersion: return "version is not MAJOR.MINOR.PATCH";
    case OtaVerdict::BadSignature: return "bad signature";
  }
  return "bad signature";
}

// Ed25519Stream verifies a pure Ed25519 signature over a message fed in
// pieces. It is the raw primitive, streamed: no policy, empty messages
// allowed. The RFC 8032 vectors run through it.
class Ed25519Stream {
 public:
  Ed25519Stream(const uint8_t publicKey[kEd25519PublicKeyBytes],
                const uint8_t signature[kEd25519SignatureBytes]) {
    memcpy(key_, publicKey, sizeof(key_));
    memcpy(sig_, signature, sizeof(sig_));
    // h = SHA-512(R || A || M) mod L. R is the first half of the signature.
    crypto_sha512_init(&ctx_);
    crypto_sha512_update(&ctx_, sig_, 32);
    crypto_sha512_update(&ctx_, key_, sizeof(key_));
  }

  void update(const uint8_t* data, size_t len) {
    if (finished_ || len == 0) return;
    crypto_sha512_update(&ctx_, data, len);
  }

  // Single use: a second call is false.
  bool finish() {
    if (finished_) return false;
    finished_ = true;
    uint8_t digest[64];
    crypto_sha512_final(&ctx_, digest);
    if (isUnprovisionedKey(key_)) return false;
    uint8_t h[32];
    crypto_eddsa_reduce(h, digest);
    // Rejects A or R off the curve and S >= L (malleability), then checks
    // [S]B = R + [h]A.
    return crypto_eddsa_check_equation(sig_, key_, h) == 0;
  }

 private:
  uint8_t key_[kEd25519PublicKeyBytes];
  uint8_t sig_[kEd25519SignatureBytes];
  crypto_sha512_ctx ctx_;
  bool finished_ = false;
};

// ImageVerifier streams an image through Ed25519 verification, with the
// signed preamble for `version` and `expectedSize` hashed in front of it.
//
//   ImageVerifier v(kOtaReleasePublicKey, manifest.signature, manifest.version, manifest.size);
//   for each chunk read back from the OTA partition: v.update(chunk, n);
//   if (v.finish() != OtaVerdict::Ok) -> do not set the boot partition.
//
// finish() is single-use: a second call returns BadSignature rather than
// re-reporting Ok, so a caller cannot accidentally reuse a verdict for
// bytes it did not hash.
class ImageVerifier {
 public:
  ImageVerifier(const uint8_t publicKey[kEd25519PublicKeyBytes],
                const uint8_t signature[kEd25519SignatureBytes], const std::string& version,
                size_t expectedSize)
      : stream_(publicKey, signature),
        expected_(expectedSize),
        noKey_(isUnprovisionedKey(publicKey)),
        versionOk_(parseOtaVersion(version, nullptr)) {
    if (versionOk_) {
      const std::string pre = otaSignedPreamble(version, expectedSize);
      stream_.update(reinterpret_cast<const uint8_t*>(pre.data()), pre.size());
    }
  }

  void update(const uint8_t* data, size_t len) {
    if (finished_ || len == 0) return;
    seen_ += len;
    stream_.update(data, len);
  }

  size_t bytesSeen() const { return seen_; }

  OtaVerdict finish() {
    if (finished_) return OtaVerdict::BadSignature;
    finished_ = true;
    if (noKey_) return OtaVerdict::NoKey;
    if (!versionOk_) return OtaVerdict::BadVersion;
    if (expected_ == 0 || seen_ == 0) return OtaVerdict::EmptyImage;
    if (seen_ != expected_) return OtaVerdict::SizeMismatch;
    return stream_.finish() ? OtaVerdict::Ok : OtaVerdict::BadSignature;
  }

 private:
  Ed25519Stream stream_;
  size_t expected_;
  bool noKey_;
  bool versionOk_;
  size_t seen_ = 0;
  bool finished_ = false;
};

// OtaManifest mirrors the 200 body of GET /v1/device/firmware in
// docs/openapi.yaml.
struct OtaManifest {
  bool available = false;
  std::string version;
  std::string url;
  uint64_t size = 0;
  uint8_t sha256[kSha256Bytes] = {};
  uint8_t signature[kEd25519SignatureBytes] = {};
};

constexpr size_t kManifestMaxVersion = 32;  // matches firmware_version maxLength
constexpr size_t kManifestMaxUrl = 512;

// The gateway serves images itself, at a path relative to the API base the
// terminal already talks to (GET /v1/device/firmware/images/{sha256}), and
// that download is HMAC-signed like every other device call. An absolute
// http(s) URL is still accepted for an image hosted elsewhere; either way the
// image's integrity comes from the signature, not the transport.
inline bool otaUrlIsGatewayPath(const std::string& url) {
  if (url.rfind("/v1/device/firmware/images/", 0) != 0) return false;
  for (char c : url) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '/' || c == '.' || c == '-' ||
                    (c >= 'A' && c <= 'Z') || c == '_';
    if (!ok) return false;  // no query, no escapes: the path is signed verbatim
  }
  return url.find("..") == std::string::npos;
}

// parseOtaManifest returns false for anything it cannot use, and every caller
// treats false as "no update". available=false with nothing else is a valid
// manifest. available=true requires every field, a MAJOR.MINOR.PATCH version,
// a positive size, a 64-hex sha256 and a 128-hex signature -- a truncated or
// padded signature fails here before any flash is touched.
inline bool parseOtaManifest(const char* json, OtaManifest* out) {
  if (json == nullptr || out == nullptr) return false;
  OtaManifest m;
  if (!parseJsonBool(json, "available", &m.available)) return false;
  if (!m.available) {
    *out = m;
    return true;
  }

  std::string sha, sig;
  int64_t size = 0;
  if (!parseJsonString(json, "version", &m.version, kManifestMaxVersion)) return false;
  if (!parseOtaVersion(m.version, nullptr)) return false;
  if (!parseJsonString(json, "url", &m.url, kManifestMaxUrl)) return false;
  if (!otaUrlIsGatewayPath(m.url) && m.url.rfind("https://", 0) != 0 && m.url.rfind("http://", 0) != 0) {
    return false;
  }
  if (!parseJsonInt(json, "size", &size) || size <= 0) return false;
  if (!parseJsonString(json, "sha256", &sha, 2 * kSha256Bytes)) return false;
  if (!parseJsonString(json, "signature", &sig, 2 * kEd25519SignatureBytes)) return false;
  if (!decodeHexExact(sha, m.sha256, kSha256Bytes)) return false;
  if (!decodeHexExact(sig, m.signature, kEd25519SignatureBytes)) return false;

  m.size = static_cast<uint64_t>(size);
  *out = m;
  return true;
}

}  // namespace presence
