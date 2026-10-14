// ota_verify.h — the OTA security gate: Ed25519 over the firmware image.
//
// SPEC §3 "OTA is a security boundary": an unsigned OTA channel is a remote
// code execution channel into every site the terminal is deployed to. The
// manifest from GET /v1/device/firmware carries the image's sha256 and a
// detached Ed25519 signature (RFC 8032, pure Ed25519) over the EXACT BYTES of
// the image. The terminal checks that signature against a public key compiled
// into the firmware (ota_pubkey.h) before it marks the new partition
// bootable. Anything else -- a bad signature, a different key, a size that
// does not match, an empty image, no key compiled in -- keeps the running
// image.
//
// Free of Arduino headers, like canonical.h and events_json.h, so the host
// tests exercise exactly the code the terminal runs. The flash and HTTP side
// lives in main.cpp.
//
// The arithmetic is Monocypher 4.0.2 (firmware/lib/monocypher, vendored
// unmodified; see VENDORED there). Pure Ed25519 hashes R || A || M, and R and
// A are known before the first image byte arrives, so the image is streamed
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

enum class OtaVerdict : uint8_t {
  Ok,
  NoKey,         // the compiled-in key is the unprovisioned sentinel
  EmptyImage,    // zero bytes expected or zero bytes seen
  SizeMismatch,  // bytes seen != size the manifest promised
  BadSignature,  // the equation failed, or finish() was called twice
};

inline const char* otaVerdictName(OtaVerdict v) {
  switch (v) {
    case OtaVerdict::Ok: return "ok";
    case OtaVerdict::NoKey: return "no release key compiled in";
    case OtaVerdict::EmptyImage: return "empty image";
    case OtaVerdict::SizeMismatch: return "image size does not match manifest";
    case OtaVerdict::BadSignature: return "bad signature";
  }
  return "bad signature";
}

// ImageVerifier streams an image through Ed25519 verification.
//
//   ImageVerifier v(kOtaReleasePublicKey, manifest.signature, manifest.size);
//   for each chunk read back from the OTA partition: v.update(chunk, n);
//   if (v.finish() != OtaVerdict::Ok) -> do not set the boot partition.
//
// finish() is single-use: a second call returns BadSignature rather than
// re-reporting Ok, so a caller cannot accidentally reuse a verdict for
// bytes it did not hash.
class ImageVerifier {
 public:
  ImageVerifier(const uint8_t publicKey[kEd25519PublicKeyBytes],
                const uint8_t signature[kEd25519SignatureBytes], size_t expectedSize)
      : expected_(expectedSize) {
    memcpy(key_, publicKey, sizeof(key_));
    memcpy(sig_, signature, sizeof(sig_));
    // h = SHA-512(R || A || M) mod L. R is the first half of the signature.
    crypto_sha512_init(&ctx_);
    crypto_sha512_update(&ctx_, sig_, 32);
    crypto_sha512_update(&ctx_, key_, sizeof(key_));
  }

  void update(const uint8_t* data, size_t len) {
    if (finished_ || len == 0) return;
    seen_ += len;
    crypto_sha512_update(&ctx_, data, len);
  }

  size_t bytesSeen() const { return seen_; }

  OtaVerdict finish() {
    if (finished_) return OtaVerdict::BadSignature;
    finished_ = true;

    uint8_t digest[64];
    crypto_sha512_final(&ctx_, digest);

    if (isUnprovisionedKey(key_)) return OtaVerdict::NoKey;
    if (expected_ == 0 || seen_ == 0) return OtaVerdict::EmptyImage;
    if (seen_ != expected_) return OtaVerdict::SizeMismatch;

    uint8_t h[32];
    crypto_eddsa_reduce(h, digest);
    // Rejects A or R off the curve and S >= L (malleability), then checks
    // [S]B = R + [h]A.
    return crypto_eddsa_check_equation(sig_, key_, h) == 0 ? OtaVerdict::Ok
                                                           : OtaVerdict::BadSignature;
  }

 private:
  uint8_t key_[kEd25519PublicKeyBytes];
  uint8_t sig_[kEd25519SignatureBytes];
  crypto_sha512_ctx ctx_;
  size_t expected_;
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

// parseOtaManifest returns false for anything it cannot use, and every caller
// treats false as "no update". available=false with nothing else is a valid
// manifest. available=true requires every field, a positive size, a 64-hex
// sha256 and a 128-hex signature -- a truncated or padded signature fails
// here before any flash is touched.
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
  if (!parseJsonString(json, "version", &m.version, kManifestMaxVersion) || m.version.empty()) return false;
  if (!parseJsonString(json, "url", &m.url, kManifestMaxUrl)) return false;
  if (m.url.rfind("https://", 0) != 0 && m.url.rfind("http://", 0) != 0) return false;
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
