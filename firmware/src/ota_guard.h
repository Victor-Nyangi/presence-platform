// ota_guard.h — downgrade protection and boot confirmation for OTA.
//
// ota_verify.h answers "did the release key sign this image, at this
// version?". This file answers the two questions that come after it:
//
// 1. IS IT NEWER? A validly signed old image is still validly signed, so a
//    signature alone lets anyone who can answer GET /v1/device/firmware
//    replay last year's build, bugs and all. The signed version must be
//    strictly greater than the running build's version AND strictly greater
//    than a floor kept in NVS. The floor is the highest version that has ever
//    proved healthy on this terminal, and it only moves up, so a terminal that
//    ends up on an older slot (bootloader fallback, a USB reflash) still
//    refuses anything at or below the newest build it has run.
//
// 2. DOES IT WORK? A signed image can still be broken: a bad Wi-Fi or TLS
//    change boots fine and then never reaches the gateway again, and an
//    unreachable terminal can never be fixed over the air. With app rollback
//    enabled, a freshly flashed image boots in PENDING_VERIFY. It is marked
//    valid only after its first successful heartbeat. If that does not happen
//    within the confirm window, the terminal reboots without confirming, and
//    the bootloader then falls back to the previous slot. A crash or a power
//    cut inside the window has the same effect, which is the point.
//
// Ordering rules, in the spirit of "commit the sequence number before use":
//
// - RECORD THE PENDING UPDATE BEFORE MAKING IT BOOTABLE. notePending() writes
//   NVS before esp_ota_set_boot_partition, so a rollback is always noticed on
//   the next boot (running version != pending version) and that exact image is
//   never retried. A power cut between the two burns one image, which is
//   harmless. The reverse order can loop forever: download, boot, fail, roll
//   back, download again.
// - MARK VALID BEFORE RAISING THE FLOOR. If power drops between the two, the
//   image is valid and the floor is merely stale, and the next healthy boot
//   raises it. The reverse order can leave a floor above an image that then
//   rolls back, and that terminal would refuse the very release it needs.
// - NEVER START AN UPDATE WHILE THIS IMAGE IS UNCONFIRMED. Flashing the idle
//   slot from a pending image overwrites the only image known to work.
//
// Free of Arduino headers so the host tests run the same state machine. The
// NVS blob and the esp_ota_* calls are behind the two small interfaces below,
// implemented in main.cpp.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "ota_verify.h"

namespace presence {

// The whole persisted OTA state, written as ONE NVS entry (like the ring
// cursors) so that a power cut cannot leave a floor from one write beside a
// pending record from another. Changing the layout means bumping the magic.
struct __attribute__((packed)) OtaPersistedState {
  uint32_t magic;
  uint64_t floor;           // highest version proven healthy here; only rises
  uint8_t hasPending;       // an update was made bootable and is not yet confirmed
  uint64_t pendingVersion;  // ...at this version
  uint8_t pendingSha[kSha256Bytes];
  uint8_t hasBad;           // an update rolled back; never try that image again
  uint8_t badSha[kSha256Bytes];
};
static_assert(sizeof(OtaPersistedState) == 4 + 8 + 1 + 8 + 32 + 1 + 32, "OtaPersistedState layout changed");
constexpr uint32_t kOtaStateMagic = 0x3141544Fu;  // "OTA1"

class OtaStateStore {
 public:
  virtual ~OtaStateStore() = default;
  // false when nothing (or nothing readable) is stored
  virtual bool load(OtaPersistedState* out) = 0;
  virtual bool save(const OtaPersistedState& s) = 0;
};

class OtaBootControl {
 public:
  virtual ~OtaBootControl() = default;
  // esp_ota_mark_app_valid_cancel_rollback()
  virtual bool markValid() = 0;
  // Reboot WITHOUT confirming, so the bootloader falls back to the previous
  // slot. Returns only if it could not reboot (a host test, or a failure).
  virtual void rollback() = 0;
};

enum class OtaCandidate : uint8_t {
  Accept,
  RunningUnversioned,  // this build's own version does not parse; nothing can be compared
  BadVersion,          // the candidate's version does not parse
  NotNewer,            // candidate <= the running version (replay, or the same build)
  BelowFloor,          // candidate <= the highest version proven healthy here
  KnownBad,            // this exact image was installed once and rolled back
  Unconfirmed,         // the running image has not been confirmed yet
};

inline const char* otaCandidateName(OtaCandidate c) {
  switch (c) {
    case OtaCandidate::Accept: return "ok";
    case OtaCandidate::RunningUnversioned: return "running build has no MAJOR.MINOR.PATCH version";
    case OtaCandidate::BadVersion: return "version is not MAJOR.MINOR.PATCH";
    case OtaCandidate::NotNewer: return "not newer than the running version";
    case OtaCandidate::BelowFloor: return "not newer than the version floor";
    case OtaCandidate::KnownBad: return "this image was rolled back before";
    case OtaCandidate::Unconfirmed: return "running image is not confirmed yet";
  }
  return "refused";
}

// What begin() found, for the boot log.
enum class OtaBootKind : uint8_t {
  Normal,          // nothing pending
  AwaitingConfirm, // a new image, pending verification: confirm or roll back
  RolledBack,      // the update recorded as pending is not what is running
};

class OtaGuard {
 public:
  OtaGuard(OtaStateStore* store, OtaBootControl* boot, uint32_t confirmTimeoutMs)
      : store_(store), boot_(boot), timeoutMs_(confirmTimeoutMs) {
    memset(&st_, 0, sizeof(st_));
  }

  // begin runs once at boot. runningVersion is this build's FIRMWARE_VERSION;
  // pendingVerify is whether the bootloader reports this image as
  // ESP_OTA_IMG_PENDING_VERIFY.
  OtaBootKind begin(const std::string& runningVersion, bool pendingVerify, uint32_t nowMs) {
    bootMs_ = nowMs;
    runningOk_ = parseOtaVersion(runningVersion, &running_);
    OtaPersistedState loaded;
    if (store_ && store_->load(&loaded) && loaded.magic == kOtaStateMagic) {
      st_ = loaded;
    } else {
      memset(&st_, 0, sizeof(st_));
      st_.magic = kOtaStateMagic;
    }

    kind_ = OtaBootKind::Normal;
    if (st_.hasPending && !(runningOk_ && st_.pendingVersion == running_)) {
      // The update made bootable last time is not what booted: the bootloader
      // fell back (no confirmation in time, a crash, a power cut), or it never
      // booted at all. Either way, never install that exact image again.
      st_.hasBad = 1;
      memcpy(st_.badSha, st_.pendingSha, sizeof(st_.badSha));
      st_.hasPending = 0;
      save();
      kind_ = OtaBootKind::RolledBack;
    }
    awaiting_ = pendingVerify;
    if (awaiting_) kind_ = OtaBootKind::AwaitingConfirm;
    healthy_ = false;
    return kind_;
  }

  // check decides whether a signed candidate may be installed. It runs before
  // anything is erased; the signature is checked afterwards, from flash.
  OtaCandidate check(const std::string& version, const uint8_t sha256[kSha256Bytes]) const {
    if (!runningOk_) return OtaCandidate::RunningUnversioned;
    if (awaiting_) return OtaCandidate::Unconfirmed;
    uint64_t cand = 0;
    if (!parseOtaVersion(version, &cand)) return OtaCandidate::BadVersion;
    if (cand <= running_) return OtaCandidate::NotNewer;
    if (cand <= st_.floor) return OtaCandidate::BelowFloor;
    if (st_.hasBad && memcmp(sha256, st_.badSha, kSha256Bytes) == 0) return OtaCandidate::KnownBad;
    return OtaCandidate::Accept;
  }

  // notePending: call after the image verified and BEFORE
  // esp_ota_set_boot_partition. false means NVS refused the write, and the
  // caller must not make the image bootable.
  bool notePending(const std::string& version, const uint8_t sha256[kSha256Bytes]) {
    uint64_t v = 0;
    if (!parseOtaVersion(version, &v)) return false;
    st_.hasPending = 1;
    st_.pendingVersion = v;
    memcpy(st_.pendingSha, sha256, kSha256Bytes);
    return save();
  }

  // clearPending: esp_ota_set_boot_partition failed, so nothing changed.
  void clearPending() {
    st_.hasPending = 0;
    save();
  }

  // onHealthy: the first successful gateway heartbeat of this boot. Confirms
  // a pending image (mark valid FIRST), then raises the floor to this build.
  // Idempotent; only the first call per boot does anything.
  void onHealthy() {
    if (healthy_) return;
    if (awaiting_) {
      if (!boot_ || !boot_->markValid()) return;  // try again on the next heartbeat
      awaiting_ = false;
    }
    healthy_ = true;
    bool dirty = false;
    if (runningOk_ && running_ > st_.floor) {
      st_.floor = running_;
      dirty = true;
    }
    if (st_.hasPending && runningOk_ && st_.pendingVersion == running_) {
      st_.hasPending = 0;
      dirty = true;
    }
    if (dirty) save();
  }

  // tick: call regularly from the network task, whether or not Wi-Fi is up.
  // Rolls back an image that has not been confirmed inside the window.
  void tick(uint32_t nowMs) {
    if (!awaiting_ || rollbackRequested_) return;
    if (static_cast<uint32_t>(nowMs - bootMs_) < timeoutMs_) return;
    rollbackRequested_ = true;
    // Record it now as well as on the next boot, so the image is refused even
    // if the reboot lands somewhere unexpected. The pending record stays, so
    // the next boot still sees (and reports) the rollback.
    if (st_.hasPending && runningOk_ && st_.pendingVersion == running_) {
      st_.hasBad = 1;
      memcpy(st_.badSha, st_.pendingSha, sizeof(st_.badSha));
      save();
    }
    if (boot_) boot_->rollback();
  }

  bool awaitingConfirm() const { return awaiting_; }
  bool rollbackRequested() const { return rollbackRequested_; }
  bool healthy() const { return healthy_; }
  uint64_t floor() const { return st_.floor; }
  uint64_t running() const { return runningOk_ ? running_ : kInvalidOtaVersion; }
  uint32_t confirmTimeoutMs() const { return timeoutMs_; }
  OtaBootKind bootKind() const { return kind_; }
  const OtaPersistedState& state() const { return st_; }

 private:
  bool save() { return store_ != nullptr && store_->save(st_); }

  OtaStateStore* store_;
  OtaBootControl* boot_;
  uint32_t timeoutMs_;
  OtaPersistedState st_;
  uint64_t running_ = 0;
  bool runningOk_ = false;
  bool awaiting_ = false;
  bool healthy_ = false;
  bool rollbackRequested_ = false;
  uint32_t bootMs_ = 0;
  OtaBootKind kind_ = OtaBootKind::Normal;
};

}  // namespace presence
