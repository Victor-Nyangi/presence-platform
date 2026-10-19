// terminal_state.h — which state the terminal is in, derived from its health.
//
// The state is not assigned; it is COMPUTED from a few facts that each have
// one owner, so no ordering of setup() lines or race between tasks can let a
// later, milder fact overwrite an earlier, worse one:
//
//   not through self-test ................................. SELFTEST
//   sensor not answering, or the punch buffer unusable .... FAULT      (wins)
//   no device secret ....................................... PROVISION
//   otherwise ............................................... READY
//
// SPEC §5 drew BOOT → SELFTEST → [secret in NVS?] → PROVISION → TIME_SYNC →
// READY, and FAULT "retry with backoff" back to READY. The two departures
// below were accepted as made on 2026-10-19, and §5 now draws them.
//
// TIME_SYNC does not gate READY. §4 requires a terminal with a dead RTC and no
// network to keep taking punches (stamped uptime_only, reconstructed by the
// gateway), and the scan loop must never wait on the network, so a terminal
// that held READY until a server clock arrived would refuse punches during
// exactly the outage the buffer exists for. The clock is corrected on the net
// task whenever the gateway answers (heartbeat, clock_skew); each punch
// records which time source it had.
//
// Recovery: a sensor that stops answering (kSensorLostAfter comm errors in a
// row) faults the terminal, and the scan task re-probes it with backoff
// (sensorProbeDelayMs); one good probe returns it to READY. A buffer fault is
// latched until reboot: a ring that could not be opened, or failed a write,
// is not safe to append to again, and a green beep on a dropped punch is the
// one thing the firmware must never do.
//
// Free of Arduino headers so the host tests run it. Fields are atomics because
// the scan task, the net task and setup() each own different ones.
#pragma once

#include <stdint.h>

#include <atomic>

namespace presence {

enum class TerminalState : uint8_t { Boot, SelfTest, Provision, TimeSync, Ready, Enroll, Ota, Fault };

inline const char* terminalStateName(TerminalState s) {
  switch (s) {
    case TerminalState::Boot: return "BOOT";
    case TerminalState::SelfTest: return "SELFTEST";
    case TerminalState::Provision: return "PROVISION";
    case TerminalState::TimeSync: return "TIME_SYNC";
    case TerminalState::Ready: return "READY";
    case TerminalState::Enroll: return "ENROLL";
    case TerminalState::Ota: return "OTA";
    case TerminalState::Fault: return "FAULT";
  }
  return "?";
}

// Consecutive packet errors from the sensor before it counts as lost. A
// single garbled reply on a noisy UART is not a fault; five in a row (each
// one a full read timeout) is.
constexpr uint8_t kSensorLostAfter = 5;
constexpr uint32_t kSensorProbeMinMs = 2'000;
constexpr uint32_t kSensorProbeMaxMs = 60'000;

class TerminalStatus {
 public:
  void beginSelfTest() { phase_ = Phase::SelfTest; }
  // End of setup(): from here the state follows the facts below.
  void selfTestDone() { phase_ = Phase::Running; }

  // --- the sensor (setup()'s first check, then the scan task) ----------
  void setSensorOk(bool ok) {
    sensorOk_ = ok;
    commErrors_ = 0;
    if (ok) failedProbes_ = 0;
  }
  // noteSensorCommError: true exactly when this error is the one that marks
  // the sensor lost (so the caller logs it once).
  bool noteSensorCommError() {
    if (!sensorOk_) return false;
    if (++commErrors_ < kSensorLostAfter) return false;
    sensorOk_ = false;
    commErrors_ = 0;
    failedProbes_ = 0;
    return true;
  }
  void noteSensorReplied() { commErrors_ = 0; }
  // noteSensorProbe: the result of a re-probe while faulted.
  void noteSensorProbe(bool ok) {
    if (ok) {
      setSensorOk(true);
    } else if (failedProbes_ < 31) {
      failedProbes_++;
    }
  }
  // sensorProbeDelayMs: 2 s, doubling per failed probe, capped at 60 s.
  uint32_t sensorProbeDelayMs() const {
    const uint32_t n = failedProbes_;
    if (n >= 5) return kSensorProbeMaxMs;  // 2 s << 5 = 64 s
    const uint32_t d = kSensorProbeMinMs << n;
    return d > kSensorProbeMaxMs ? kSensorProbeMaxMs : d;
  }

  // --- the punch buffer (setup(), then the scan task) ------------------
  void setBufferOpened(bool ok) { bufferOk_ = ok && !bufferFailed_; }
  void noteBufferWriteFailed() {
    bufferFailed_ = true;
    bufferOk_ = false;
  }

  // --- the device secret (setup(), then the net task) ------------------
  void setProvisioned(bool p) { provisioned_ = p; }

  bool sensorOk() const { return sensorOk_; }
  bool bufferOk() const { return bufferOk_; }
  bool provisioned() const { return provisioned_; }

  TerminalState state() const {
    switch (phase_.load()) {
      case Phase::Boot: return TerminalState::Boot;
      case Phase::SelfTest: return TerminalState::SelfTest;
      case Phase::Running: break;
    }
    if (!sensorOk_ || !bufferOk_) return TerminalState::Fault;  // fault wins
    if (!provisioned_) return TerminalState::Provision;
    return TerminalState::Ready;
  }

 private:
  enum class Phase : uint8_t { Boot, SelfTest, Running };
  std::atomic<Phase> phase_{Phase::Boot};
  std::atomic<bool> sensorOk_{false};
  std::atomic<bool> bufferOk_{false};
  std::atomic<bool> bufferFailed_{false};
  std::atomic<bool> provisioned_{false};
  std::atomic<uint8_t> commErrors_{0};
  std::atomic<uint8_t> failedProbes_{0};
};

}  // namespace presence
