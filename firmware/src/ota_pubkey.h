// ota_pubkey.h — the release public key every OTA image is checked against.
//
// PUBLIC half only. The private key is generated and kept OFFLINE, never in
// this repository; see docs/ota-signing.md for where it lives, how to
// generate it, and how to rotate it.
//
// ALL ZEROS MEANS "NOT PROVISIONED": the terminal refuses every update and
// says so at boot. That fails closed -- an unprovisioned build can still be
// flashed over USB, it just cannot be updated over the air. Replace this with
// the output of `fwsign keygen` (or `fwsign pubkey -key <path>`) before a
// terminal leaves the desk; a device that ships with the sentinel can only
// ever be updated by physically touching it.
//
// Changing this key is a rotation, not an edit: images signed with the old
// key stop verifying on every terminal running the new build. Follow the
// rotation procedure in docs/ota-signing.md.
#pragma once

#include <stdint.h>

namespace presence {

static const uint8_t kOtaReleasePublicKey[32] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

}  // namespace presence
