# OTA signing: the release key and how to handle it

SPEC §3, *OTA is a security boundary*: a terminal boots a new image only if a detached
Ed25519 signature over that image verifies against a public key compiled into the firmware
it is already running. Whoever holds the matching private key can run code on every terminal
in every school and hospital. Everything here protects that key.

## What is signed and what is checked

| | |
|---|---|
| Scheme | Pure Ed25519 (RFC 8032), not Ed25519ph, not a signature over the sha256 |
| Message | The exact bytes of `firmware.bin` as served from the manifest's `url` |
| Encoding | `signature` is 128 lowercase hex characters, `sha256` is 64 (`docs/openapi.yaml`) |
| Signer | `gateway/cmd/fwsign` (Go `crypto/ed25519`) |
| Verifier | `firmware/src/ota_verify.h`, on vendored Monocypher 4.0.2 (`firmware/lib/monocypher/VENDORED`) |
| Trusted key | `kOtaReleasePublicKey` in `firmware/src/ota_pubkey.h` |

On the terminal (`applyOta` in `firmware/src/main.cpp`), in this order:

1. Refuse at once if the compiled-in key is the all-zero *unprovisioned* sentinel, the image
   is empty, or it is larger than the idle OTA slot.
2. Stream the download into the idle slot. The running slot is never written.
3. `esp_ota_end`: an app-image format check, which catches a corrupt download. It is not the
   security check, because anyone can build a well-formed image.
4. **Read the slot back from flash** and run it through sha256 and Ed25519. The check covers
   the bytes that will boot, not a RAM copy of what arrived.
5. Only if both pass: `esp_ota_set_boot_partition`, then reboot. On any failure the slot's
   first sector is erased and otadata still points at the running image, so the terminal
   keeps the image it was running.

The two sides are pinned together the way the HMAC format is: a golden image, public key and
signature appear in both `firmware/test/host_test.cpp` and
`gateway/internal/fwsign/fwsign_test.go`. Its private key was generated in memory and never
written down. The host tests also run the RFC 8032 §7.1 vectors, using only their public
halves.

## Where the private key lives

**Offline. Never in this repository, never in CI, never on the gateway.** The gateway only
serves the manifest and the image. It never signs, so a compromised gateway can withhold
updates but cannot forge one.

- Generate it on a machine you trust (ideally one that is offline while you do it) and write
  it straight to **an encrypted USB stick** (LUKS or VeraCrypt) that is not normally plugged
  in.
- Make **a second encrypted copy** and store it in a different physical place. Losing the
  key is nearly as bad as leaking it: without it, the only way to update a deployed terminal
  is to drive to it with a USB cable.
- Keep it out of cloud-synced folders, password-manager attachments that sync to a phone,
  dotfiles repos and shell history.
- `fwsign` enforces part of this. `keygen` refuses to write inside any git work tree and
  refuses to overwrite an existing file. `sign` and `pubkey` refuse a key file that group or
  others can read, the way ssh does. The `.gitignore` is not what protects the key, and it
  shouldn't be.

The public key is not secret. It is committed in `ota_pubkey.h` and compiled into every
build.

## First-time setup (before device #3 leaves the desk)

`ota_pubkey.h` ships with the all-zero sentinel. A build with the sentinel boots, buffers and
uploads normally, prints `WARNING: no OTA release key compiled in` at boot, and refuses
every update. That is the safe failure, but a terminal that leaves the desk in that state
can only ever be updated by hand.

```bash
make build                                   # builds .build/fwsign among the rest
# with the encrypted stick mounted at /media/ota-key:
./.build/fwsign keygen -out /media/ota-key/presence-ota-release.pem
```

`keygen` prints the public key and a ready-made `kOtaReleasePublicKey` initializer. Paste
the initializer into `firmware/src/ota_pubkey.h`, commit it, and build. From that build on,
the terminal trusts that key and no other. Unmount the stick, then make the second copy.

## Releasing an image

```bash
cd firmware && pio run -e esp32dev && cd ..
./.build/fwsign sign \
    -key /media/ota-key/presence-ota-release.pem \
    -image firmware/.pio/build/esp32dev/firmware.bin \
    -version 0.2.0 \
    -url https://<where the image is hosted>/presence-0.2.0.bin \
    -header firmware/src/ota_pubkey.h > manifest-0.2.0.json
./.build/fwsign verify -image firmware/.pio/build/esp32dev/firmware.bin \
    -manifest manifest-0.2.0.json -header firmware/src/ota_pubkey.h
```

`-header` makes `sign` fail if the key does not match the one the firmware compiles in, or if
that header still holds the sentinel. Without the check you can publish an image that every
terminal will refuse. `sign` also verifies its own output before printing it. `-version`
must match the `FIRMWARE_VERSION` the image reports, or the terminal will keep fetching
it. The manifest JSON is written without HTML escaping, because the firmware's JSON reader
refuses `\u` escapes, including the `\u0026` Go would otherwise write for `&`.

Publish the image and serve the manifest from `GET /v1/device/firmware`. **The gateway does
not serve that endpoint yet** (see *Known gaps*).

## Rotating the key

A terminal trusts exactly one key: the one in the build it is running. So a rotation is a
release, signed with the old key, that carries the new key:

1. `fwsign keygen` a new key onto new encrypted media.
2. Put the **new** public key in `ota_pubkey.h` and bump `FIRMWARE_VERSION`.
3. Sign that build with the **old** key (skip `-header` for this one release, since the
   header now holds the new key, and run `fwsign verify -pub <old key hex>` instead).
4. Roll it out. Confirm from heartbeats (`device.firmware_version`) that **every** terminal
   is on it. A terminal that missed this release still trusts only the old key.
5. Sign every release from then on with the new key. Retire the old key only after step 4 is
   complete. Destroy it if it was compromised; otherwise archive it until no terminal running
   an older build could ever come back online.

**If the key is compromised**, rotate the same way, immediately. Know what that buys you,
though. Until a terminal takes the rotation release, the attacker can sign images it will
accept, including one that installs the attacker's own key. A terminal that already took a
malicious image is only recovered by reflashing it over USB.

**If the key is lost** (both copies), no deployed terminal can be updated over the air
again. Each one needs a USB reflash with a build that carries a new key.

## Bench keys

A key you generate to try OTA on the desk is a **bench key**, not the release key. Keep it
outside the repository like any other key, and never let a build that trusts it leave the
desk. A terminal built with a bench key will accept anything signed by whoever has a copy of
that file. Before device #3 ships, check that `ota_pubkey.h` holds the release key.

The `esp32dev-debug` env adds `PRESENCE_BENCH_SERIAL_OTA`, so the terminal also accepts
images over USB serial (`firmware/tools/serial_ota.py`). It goes through the same
`applyOta` and the same key check as the network path. The point is to prove the gate on a
board before the gateway serves manifests (see *Verifying on hardware*).

## Verifying on hardware

This has never been run on a board. Keys go outside the repo (here `~/ota-bench/`):

```bash
make build
./.build/fwsign keygen -out ~/ota-bench/bench.pem     # paste the printed key into ota_pubkey.h
./.build/fwsign keygen -out ~/ota-bench/other.pem     # a second key, for the wrong-key case

# Image A: flashed over USB. Its boot line reads "presence terminal 0.1.0, running from app0".
cd firmware && pio run -e esp32dev-debug -t upload && cd ..

# Image B: set -DFIRMWARE_VERSION=\"0.1.1\" in platformio.ini, rebuild, do NOT upload.
cd firmware && pio run -e esp32dev-debug && cd ..
IMG=firmware/.pio/build/esp32dev-debug/firmware.bin
./.build/fwsign sign -key ~/ota-bench/bench.pem -image $IMG -version 0.1.1 \
    -url https://bench.invalid/b.bin -header firmware/src/ota_pubkey.h > ~/ota-bench/good.json
./.build/fwsign sign -key ~/ota-bench/other.pem -image $IMG -version 0.1.1 \
    -url https://bench.invalid/b.bin > ~/ota-bench/wrong-key.json

S="uvx --with pyserial python firmware/tools/serial_ota.py --port /dev/ttyUSB0 --image $IMG"
$S --manifest ~/ota-bench/good.json --flip-byte 400000 --expect-reject                     # sha256 mismatch
$S --manifest ~/ota-bench/good.json --flip-byte 400000 --recompute-sha256 --expect-reject  # bad signature
$S --manifest ~/ota-bench/wrong-key.json --expect-reject                                   # bad signature
$S --manifest ~/ota-bench/good.json                                                        # accepted
```

Each rejection prints `REJECTED: <reason>`. Press reset afterwards: the boot line must still
read `0.1.0, running from app0`. After the accepted transfer the terminal reboots by itself
and must read `0.1.1, running from app1`. Watch the transfer time (about 70 s at 115200 baud)
and the read-back time between the last chunk and the verdict. That read-back is the
on-device Ed25519 cost, which has not been measured anywhere yet.

Afterwards, put the sentinel (or the release key) back in `ota_pubkey.h` and delete
`~/ota-bench/`.

## Known gaps

These are outside what this change does, and they are written down so nobody assumes
otherwise:

- **No downgrade protection.** The signature covers the image, not "this version or newer",
  so a validly signed *older* image can be replayed. ESP-IDF anti-rollback
  (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`) is off in the Arduino core's sdkconfig. A
  monotonic version check on the terminal is the cheap mitigation.
- **New images are marked valid at boot.** The bootloader has app rollback enabled, but the
  Arduino core calls `esp_ota_mark_app_valid_cancel_rollback()` from `initArduino()` unless
  the sketch defines `verifyRollbackLater()` to return true. As things stand, a signed image
  that boots but can no longer reach the gateway does not roll back. The fix is to define
  that hook and mark the image valid after the first successful heartbeat.
- **The gateway does not serve `GET /v1/device/firmware`** and always reports
  `firmware_available: false`, so the network path is wired but unreachable. The terminal
  also never calls `WiFi.begin()` yet. Until both exist, the bench serial loader is the only
  way to exercise OTA.
- **One trusted key.** Two key slots (current and next) would let you stage a rotation in an
  ordinary release and recover from a compromise faster. That is not built.
