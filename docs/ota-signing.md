# OTA signing: the release key and how to handle it

SPEC §3, *OTA is a security boundary*: a terminal boots a new image only if a detached
Ed25519 signature over that image and its version verifies against a public key compiled
into the firmware it is already running, and only if that version is newer than anything it
has run. Whoever holds the matching private key can run code on every terminal in every
school and hospital. Everything here protects that key.

## What is signed and what is checked

| | |
|---|---|
| Scheme | Pure Ed25519 (RFC 8032), not Ed25519ph, not a signature over the sha256 |
| Message | A preamble naming the version and size, then the exact bytes of `firmware.bin` (below) |
| Version | `MAJOR.MINOR.PATCH`, each 0-65535, no leading zeros, no suffix; compared numerically |
| Encoding | `signature` is 128 lowercase hex characters, `sha256` is 64 (`docs/openapi.yaml`) |
| Signer | `gateway/cmd/fwsign` (Go `crypto/ed25519`) |
| Verifier | `firmware/src/ota_verify.h`, on vendored Monocypher 4.0.2 (`firmware/lib/monocypher/VENDORED`) |
| Downgrade and rollback | `firmware/src/ota_guard.h` |
| Trusted key | `kOtaReleasePublicKey` in `firmware/src/ota_pubkey.h` |

The signed message is

```
presence-ota-image/v1\n
version=0.2.0\n
size=775408\n
<the image bytes>
```

The preamble is never stored or sent. Both sides rebuild it from the manifest's `version` and
`size`. Because the version is signed, a validly signed old image cannot be relabelled as a
newer one: changing the number breaks the signature. The preamble's first line also separates
this scheme from the earlier signature over the bare image, so a signature made that way does
not verify.

On the terminal (`applyOta` in `firmware/src/main.cpp`), in this order:

1. Refuse at once if the compiled-in key is unusable (`isUnusableKey`) or the image is empty.
   Unusable means the all-zero *unprovisioned* sentinel or **any small-order point**, in any
   of its 14 encodings (8 canonical, 6 non-canonical). Monocypher's check is cofactored,
   `[8]([S]B − R − [h]A) = 0`, so under a small-order key the signature R = identity, S = 0
   verifies on every message; the host tests show the raw primitive accepting exactly that
   forgery under each encoding. A host test also fails if `ota_pubkey.h` ever holds a
   small-order key other than the sentinel, and `fwsign` refuses to sign for one.
2. **Downgrade check** (`OtaGuard::check`), before anything is erased. Refuse unless the signed
   version is strictly newer than the running build *and* strictly newer than the **floor** in
   NVS, which is the highest version that has ever proved healthy on this terminal. Also
   refuse an image that was installed once and rolled back (matched by sha256), and any update
   while the running image is itself still unconfirmed.
3. Refuse an image larger than the idle OTA slot. Stream the download into the idle slot; the
   running slot is never written.
4. `esp_ota_end`: an app-image format check, which catches a corrupt download. It is not the
   security check, because anyone can build a well-formed image.
5. **Read the slot back from flash** and run it through sha256 and Ed25519 (preamble, then
   image). The check covers the bytes that will boot, not a RAM copy of what arrived.
6. Record the update as pending in NVS, *then* `esp_ota_set_boot_partition`, then reboot. On
   any failure the slot's first sector is erased and otadata still points at the running
   image, so the terminal keeps the image it was running.

After the reboot the new image is `PENDING_VERIFY`. App rollback is enabled in this core's
bootloader (`CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`), and the sketch defines
`verifyRollbackLater()` so the Arduino core no longer marks the image valid at boot:

7. **The first successful gateway heartbeat confirms it.** `esp_ota_mark_app_valid_cancel_rollback`
   runs first, then the floor is raised to this version. The order matters: a power cut
   between the two leaves a valid image and a stale floor, which the next healthy boot fixes.
8. **No heartbeat within the confirm window** (10 minutes; 2 in `esp32dev-debug`): the terminal
   reboots without confirming. The bootloader marks the image aborted and boots the previous
   slot. A crash, watchdog reset or power cut inside the window does the same. The next boot
   notices that the pending version is not what is running, and records that image's sha256
   so it is never installed again.

   The deadline is an `esp_timer` one-shot armed at boot, not only the network task's
   `tick()`, because a broken image's likeliest failure is a hung network task, which would
   otherwise leave the image unconfirmed until a power cycle. The callback runs in the
   `esp_timer` task and only calls `esp_restart()`. That is safe in every state: a pending
   image rolls back; an image confirmed a moment earlier boots again as itself. The task
   watchdog was the alternative and was not chosen: the network task blocks for minutes by
   design (backoff, HTTP timeouts, the download), so it would need feeding at each of those
   points, and it would also reset a confirmed terminal whose network task merely stalled.
   `tick()` stays as the in-task path and the fallback if the timer cannot be armed.

The floor and the pending and rolled-back records are one NVS entry (`ota_state`), so they
cannot tear apart, the way the ring cursors cannot. The floor only rises. An older build on
the same NVS (a USB reflash, or the bootloader falling back past a corrupt slot) keeps
refusing everything at or below the newest version the terminal has run.

The two sides are pinned together the way the HMAC format is: a golden image, version,
public key and signature appear in both `firmware/test/host_test.cpp` and
`gateway/internal/fwsign/fwsign_test.go`. Its private key was generated in memory and never
written down. The version grammar is pinned by one table that both
`gateway/internal/fwversion` and the host tests run. The host tests also run the RFC 8032 §7.1
vectors, using only their public halves, and drive `OtaGuard` against a simulated two-slot
flash, bootloader and file-backed NVS.

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
  refuses to overwrite an existing file. `sign` and `pubkey` open the key file once, check
  the open handle (a regular file, owned by you, not readable by group or others, the way ssh
  does) and read from that same handle, so the file checked is the file read. The `.gitignore` is not what protects the key, and it
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

Every release is a version bump. Terminals refuse an image whose version is not strictly
greater than the one they run, so re-signing the same version, or publishing an older one to
undo a bad release, does nothing. To undo a release, ship a fix as a newer version.

1. **Bump `FIRMWARE_VERSION`** in `firmware/platformio.ini` (`-DFIRMWARE_VERSION=\"0.2.0\"`).
   It must be `MAJOR.MINOR.PATCH`. A `static_assert` in `main.cpp` refuses anything else, so a
   `-dev` suffix does not compile. Commit the bump.
2. **Keep stored formats readable by the previous release.** A release that fails to confirm
   boots the previous image against the same NVS and LittleFS. If the release changes the
   ring layout or an NVS entry, the previous build has to cope with it, or a rollback faults
   the terminal.
3. Build, sign and check:

```bash
cd firmware && pio run -e esp32dev && cd ..
IMG=firmware/.pio/build/esp32dev/firmware.bin
./.build/fwsign sign -key /media/ota-key/presence-ota-release.pem -image $IMG \
    -version 0.2.0 -header firmware/src/ota_pubkey.h > manifest-0.2.0.json
./.build/fwsign verify -image $IMG -manifest manifest-0.2.0.json -header firmware/src/ota_pubkey.h
```

`-header` makes `sign` fail if the key does not match the one the firmware compiles in, or if
that header still holds the sentinel or a small-order key. Without the check you can publish an image that every
terminal will refuse. `sign` and `verify` also read the version the image was built as (the
`PRESENCE_FW_VERSION=` marker every build carries) and fail if `-version` differs. A terminal
trusts the signed version, so an image signed under the wrong one would install, report its
real version, and be offered the same release on every heartbeat. `sign` verifies its own
output before printing it. Leave `-url` out: the gateway serves the image and fills in its
path. (`-url` is still accepted for an image hosted elsewhere, but the gateway refuses to
serve such a manifest.) The manifest JSON is written without HTML escaping, because the
firmware's JSON reader refuses `\u` escapes.

4. **Publish** to the gateway's release directory (`PRESENCE_FIRMWARE_DIR`), image first, then
   the manifest, each renamed into place so a request never sees half a file:

```bash
DIR=/srv/presence-firmware          # PRESENCE_FIRMWARE_DIR
SHA=$(sha256sum $IMG | cut -d' ' -f1)
install -D -m 0644 $IMG $DIR/images/$SHA.bin.tmp && mv $DIR/images/$SHA.bin.tmp $DIR/images/$SHA.bin
install -D -m 0644 manifest-0.2.0.json $DIR/stable/manifest.json.tmp \
    && mv $DIR/stable/manifest.json.tmp $DIR/stable/manifest.json
```

The layout is `<dir>/<channel>/manifest.json` and `<dir>/images/<sha256>.bin`. A device gets the
release on its `device.firmware_channel` (default `stable`; move a bench or pilot terminal
with `UPDATE device SET firmware_channel = 'beta' ...`). Images are named by their hash, so
promoting a release from `beta` to `stable` is copying the manifest. The gateway re-reads the
manifest on each request (no restart), refuses one whose image is missing or whose size or
sha256 does not match, and checks the image against its name before streaming it. It never
signs, builds or alters an image. `PRESENCE_FIRMWARE_DIR` unset means no releases: every
device is told `available: false`. Set but missing, the gateway does not start.

5. **Watch the rollout** in heartbeats (`device.firmware_version`). A terminal that installs the
   image and then cannot reach the gateway goes back to the previous version within about ten
   minutes and does not take that image again; it shows up still reporting the old version.
   To stop a rollout, delete the channel's `manifest.json`.

The image download is `GET /v1/device/firmware/images/{sha256}`, HMAC-signed like every other
device call. The gateway extends the write deadline for it to 10 minutes, since the server's
30-second `WriteTimeout` does not cover ~775 KB over a school's uplink.

## Rotating the key

A terminal trusts exactly one key: the one in the build it is running. So a rotation is a
release, signed with the old key, that carries the new key:

1. `fwsign keygen` a new key onto new encrypted media.
2. Put the **new** public key in `ota_pubkey.h` and bump `FIRMWARE_VERSION`, as for any release.
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
`applyOta`, key check and downgrade check as the network path. It also adds `OTA STATUS` and
`OTA HEALTHY` commands (`serial_ota.py --status` and `--confirm`), so the confirm and rollback
paths can be driven on a board with no Wi-Fi (see *Verifying on hardware*). `OTA HEALTHY`
confirms an image without a gateway, which is no more than anyone at the USB port can already
do with esptool, and it exists only in that env.

## Verifying on hardware

None of this has been run on a board. A freshly erased bench board has no Wi-Fi (it opens the
setup portal instead; see *Known gaps*), so the serial loader stands in for the network path,
and `serial_ota.py --confirm` stands in for the first gateway heartbeat. The `esp32dev-debug` env shortens the confirm window to 2 minutes.
Keys and images go outside the repo (here `~/ota-bench/`):

```bash
make build
mkdir -p ~/ota-bench
./.build/fwsign keygen -out ~/ota-bench/bench.pem     # paste the printed key into ota_pubkey.h
./.build/fwsign keygen -out ~/ota-bench/other.pem     # a second key, for the wrong-key case
cd firmware && pio run -e esp32dev-debug -t erase && cd ..   # clean NVS: floor 0.0.0

# Build five images. For each version V in 0.1.0 0.1.1 0.1.2 0.1.3 0.1.4: set
# -DFIRMWARE_VERSION=\"V\" in platformio.ini, then
cd firmware && pio run -e esp32dev-debug && cd ..
cp firmware/.pio/build/esp32dev-debug/firmware.bin ~/ota-bench/V.bin
./.build/fwsign sign -key ~/ota-bench/bench.pem -image ~/ota-bench/V.bin -version V \
    -header firmware/src/ota_pubkey.h > ~/ota-bench/V.json

# Flash 0.1.0 over USB (set the version back to 0.1.0 first):
cd firmware && pio run -e esp32dev-debug -t upload && cd ..
./.build/fwsign sign -key ~/ota-bench/other.pem -image ~/ota-bench/0.1.1.bin -version 0.1.1 > ~/ota-bench/wrong-key.json

S="uvx --with pyserial python firmware/tools/serial_ota.py --port /dev/ttyUSB0"
B="$S --image $HOME/ota-bench"   # then append V.bin --manifest ~/ota-bench/V.json
```

Boot line: `presence terminal 0.1.0, running from app0`, then `OTA: version floor 0.0.0`.
Close `pio device monitor` while `serial_ota.py` runs, and open it between steps to read the
boot lines. Each rejection prints `REJECTED: <reason>`.

| # | Do | Expect |
|---|---|---|
| 1 | `$B/0.1.1.bin --manifest ~/ota-bench/0.1.1.json --flip-byte 400000 --expect-reject` | `sha256 does not match manifest` |
| 2 | same, plus `--recompute-sha256` | `bad signature` |
| 3 | `$B/0.1.1.bin --manifest ~/ota-bench/wrong-key.json --expect-reject` | `bad signature` |
| 4 | `$B/0.1.0.bin --manifest ~/ota-bench/0.1.0.json --expect-reject` | **equal version:** `not newer than the running version`, at once, no transfer |
| 5 | `$B/0.1.0.bin --manifest ~/ota-bench/0.1.0.json --claim-version 0.1.9 --expect-reject` | **relabelled old image:** passes the version check, transfers, then `bad signature` |
| 6 | `$B/0.1.1.bin --manifest ~/ota-bench/0.1.1.json` | `ACCEPTED`; reboots to `0.1.1, running from app1` and `OTA: new image pending; rolls back unless the gateway answers within 120 s` |
| 7 | within 2 minutes: `$S --confirm` | `OTA CONFIRMED running=0.1.1 floor=0.1.1 awaiting=0`; press reset: boots `0.1.1` from `app1`, no pending line, `version floor 0.1.1` |
| 8 | `$B/0.1.0.bin --manifest ~/ota-bench/0.1.0.json --expect-reject` | **replayed older image:** `not newer than the running version` |
| 9 | `$B/0.1.2.bin --manifest ~/ota-bench/0.1.2.json`, then do nothing | reboots to `0.1.2, running from app0`, pending; after 120 s `OTA: new image not confirmed in time, rolling back`, then `0.1.1, running from app1` and `the last update did not stay booted` |
| 10 | `$S --status`, then step 9's command again with `--expect-reject` | `floor=0.1.1 bad=<first 8 hex of 0.1.2's sha256>`; `this image was rolled back before`, at once |
| 11 | `$B/0.1.3.bin --manifest ~/ota-bench/0.1.3.json`, then press reset within 2 minutes | **power cut in the window:** back on `0.1.1` from `app1`, `did not stay booted` |
| 12 | USB-flash 0.1.0 again *without* erasing (`pio run -e esp32dev-debug -t upload` with 0.1.0), then `$S --status` | **floor survives a reboot and a reflash:** `running=0.1.0 floor=0.1.1` |
| 13 | `$B/0.1.1.bin --manifest ~/ota-bench/0.1.1.json --expect-reject` | newer than 0.1.0 but `not newer than the version floor` |
| 14 | `$B/0.1.4.bin --manifest ~/ota-bench/0.1.4.json`, then do nothing | rollback on the **first update after a USB flash**: otadata has no entry for app0, so `esp_ota_mark_app_invalid_rollback_and_reboot` refuses (level-5 log `Rollback is not possible`) and the plain restart must still land on `0.1.0, running from app0` |

Steps 9 and 14 take the two different rollback paths in `EspBootControl::rollback`; step 14 is
the one that depends on the bootloader booting `ota_0` when no otadata entry is selectable,
which is read from the IDF 4.4 source and not yet seen on a board. Also watch the transfer
time (about 70 s at 115200 baud) and the read-back time between the last chunk and the
verdict. That read-back is the on-device Ed25519 cost, which has not been measured anywhere
yet.

Afterwards, put the sentinel (or the release key) back in `ota_pubkey.h`, restore
`FIRMWARE_VERSION`, erase the board (`pio run -e esp32dev-debug -t erase`) so its NVS does not
carry the bench floor, and delete `~/ota-bench/`.

## Known gaps

These are outside what this change does, and they are written down so nobody assumes
otherwise:

- **Not run on a board.** Downgrade protection, rollback and the gateway endpoint are
  host-tested and the gateway side is tested end to end against Postgres; the hardware steps
  above have not been run.
- **Wi-Fi comes from the SoftAP setup portal (2026-10-18), also not run on a board.** Until a
  board has joined a network through it ([`wifi-provisioning.md`](wifi-provisioning.md)), the
  bench serial loader remains the test path. On a board with no Wi-Fi a new image can never
  send a heartbeat, so without `--confirm` it always rolls back, which is the safe failure.
- **The floor is software, in NVS.** It stops a replayed image over the air. It does not stop
  someone with USB access, who can erase NVS or flash anything; that needs secure boot and
  eFuse anti-rollback (`CONFIG_BOOTLOADER_APP_ANTI_ROLLBACK`, off in this core's sdkconfig and
  not changeable without building the bootloader from ESP-IDF).
- **Healthy means "reached the gateway".** The confirm proves Wi-Fi, TLS, the clock and the
  HMAC secret work. A release that breaks the fingerprint sensor but still heartbeats is
  confirmed. A gateway outage during the confirm window rolls a good release back, and that
  image is not retried; publish a newer version.
- **One trusted key.** Two key slots (current and next) would let you stage a rotation in an
  ordinary release and recover from a compromise faster. That is not built.
