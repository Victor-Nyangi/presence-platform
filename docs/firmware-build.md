# Firmware: first ESP32 toolchain build

**2026-10-11. Built and measured with no hardware attached.** Nothing here has run on a board.

## Toolchain

| | |
|---|---|
| PlatformIO Core | 6.2.0 |
| Platform | espressif32 6.13.0 (pinned `^6.9.0`) |
| Framework | framework-arduinoespressif32 3.20017.241212 (Arduino core 2.0.17, ESP-IDF v4.4.7) |
| Toolchain | xtensa-esp32 8.4.0+2021r2-patch5, esptool 4.11.0 |
| Libraries | Adafruit Fingerprint 2.1.4, RTClib 2.1.4 (+ BusIO 1.17.4), ArduinoJson 7.4.3 |
| Board | `esp32dev`, 4 MB flash |
| Partition table | `min_spiffs.csv` |

`pio run` succeeds for `esp32dev` and `esp32dev-debug`, with zero warnings and no source changes.
The only edit was in `platformio.ini`: `esp32dev-debug` inherited `-DCORE_DEBUG_LEVEL=2` and then
added `=5`, so every translation unit warned about a redefinition. It now unflags the inherited
value. The effective level was 5 before the edit and still is.

## Size

| | `esp32dev` | `esp32dev-debug` |
|---|---|---|
| Flash (app) | 746,909 B (38.0% of the slot) | 779,053 B (39.6%) |
| `firmware.bin` | 748,448 B | — |
| Static RAM | 39,812 B of 327,680 (12.1%) | 39,812 B |

Static RAM leaves out the FreeRTOS task stacks (8 + 4 + 16 KB) and the heap that WiFi/TLS allocate at runtime.

## OTA slack

The OTA app slot is `0x1E0000` = 1,966,080 B. **Free: 1,217,632 B, or 61.9% of the slot.**

| Scheme | App slot | Free after the 748,448 B image | Filesystem |
|---|---|---|---|
| `min_spiffs.csv` (current) | 1,966,080 | 1,217,632 (61.9%) | 128 KiB |
| custom, 2 × `0x180000` | 1,572,864 | 824,416 (52.4%) | 896 KiB |
| `default.csv` | 1,310,720 | 562,272 (42.9%) | 1,408 KiB |

Not yet in the image, and all of it will grow it: OTA download/verify, Ed25519, command handling, the display/RFID drivers.

## Ring-buffer capacity

`setup()` constructs the buffer: `LittleFsStorage::begin()` → `ringCapacityBytes(total, used, 0, 8 KiB, 256)`.
On a freshly formatted partition, `usedBytes()` is 2 blocks (8,192 B) for littlefs's superblock pair.

| Scheme | FS blocks | `ringCapacityBytes` computes | Largest ring that survives an in-place rewrite |
|---|---|---|---|
| `min_spiffs.csv` | 32 | 1,911 records (114,660 B) | 1,022 records |
| custom 896 KiB FS | 224 | 15,018 | 7,563 |
| `default.csv` | 352 | 23,756 | 11,923 |

**What is confirmed:** the partition sizes come from the CSV the build used, and the arithmetic is
`ringCapacityBytes`, which the host tests cover.

**What is an estimate:** the `usedBytes()` figure, and so the exact record count. Only the
`punch buffer: N records` line on a real board is authoritative.

### Finding: the computed size faults on the first punch (emulated, not yet seen on a board)

littlefs is copy-on-write. Rewriting a file at offset X copies everything from X to end-of-file into
newly allocated blocks before freeing the old ones. A write at offset 0 therefore needs a whole
file's worth of free blocks.

`ringCapacityBytes` holds back only `kRingReserveBytes` (8 KiB) on top of the file. Under
`min_spiffs`, preallocation fills 31 of 32 blocks, and it succeeds. Then the first `append()`
(offset 0) fails with `LFS_ERR_NOSPC`. `append()` returns false, the red LED fires, and the
terminal enters `State::Fault`.

Every scheme above fails the same way. The ratio holds, so a bigger partition does not fix it:
a ring only works up to roughly half the filesystem.

That fault is the designed response to a failed write, so no punch is falsely confirmed and no
invariant is broken. The terminal still can't record a punch.

Even at a size that works, each append rewrites on average half the file. At 1,022 records the
emulation shows 8 block erases per punch on average and 16 in the worst case. That cost sits on
the scan path before the green light, and it wears flash at that rate. Latency is an **estimate**
that needs a board: tens of ms per 4 KB erase puts it in the hundreds of ms per punch.

This is a design decision, not a mechanical fix, so it is left open:
- Cap the ring at what an in-place rewrite can afford (about half the FS).
- Put the ring on a raw data partition through `esp_partition_*`, bypassing littlefs.
- Split the ring into per-block files, so a rewrite copies at most one block.

Reproduce: `pip install littlefs-python && python firmware/tools/littlefs_ring_sim.py 0x20000`.
The script mirrors `littlefs_storage.h` using the framework's `CONFIG_LITTLEFS_*` geometry. Its
littlefs (2.11) is newer than the framework's precompiled `esp_littlefs` (41873c2). Copy-on-write
on mid-file writes is longstanding littlefs v2 behaviour, but a board run is what settles it.
