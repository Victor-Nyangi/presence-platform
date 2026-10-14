# Firmware: first ESP32 toolchain build

**2026-10-11. Built and measured with no hardware attached.** Nothing here has run on a board.
Updated the same day for the copy-on-write ring cap (option (a) below); figures marked *was* are
from the first build.

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
| Flash (app) | **773,869 B (39.4% of the slot)**; 769,449 before rollback, 747,089 before OTA | **822,745 B (41.8%)**; 815,601 before rollback, 779,337 before OTA |
| `firmware.bin` | **775,408 B**; 770,992 before rollback, 748,624 before OTA | 824,288 B; 817,136 before rollback |
| Static RAM | 39,996 B of 327,680 (12.2%); 39,860 before rollback, 39,812 before OTA | 39,996 B |

**OTA verification (2026-10-14)** added 22,360 B of flash and 48 B of static RAM to `esp32dev`:
Ed25519 verification and SHA-512 from vendored Monocypher 4.0.2 (about 11 KB of its symbols),
plus the download, read-back and commit path in `main.cpp`. `esp32dev-debug` grew by 36,264 B,
because it also carries the bench serial loader (`PRESENCE_BENCH_SERIAL_OTA`) and level-5 log
strings. Both envs still build with zero warnings. Same toolchain as below, PlatformIO Core
6.2.0. Nothing has run on a board, so the time an Ed25519 check over a ~770 KB image takes on
the ESP32 is still unmeasured.

**OTA downgrade protection and rollback (2026-10-14, later the same day)** added 4,420 B of
flash and 136 B of static RAM to `esp32dev` (`firmware.bin` 770,992 → 775,408 B): the signed
version preamble, `ota_guard.h`, the NVS binding, the boot-confirm hook and the signed image
download. `esp32dev-debug` grew by 7,152 B (`firmware.bin` 817,136 → 824,288 B) with the bench
`OTA STATUS`/`OTA HEALTHY` commands. Both envs build with zero warnings, clean builds, same
toolchain.

The ring cap (2026-10-11) added 180 B of flash and no static RAM.

Static RAM leaves out the FreeRTOS task stacks (8 + 4 + 16 KB) and the heap that WiFi/TLS allocate at runtime.

## OTA slack

The OTA app slot is `0x1E0000` = 1,966,080 B. **Free: 1,190,672 B, or 60.6% of the slot**
(1,195,088 B / 60.8% before downgrade protection and rollback, 1,217,456 B / 61.9% before OTA
verification). `esp32dev-debug` leaves 1,141,792 B (58.1%).

| Scheme | App slot | Free after the 775,408 B image | Filesystem |
|---|---|---|---|
| `min_spiffs.csv` (current) | 1,966,080 | 1,190,672 (60.6%) | 128 KiB |
| custom, 2 × `0x180000` | 1,572,864 | 797,456 (50.7%) | 896 KiB |
| `default.csv` | 1,310,720 | 535,312 (40.8%) | 1,408 KiB |

Now in the image: OTA download (signed, from the gateway), flash read-back, sha256 and
Ed25519 verification over the version preamble and image, the downgrade floor and the
boot-confirm rollback (`docs/ota-signing.md`). Not yet in it, and all of these will grow it: command handling, Wi-Fi
bring-up, and the display/RFID drivers.

## Ring-buffer capacity

`setup()` constructs the buffer: `LittleFsStorage::begin()` →
`ringCapacityBytes(4096, totalBytes / 4096, usedBytes, 0, kRingSlackBlocks = 2, 256)`.
On a freshly formatted partition, `usedBytes()` is 2 blocks (8,192 B) for littlefs's superblock pair.

The ring is sized so that littlefs can always rewrite it in place:

```
ring_blocks = (block_count - metadata_blocks - slack_blocks) / 2
capacity    = ring_blocks * (block_size - 8), rounded down to whole 60-byte records
```

- **Halved** because littlefs is copy-on-write: an append at offset 0 copies the whole file into
  new blocks before freeing the old ones, so the free space must hold a second copy of the file.
- **`metadata_blocks`** is everything on the partition that is not the ring file, read from
  `usedBytes()` rather than assumed (2 blocks on a fresh partition).
- **`slack_blocks` = 2**, one metadata pair, so littlefs can relocate a worn pair mid-commit while
  both copies of the file are live.
- **`block_size - 8`**: littlefs's CTZ skip-list costs fewer than two 4-byte pointers per block, so
  this is a strict lower bound on what a block holds and the file never spills into an extra block.

| Scheme | FS blocks | Was (all free space bar 8 KiB) | Now | Largest ring that survives an in-place rewrite (emulated) |
|---|---|---|---|---|
| `min_spiffs.csv` | 32 | 1,911 records — faults on first append | **953 records** (57,180 B, 16/32 blocks used) | 1,022 |
| custom 896 KiB FS | 224 | 15,018 — faults | **7,494** (449,640 B, 112/224 blocks used) | 7,563 |
| `default.csv` | 352 | 23,756 — faults | **11,855** (711,300 B, 176/352 blocks used) | 11,923 |

With zero slack the formula gives 1,022 / 7,562 / 11,923: it reproduces the emulated boundary to
within one record, which is the evidence that it models littlefs rather than merely being small
enough. The 2 slack blocks cost 69 / 68 / 68 records against that.

**What is confirmed:** the partition sizes come from the CSV the build used, and the arithmetic is
`ringCapacityBytes`, which the host tests cover for all three schemes (exact value, at or below the
emulated limit, within 10% of it, and a sweep over 4–1,024 blocks checking file + copy + metadata +
slack always fits).

**What is still pending: board confirmation.** The `usedBytes()` figure, and so the exact record
count, is an estimate until a board prints its `punch buffer: N records` boot line. Under
`min_spiffs` that line should read 953. A different number means `usedBytes()` on the device is not
the 2 blocks assumed here; the formula still adapts to it, but the table above would need updating.

### Upgrading a board that ran the earlier build

A ring file created by the earlier sizing can never take an append, and an existing file normally
keeps its size across boots. `begin()` therefore checks an existing file with `ringFileRewritable`
(free blocks ≥ the file's blocks + slack). One that fails and holds no unacknowledged records is
deleted and resized; since every append to such a file failed, that is the only state one can be
in. One that fails while holding records is kept, so they can still drain, and a failed append
still faults as designed.

### Finding: the original sizing faulted on the first punch (emulated, not yet seen on a board)

littlefs is copy-on-write. Rewriting a file at offset X copies everything from X to end-of-file into
newly allocated blocks before freeing the old ones. A write at offset 0 therefore needs a whole
file's worth of free blocks.

The original `ringCapacityBytes` held back only an 8 KiB reserve on top of the file. Under
`min_spiffs`, preallocation filled 31 of 32 blocks, and it succeeded. Then the first `append()`
(offset 0) failed with `LFS_ERR_NOSPC`. `append()` returned false, the red LED fired, and the
terminal entered `State::Fault`. Every scheme failed the same way: a ring only works up to roughly
half the filesystem.

That fault is the designed response to a failed write, so no punch was falsely confirmed and no
invariant was broken; the fix keeps that behaviour and changes only the size.

Three options were on the table, and the owner chose (a) on 2026-10-11:
- **(a) Cap the ring at what an in-place rewrite can afford (about half the FS).** Implemented above.
- (b) Put the ring on a raw data partition through `esp_partition_*`, bypassing littlefs.
- (c) Split the ring into per-block files, so a rewrite copies at most one block.

**Still open with (a): write cost.** Each append rewrites on average half the file. At the new
`min_spiffs` size the emulation shows 7.55 block erases per punch on average and 15
in the worst case; it scales with the ring, so larger partitions pay proportionally more (table
below). That cost sits on the scan path before the green light, and it wears flash at that rate.
Latency is an **estimate** that needs a board: tens of ms per 4 KB erase puts it in the hundreds of
ms per punch under `min_spiffs`, and seconds under the larger schemes. (b) or (c) is the route if
that proves too slow or too wearing.

### Emulation of the new sizing

`python firmware/tools/littlefs_ring_sim.py <partition> --laps N --search`
(`pip install littlefs-python`). It sizes the ring with the same arithmetic, preallocates it,
then appends at `(seq % slots) * 60` exactly as `RingBuffer::append` does, wrapping the ring N
times, and runs the old sizing as a control.

Run 2026-10-11 against littlefs-python's littlefs 2.11:

| Scheme | Old sizing (control) | New size | Appends run | `LFS_ERR_NOSPC` | Block erases per append: avg / worst / best |
|---|---|---|---|---|---|
| `min_spiffs` (`0x20000`) | 1,911 records, 31/32 blocks: **fails on append 1** | 953 records, 16/32 blocks | 2,859 (3 laps) | none | 7.55 / 15 / 1 |
| custom 896 KiB (`0xE0000`) | 15,018, 223/224: **fails on append 1** | 7,494, 112/224 | 9,367 (1.25 laps) | none | 63.79 / 111 / 1 |
| `default` (`0x160000`) | 23,756, 351/352: **fails on append 1** | 11,855, 176/352 | 14,818 (1.25 laps) | none | 100.59 / 175 / 1 |

`--search` found the largest ring that survives rewriting offset 0 unchanged at 1,022 / 7,563 /
11,923 records, 69 / 69 / 68 above the new sizes. The larger schemes ran 1.25 laps rather than 3
because each append there copies ~64–100 blocks in Python; the 1.25-lap averages lean high,
since the first lap starts at offset 0. A 30,000-append run at the `min_spiffs` boundary (1,022
records, zero slack) also completed without `LFS_ERR_NOSPC`, so the 2 slack blocks are margin, not
a measured necessity.

The script mirrors `littlefs_storage.h` using the framework's `CONFIG_LITTLEFS_*` geometry. Its
littlefs (2.11) is newer than the framework's precompiled `esp_littlefs` (41873c2). Copy-on-write
on mid-file writes is longstanding littlefs v2 behaviour, but a board run is what settles it.
