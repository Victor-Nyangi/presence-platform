"""Emulate LittleFsStorage's write pattern on a real littlefs, on the host.

    pip install littlefs-python
    python firmware/tools/littlefs_ring_sim.py 0x20000      # min_spiffs.csv
    python firmware/tools/littlefs_ring_sim.py 0xE0000      # custom, 896 KiB FS
    python firmware/tools/littlefs_ring_sim.py 0x160000     # default.csv
    python firmware/tools/littlefs_ring_sim.py 0x20000 --laps 3 --search

Mirrors firmware/src/littlefs_storage.h + ring_buffer.h: size the ring with
ringCapacityBytes(4096, blocks, used, 0, kRingSlackBlocks, 256), preallocate
it in 480-byte zero chunks, reopen "r+", then append = seek + 60-byte write +
sync (what File::flush() does: fflush + fsync), at (seq % slots) * 60 exactly
as RingBuffer::append does, so the run wraps the ring --laps times.
Filesystem geometry and caches are the CONFIG_LITTLEFS_* values from
arduino-esp32 2.0.17's sdkconfig.

It answers one question a board would otherwise have to: does a ring file
sized by ringCapacityBytes survive being rewritten in place, every slot,
lap after lap? littlefs is copy-on-write, so a write at offset X re-copies
the file from X to EOF into fresh blocks before the old ones are freed;
offset 0 needs a whole file's worth of free blocks. The previous sizing
(all free space bar 8 KiB) is run too, as the control: its first append
fails with LFS_ERR_NOSPC. The library is newer than the one in the
framework, so the result is an emulation, not a measurement.

Exits non-zero if the current sizing fails any append.
"""
import argparse
import sys

from littlefs import LittleFS, UserContext, lfs

REC = 60                # sizeof(PunchRecord)
MIN_RECORDS = 256       # kRingMinRecords
SLACK_BLOCKS = 2        # kRingSlackBlocks
CTZ_OVERHEAD = 8        # kLfsCtzOverheadPerBlock
BLOCK = 4096            # kLfsBlockSize (SPI_FLASH_SEC_SIZE)
OLD_RESERVE = 8 * 1024  # the pre-fix kRingReserveBytes, for the control run


class CountingContext(UserContext):
    def __init__(self, n):
        super().__init__(n)
        self.erases = 0

    def erase(self, cfg, block):
        self.erases += 1
        return super().erase(cfg, block)


def ring_capacity_bytes(block, blocks, used, existing, slack, min_records):
    # Same arithmetic as presence::ringCapacityBytes.
    if block <= CTZ_OVERHEAD or blocks == 0:
        return 0
    used_blocks = -(-used // block)
    if used_blocks > blocks:
        return 0
    reclaim = min(existing // block, used_blocks)
    metadata = used_blocks - reclaim
    if metadata + slack >= blocks:
        return 0
    ring_blocks = (blocks - metadata - slack) // 2
    records = ring_blocks * (block - CTZ_OVERHEAD) // REC
    if records == 0 or records < min_records:
        return 0
    return records * REC


def old_ring_capacity_bytes(total, used):
    # The pre-fix formula: all of the free space bar an 8 KiB reserve.
    available = total - used
    if available <= OLD_RESERVE:
        return 0
    records = (available - OLD_RESERVE) // REC
    return records * REC if records >= MIN_RECORDS else 0


def fresh_fs(partition_bytes):
    ctx = CountingContext(partition_bytes)
    fs = LittleFS(context=ctx, block_size=BLOCK, block_count=partition_bytes // BLOCK,
                  read_size=128, prog_size=128, cache_size=512, lookahead_size=128,
                  block_cycles=512, name_max=64, mount=True)
    return fs, ctx


def computed_records(partition_bytes):
    fs, _ = fresh_fs(partition_bytes)
    used = fs.used_block_count * BLOCK  # LittleFS.usedBytes() = lfs_fs_size * block
    new = ring_capacity_bytes(BLOCK, fs.block_count, used, 0, SLACK_BLOCKS, MIN_RECORDS)
    old = old_ring_capacity_bytes(fs.block_count * BLOCK, used)
    return new // REC, old // REC


def survives(partition_bytes, records, offsets):
    """Preallocate `records` slots, then append at each offset.

    Returns (True, per-append erase counts, blocks used after create), or
    (False, error text, blocks used) on the first failure.
    """
    fs, ctx = fresh_fs(partition_bytes)
    used = None
    erases = []
    try:
        with fs.open("/punches.bin", "wb") as f:
            remaining = records * REC
            while remaining:
                chunk = min(remaining, REC * 8)
                f.write(bytes(chunk))
                remaining -= chunk
        used = fs.used_block_count
        fh = lfs.file_open(fs.fs, "/punches.bin", "r+")
        for off in offsets:
            before = ctx.erases
            lfs.file_seek(fs.fs, fh, off, 0)
            lfs.file_write(fs.fs, fh, bytes(REC))
            lfs.file_sync(fs.fs, fh)
            erases.append(ctx.erases - before)
        return True, erases, used
    except Exception as e:  # LittleFSError -28 is LFS_ERR_NOSPC
        return False, f"{e} (after {len(erases)} appends)", used


def worst_case_ok(partition_bytes, records):
    # Offset 0 copies the whole file, so it is the most space a write needs.
    return survives(partition_bytes, records, [0, 0, 0])[0]


def largest_surviving(partition_bytes, hi):
    lo = MIN_RECORDS
    if not worst_case_ok(partition_bytes, lo):
        return 0
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if worst_case_ok(partition_bytes, mid):
            lo = mid
        else:
            hi = mid - 1
    return lo


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("partition", type=lambda v: int(v, 0), help="LittleFS partition size in bytes")
    ap.add_argument("--laps", type=float, default=2.0,
                    help="appends to run, in multiples of the ring's slot count (default 2)")
    ap.add_argument("--search", action="store_true",
                    help="also binary-search the largest ring that survives rewriting offset 0")
    args = ap.parse_args()

    part = args.partition
    n, old = computed_records(part)
    blocks = part // BLOCK
    print(f"partition {part} B ({blocks} blocks of {BLOCK})")

    ok, detail, used = survives(part, old, [0])
    print(f"  control, old sizing: {old} records ({old * REC} B), {used}/{blocks} blocks after create;"
          f" first append at offset 0: {'ok' if ok else 'FAILS: ' + detail}")

    if n == 0:
        print("  ringCapacityBytes -> 0: partition too small for kRingMinRecords")
        return 1
    appends = int(n * args.laps)
    offsets = [(seq % n) * REC for seq in range(appends)]
    ok, detail, used = survives(part, n, offsets)
    print(f"  ringCapacityBytes: {n} records ({n * REC} B), {used}/{blocks} blocks after create")
    if ok:
        erases = detail
        print(f"  {appends} appends ({args.laps:g} laps, wrapping at slot {n}): ok, no LFS_ERR_NOSPC")
        print(f"  block erases per append: {sum(erases) / len(erases):.2f} average, "
              f"{max(erases)} worst case, {min(erases)} best case")
    else:
        print(f"  {appends} appends: FAILS: {detail}")

    if args.search:
        lo = largest_surviving(part, max(n, old))
        print(f"  largest ring that survives rewriting offset 0: {lo} records ({lo * REC} B);"
              f" ringCapacityBytes is {lo - n} records under it")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
