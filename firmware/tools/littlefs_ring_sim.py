"""Emulate LittleFsStorage's write pattern on a real littlefs, on the host.

    pip install littlefs-python
    python firmware/tools/littlefs_ring_sim.py 0x20000      # min_spiffs.csv
    python firmware/tools/littlefs_ring_sim.py 0x160000     # default.csv

Mirrors firmware/src/littlefs_storage.h + ring_buffer.h: size the ring with
ringCapacityBytes(total, used, 0, 8 KiB, 256), preallocate it in 480-byte
zero chunks, reopen "r+", then append = seek + 60-byte write + sync (what
File::flush() does: fflush + fsync). Filesystem geometry and caches are the
CONFIG_LITTLEFS_* values from arduino-esp32 2.0.17's sdkconfig.

It answers one question a board would otherwise have to: does a ring file
sized by ringCapacityBytes survive being rewritten in place? littlefs is
copy-on-write, so a write at offset X re-copies the file from X to EOF into
fresh blocks before the old ones are freed; offset 0 needs a whole file's
worth of free blocks. The library is newer than the one in the framework, so
the result is an emulation, not a measurement.
"""
import sys

from littlefs import LittleFS, UserContext, lfs

REC = 60                # sizeof(PunchRecord)
RESERVE = 8 * 1024      # kRingReserveBytes
MIN_RECORDS = 256       # kRingMinRecords
BLOCK = 4096


class CountingContext(UserContext):
    def __init__(self, n):
        super().__init__(n)
        self.erases = 0

    def erase(self, cfg, block):
        self.erases += 1
        return super().erase(cfg, block)


def ring_capacity_bytes(total, used, existing, reserve, min_records):
    # Same arithmetic as presence::ringCapacityBytes.
    if used > total:
        return 0
    available = (total - used) + existing
    if available <= reserve:
        return 0
    records = (available - reserve) // REC
    if records < min_records:
        return 0
    return records * REC


def fresh_fs(partition_bytes):
    ctx = CountingContext(partition_bytes)
    fs = LittleFS(context=ctx, block_size=BLOCK, block_count=partition_bytes // BLOCK,
                  read_size=128, prog_size=128, cache_size=512, lookahead_size=128,
                  block_cycles=512, name_max=64, mount=True)
    return fs, ctx


def computed_records(partition_bytes):
    fs, _ = fresh_fs(partition_bytes)
    total = fs.block_count * BLOCK
    used = fs.used_block_count * BLOCK  # LittleFS.usedBytes() = lfs_fs_size * block
    return ring_capacity_bytes(total, used, 0, RESERVE, MIN_RECORDS) // REC


def survives(partition_bytes, records, offsets):
    """Preallocate `records` slots, then append at each offset. True if all succeed."""
    fs, ctx = fresh_fs(partition_bytes)
    try:
        with fs.open("/punches.bin", "wb") as f:
            remaining = records * REC
            while remaining:
                chunk = min(remaining, REC * 8)
                f.write(bytes(chunk))
                remaining -= chunk
        fh = lfs.file_open(fs.fs, "/punches.bin", "r+")
        erases = []
        for off in offsets:
            before = ctx.erases
            lfs.file_seek(fs.fs, fh, off, 0)
            lfs.file_write(fs.fs, fh, bytes(REC))
            lfs.file_sync(fs.fs, fh)
            erases.append(ctx.erases - before)
        return True, erases
    except Exception as e:  # LittleFSError -28 is LFS_ERR_NOSPC
        return False, str(e)


def worst_case_ok(partition_bytes, records):
    # Offset 0 copies the whole file, so it is the most space a write needs.
    return survives(partition_bytes, records, [0, 0, 0])[0]


def main():
    part = int(sys.argv[1], 0)
    n = computed_records(part)
    ok, detail = survives(part, n, [0])
    print(f"partition {part} B: ringCapacityBytes -> {n} records ({n * REC} B)")
    print(f"  first append at offset 0: {'ok' if ok else 'FAILS: ' + detail}")

    lo, hi = MIN_RECORDS, n
    if not worst_case_ok(part, lo):
        print("  no ring size >= kRingMinRecords survives an in-place rewrite")
        return
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if worst_case_ok(part, mid):
            lo = mid
        else:
            hi = mid - 1
    print(f"  largest ring that survives rewriting offset 0: {lo} records ({lo * REC} B)")

    if lo <= 4096:  # a full lap is cheap enough to run on small partitions
        offsets = [(i % lo) * REC for i in range(2 * lo)]
        ok, erases = survives(part, lo, offsets)
        if ok:
            print(f"  two full laps at that size: ok, {sum(erases) / len(erases):.1f} "
                  f"block erases per append on average, {max(erases)} worst case")
        else:
            print(f"  two full laps at that size: FAILS: {erases}")


if __name__ == "__main__":
    main()
