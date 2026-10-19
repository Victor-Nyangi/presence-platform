#!/usr/bin/env python3
"""Prove the bench-only BENCH-SECRET command stays out of the release build.

BENCH-SECRET (firmware/src/bench_secret.h) writes a device secret into NVS
over USB. That is what a bench board needs while /v1/device/provision is a
501, and what a deployed terminal must not have, so it is compiled in only
under PRESENCE_BENCH_SERIAL_OTA, which only the esp32dev-debug env defines.

Two checks, both stdlib only:

  check_bench_only.py
      Source check, run by `make firmware-test` (and so by CI): the release
      env does not define the flag and the debug env does; main.cpp mentions
      the command's header and functions only inside an
      `#ifdef PRESENCE_BENCH_SERIAL_OTA` block; no other firmware source
      includes bench_secret.h. Then a self-test of the #if tracking.

  check_bench_only.py --release-bin <esp32dev firmware.bin> \\
                      --debug-bin <esp32dev-debug firmware.bin>
      Build check, after `pio run -e esp32dev -e esp32dev-debug`: the command
      string is absent from the release image and present in the debug one.
      Also runs the source check.
"""

import argparse
import configparser
import re
import sys
from pathlib import Path

FLAG = "PRESENCE_BENCH_SERIAL_OTA"
COMMAND = b"BENCH-SECRET"
# Code (not comments) in main.cpp that belongs to the command.
SYMBOLS = re.compile(r'bench_secret\.h|benchSecret|BenchSecret|BENCH-SECRET')

FIRMWARE = Path(__file__).resolve().parent.parent


def strip_comment(line):
    """Drop a // comment. Good enough for this file: no // inside the strings
    that mention the command."""
    i = line.find("//")
    return line if i < 0 else line[:i]


def unguarded_uses(text):
    """Line numbers of command symbols used outside an #ifdef FLAG block."""
    stack = []  # one entry per open #if: "guard", "negated" or "other"
    bad = []
    for n, raw in enumerate(text.splitlines(), 1):
        line = strip_comment(raw).strip()
        if line.startswith("#"):
            d = line[1:].strip()
            if re.match(rf"ifdef\s+{FLAG}\b", d) or re.match(rf"if\s+defined\s*\(?\s*{FLAG}\b", d):
                stack.append("guard")
            elif d.startswith("if"):  # #if, #ifdef, #ifndef of anything else
                stack.append("other")
            elif d.startswith("else") or d.startswith("elif"):
                if stack and stack[-1] == "guard":
                    stack[-1] = "negated"
            elif d.startswith("endif"):
                if stack:
                    stack.pop()
            if "include" in d and SYMBOLS.search(d) and "guard" not in stack:
                bad.append(n)
            continue
        if SYMBOLS.search(line) and "guard" not in stack:
            bad.append(n)
    return bad


def env_flags(ini, env):
    cp = configparser.ConfigParser(interpolation=None, strict=False)
    cp.read_string(ini)
    return cp.get(f"env:{env}", "build_flags", fallback="")


def source_check():
    errors = []
    ini = (FIRMWARE / "platformio.ini").read_text()
    if FLAG in env_flags(ini, "esp32dev"):
        errors.append(f"platformio.ini: the release env esp32dev defines {FLAG}")
    if FLAG not in env_flags(ini, "esp32dev-debug"):
        errors.append(f"platformio.ini: esp32dev-debug no longer defines {FLAG}")

    main = (FIRMWARE / "src" / "main.cpp").read_text()
    for n in unguarded_uses(main):
        errors.append(f"main.cpp:{n}: BENCH-SECRET code outside #ifdef {FLAG}")
    if not re.search(r'#include\s+"bench_secret\.h"', main):
        errors.append("main.cpp no longer includes bench_secret.h (update this check)")

    for f in sorted((FIRMWARE / "src").iterdir()):
        if f.name in ("main.cpp", "bench_secret.h") or f.suffix not in (".h", ".cpp"):
            continue
        if "bench_secret.h" in f.read_text():
            errors.append(f"{f.name} includes bench_secret.h; only main.cpp may, under {FLAG}")
    return errors


def self_test():
    ok = f'#ifdef {FLAG}\n#include "bench_secret.h"\nbool benchSecretCommand();\n#endif\n'
    assert unguarded_uses(ok) == [], "guarded use flagged"
    assert unguarded_uses('#include "bench_secret.h"\n') == [1], "bare include missed"
    assert unguarded_uses(f"#ifdef {FLAG}\n#else\nbenchSecretCommand(x);\n#endif\n") == [3], "#else missed"
    assert unguarded_uses(f"#ifdef {FLAG}\n#endif\nbenchSecretCommand(x);\n") == [3], "after #endif missed"
    nested = f"#ifdef {FLAG}\n#ifndef X\nbenchSecretCommand(x);\n#endif\n#endif\n"
    assert unguarded_uses(nested) == [], "nested guard flagged"
    assert unguarded_uses("#ifndef X\nbenchSecretCommand(x);\n#endif\n") == [2], "wrong guard missed"
    assert unguarded_uses("// BENCH-SECRET is bench-only\n") == [], "comment flagged"


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--release-bin", type=Path)
    ap.add_argument("--debug-bin", type=Path)
    args = ap.parse_args()

    self_test()
    errors = source_check()
    if args.release_bin and COMMAND in args.release_bin.read_bytes():
        errors.append(f"{args.release_bin}: the release image contains {COMMAND.decode()}")
    if args.debug_bin and COMMAND not in args.debug_bin.read_bytes():
        errors.append(f"{args.debug_bin}: the debug image does not contain {COMMAND.decode()} "
                      "(so the release check above proves nothing)")
    for e in errors:
        print("check_bench_only:", e, file=sys.stderr)
    if errors:
        return 1
    what = "source and images" if args.release_bin or args.debug_bin else "source"
    print(f"check_bench_only: BENCH-SECRET is bench-only ({what})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
