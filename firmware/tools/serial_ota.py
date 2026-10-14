#!/usr/bin/env python3
"""Send a signed firmware image to a bench terminal over USB serial.

The terminal must be running an esp32dev-debug build (PRESENCE_BENCH_SERIAL_OTA)
whose ota_pubkey.h holds the key the image was signed with. The image goes
through exactly the gate the network path uses: the downgrade check (newer than
the running build and the NVS floor), then written to the idle OTA slot, read
back, sha256 + Ed25519 (over the signed version preamble and the image) checked
against the compiled-in key, and only then made bootable.

    uvx --with pyserial python firmware/tools/serial_ota.py \\
        --port /dev/ttyUSB0 --image firmware/.pio/build/esp32dev-debug/firmware.bin \\
        --manifest manifest.json

    # Rejection tests: one byte of the image flipped. The first is caught by
    # the sha256; the second recomputes the sha256 the way an attacker would,
    # so only the Ed25519 signature stands in the way.
    ... --flip-byte 400000 --expect-reject
    ... --flip-byte 400000 --recompute-sha256 --expect-reject
    # Downgrade test: claim a newer version than the image was signed as.
    ... --claim-version 9.0.0 --expect-reject

    # After an accepted image reboots it is pending; a bench board has no
    # Wi-Fi, so stand in for the first gateway heartbeat, or leave it alone
    # and watch it roll back when the confirm window (2 min on the bench) ends.
    uvx --with pyserial python firmware/tools/serial_ota.py --port /dev/ttyUSB0 --confirm
    uvx --with pyserial python firmware/tools/serial_ota.py --port /dev/ttyUSB0 --status

Exit status: 0 the terminal accepted the image and is rebooting into it;
1 the terminal rejected it (it keeps running its current image); 2 usage or
transport error. Pass --expect-reject to invert 0 and 1 for the tamper test.

Close `pio device monitor` first; only one program can hold the port.
"""

import argparse
import hashlib
import json
import sys
import time

CHUNK = 4096  # must match kOtaChunk in main.cpp


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", required=True)
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--image")
    ap.add_argument("--manifest", help="output of `fwsign sign`")
    ap.add_argument("--claim-version", metavar="X.Y.Z",
                    help="send this version instead of the manifest's, keeping its signature (downgrade test)")
    ap.add_argument("--status", action="store_true", help="print the terminal's OTA state and exit")
    ap.add_argument("--confirm", action="store_true",
                    help="stand in for the first gateway heartbeat: confirm a pending image and raise the floor")
    ap.add_argument("--flip-byte", type=int, default=None, metavar="OFFSET",
                    help="flip one bit at OFFSET before sending, keeping the manifest as signed")
    ap.add_argument("--recompute-sha256", action="store_true",
                    help="with --flip-byte: send the tampered image's own sha256, so only the signature can catch it")
    ap.add_argument("--expect-reject", action="store_true")
    ap.add_argument("--timeout", type=float, default=60.0, help="seconds to wait for each device reply")
    args = ap.parse_args()

    try:
        import serial  # pyserial
    except ImportError:
        print("pyserial is required: uvx --with pyserial python firmware/tools/serial_ota.py ...", file=sys.stderr)
        return 2

    if args.status or args.confirm:
        return command(serial, args, "OTA STATUS" if args.status else "OTA HEALTHY")
    if not args.image or not args.manifest:
        print("--image and --manifest are required to send an image", file=sys.stderr)
        return 2

    with open(args.manifest) as f:
        m = json.load(f)
    version = args.claim_version or m["version"]
    if args.claim_version:
        print(f"tampered: claiming version {version}, signature left as signed for {m['version']}")
    with open(args.image, "rb") as f:
        image = bytearray(f.read())
    if len(image) != m["size"]:
        print(f"image is {len(image)} bytes but the manifest says {m['size']}", file=sys.stderr)
        return 2
    if args.flip_byte is not None:
        if not 0 <= args.flip_byte < len(image):
            print("--flip-byte is outside the image", file=sys.stderr)
            return 2
        image[args.flip_byte] ^= 0x01
        print(f"tampered: flipped bit 0 of byte {args.flip_byte}")
        if args.recompute_sha256:
            m["sha256"] = hashlib.sha256(image).hexdigest()
            print("tampered: sha256 recomputed to match, signature left as signed")
    elif args.recompute_sha256:
        print("--recompute-sha256 only makes sense with --flip-byte", file=sys.stderr)
        return 2

    port = serial.Serial(args.port, args.baud, timeout=0.5)
    time.sleep(0.2)
    port.reset_input_buffer()

    def reply():
        """Next line starting with 'OTA ', skipping the terminal's log output."""
        deadline = time.monotonic() + args.timeout
        while time.monotonic() < deadline:
            line = port.readline().decode("utf-8", "replace").strip()
            if line.startswith("OTA "):
                return line
            if line:
                print(f"  device: {line}")
        return None

    port.write(f"OTA {version} {len(image)} {m['sha256']} {m['signature']}\n".encode())
    sent = 0
    started = time.monotonic()
    while True:
        r = reply()
        if r is None:
            print("timed out waiting for the terminal", file=sys.stderr)
            return 2
        if r == "OTA NEXT":
            if sent < len(image):
                port.write(image[sent:sent + CHUNK])
                sent = min(sent + CHUNK, len(image))
                if sent % (CHUNK * 32) == 0 or sent == len(image):
                    print(f"  sent {sent}/{len(image)} bytes ({time.monotonic() - started:.0f}s)")
            continue
        if r == "OTA OK":
            print("ACCEPTED: the terminal verified the image and is rebooting into it")
            return 1 if args.expect_reject else 0
        if r.startswith("OTA REJECT"):
            print(f"REJECTED: {r[len('OTA REJECT '):]} (the terminal keeps its current image)")
            return 0 if args.expect_reject else 1
        print(f"unexpected reply: {r}", file=sys.stderr)
        return 2


def command(serial, args, line):
    """Send one bench command and print the terminal's OTA reply."""
    port = serial.Serial(args.port, args.baud, timeout=0.5)
    time.sleep(0.2)
    port.reset_input_buffer()
    port.write((line + "\n").encode())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        reply = port.readline().decode("utf-8", "replace").strip()
        if reply.startswith("OTA "):
            print(reply)
            return 0 if "NOT-CONFIRMED" not in reply else 1
    print("timed out waiting for the terminal", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
