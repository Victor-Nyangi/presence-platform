#!/usr/bin/env python3
"""Give a terminal its Wi-Fi setup password and print the label for it.

The setup network ("presence-XXXXXX") is WPA2. Its password is derived on the
factory machine from the terminal's MAC and a factory secret, then written to
the terminal's NVS over USB serial. The factory secret never leaves the
factory machine and is never in this repo, so:

  - no two terminals share a password, and a terminal read out over JTAG
    reveals only its own;
  - the same MAC and factory secret always give the same password, so a
    label stays valid after `pio run -t erase` once the terminal is labelled
    again, and a lost label can be reprinted without the terminal.

    password = groups of 4 of base32(HMAC-SHA256(factory_secret,
               "presence-setup-ap/v1\\0" || mac[6])[:10]),
               alphabet 23456789abcdefghijkmnpqrstuvwxyz (no 0/o, 1/l)

Usage:

    # Once: the factory secret. Refuses to write inside a git work tree.
    python3 firmware/tools/setup_label.py keygen --out ~/presence-factory/setup-ap.key

    # Per terminal, after flashing (close `pio device monitor` first):
    uvx --with pyserial python firmware/tools/setup_label.py label \\
        --key ~/presence-factory/setup-ap.key --port /dev/ttyUSB0

    # Reprint a label with no board attached (MAC from esptool or the label):
    python3 firmware/tools/setup_label.py derive --key ~/presence-factory/setup-ap.key --mac 24:6F:28:A1:B2:C3

    # The golden vector (run by `make firmware-test`):
    python3 firmware/tools/setup_label.py self-test

The password is printed once, on stdout, for the label. The terminal never
prints it back. Exit status: 0 done; 1 the terminal refused; 2 usage or
transport error.
"""

import argparse
import hashlib
import hmac
import os
import re
import stat
import sys
import time

DOMAIN = b"presence-setup-ap/v1\x00"
ALPHABET = "23456789abcdefghijkmnpqrstuvwxyz"  # must match kSetupKeyAlphabet in wifi_provision.h
KEY_BYTES = 32

# Golden vector, also asserted (as a valid key) by firmware/test/host_test.cpp.
# A test key, not a real factory secret.
GOLDEN_KEY = bytes(range(32))
GOLDEN_MAC = bytes.fromhex("246F28A1B2C3")
GOLDEN_PASSWORD = "usty-qc6e-hs6z-52yd"


def derive(factory_key: bytes, mac: bytes) -> str:
    if len(factory_key) != KEY_BYTES or len(mac) != 6:
        raise ValueError("factory key must be 32 bytes and the MAC 6")
    d = hmac.new(factory_key, DOMAIN + mac, hashlib.sha256).digest()[:10]
    n = int.from_bytes(d, "big")
    chars = "".join(ALPHABET[(n >> (5 * (15 - i))) & 31] for i in range(16))
    return "-".join(chars[i:i + 4] for i in range(0, 16, 4))


def ssid_for(mac: bytes) -> str:
    return "presence-" + mac[3:].hex().upper()


def parse_mac(text: str) -> bytes:
    hexdigits = re.sub(r"[:\-]", "", text.strip())
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", hexdigits):
        raise ValueError(f"not a MAC address: {text!r}")
    return bytes.fromhex(hexdigits)


def inside_git_work_tree(path: str) -> bool:
    d = os.path.dirname(os.path.abspath(path))
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return True
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent


def keygen(out: str) -> int:
    if inside_git_work_tree(out):
        print(f"refusing to write the factory secret inside a git work tree: {out}", file=sys.stderr)
        return 2
    try:
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        print(f"{out} exists; refusing to replace a factory secret (every label printed from it would be wrong)",
              file=sys.stderr)
        return 2
    with os.fdopen(fd, "w") as f:
        f.write(os.urandom(KEY_BYTES).hex() + "\n")
    print(f"wrote {out} (mode 0600). Back it up offline: losing it means relabelling every terminal.")
    return 0


def load_key(path: str) -> bytes:
    """Read the factory secret, checking the file on the handle it is read from."""
    fd = os.open(path, os.O_RDONLY)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"{path} is not a regular file")
        if st.st_mode & 0o077:
            raise ValueError(f"{path} is readable by other users (mode {oct(st.st_mode & 0o777)}); chmod 600 it")
        text = os.read(fd, 200).decode("ascii", "replace").strip()
    finally:
        os.close(fd)
    if not re.fullmatch(r"[0-9a-f]{64}", text):
        raise ValueError(f"{path} does not hold 64 lower-case hex digits")
    return bytes.fromhex(text)


def print_label(mac: bytes, password: str) -> None:
    print(f"Terminal    {mac.hex(':').upper()}")
    print(f"Wi-Fi       {ssid_for(mac)}")
    print(f"Password    {password}")


def label(serial, args) -> int:
    key = load_key(args.key)
    port = serial.Serial(args.port, args.baud, timeout=0.5)
    time.sleep(0.2)
    port.reset_input_buffer()

    def reply(prefix, resend=None):
        """Next line starting with prefix, skipping log output. Opening the
        port can reset a DevKit, so an unanswered command is resent."""
        deadline = time.monotonic() + args.timeout
        next_send = 0.0
        while time.monotonic() < deadline:
            if resend is not None and time.monotonic() >= next_send:
                port.write(resend)
                next_send = time.monotonic() + 2.0
            line = port.readline().decode("utf-8", "replace").strip()
            if line.startswith(prefix):
                return line
        return None

    ident = reply("SETUP-ID ", resend=b"SETUP-ID\n")
    if ident is None:
        print("timed out waiting for the terminal (is pio device monitor still open?)", file=sys.stderr)
        return 2
    fields = dict(f.split("=", 1) for f in ident.split()[1:] if "=" in f)
    mac = parse_mac(fields.get("mac", ""))
    if fields.get("key") == "present" and not args.replace:
        print(f"{ssid_for(mac)} already has a setup key; pass --replace to overwrite it", file=sys.stderr)
        return 2
    password = derive(key, mac)
    port.write(f"SETUP-KEY {password}\n".encode())
    r = reply("SETUP-KEY ")
    if r is None:
        print("timed out waiting for the terminal to store the key", file=sys.stderr)
        return 2
    if r != "SETUP-KEY OK":
        print(f"the terminal refused: {r}", file=sys.stderr)
        return 1
    print_label(mac, password)
    return 0


def self_test() -> int:
    got = derive(GOLDEN_KEY, GOLDEN_MAC)
    ok = got == GOLDEN_PASSWORD
    ok = ok and re.fullmatch(r"([%s]{4}-){3}[%s]{4}" % (ALPHABET, ALPHABET), got) is not None
    ok = ok and len(set(ALPHABET)) == 32 and not set("01lo") & set(ALPHABET)
    ok = ok and derive(GOLDEN_KEY, parse_mac("24:6f:28:a1:b2:c4")) != got  # per device
    ok = ok and ssid_for(GOLDEN_MAC) == "presence-A1B2C3"
    print(("setup_label self-test passed" if ok else f"setup_label self-test FAILED: got {got}"))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="create the factory secret")
    k.add_argument("--out", required=True)
    lb = sub.add_parser("label", help="store the setup key on a terminal over USB and print its label")
    lb.add_argument("--key", required=True)
    lb.add_argument("--port", required=True)
    lb.add_argument("--baud", type=int, default=115200)
    lb.add_argument("--timeout", type=float, default=15.0)
    lb.add_argument("--replace", action="store_true", help="overwrite a setup key the terminal already holds")
    d = sub.add_parser("derive", help="print a label from the MAC, no board needed")
    d.add_argument("--key", required=True)
    d.add_argument("--mac", required=True)
    sub.add_parser("self-test", help="check the golden vector")
    args = ap.parse_args()

    try:
        if args.cmd == "keygen":
            return keygen(args.out)
        if args.cmd == "self-test":
            return self_test()
        if args.cmd == "derive":
            mac = parse_mac(args.mac)
            print_label(mac, derive(load_key(args.key), mac))
            return 0
        try:
            import serial  # pyserial
        except ImportError:
            print("pyserial is required: uvx --with pyserial python firmware/tools/setup_label.py ...",
                  file=sys.stderr)
            return 2
        return label(serial, args)
    except (OSError, ValueError) as e:
        print(e, file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
