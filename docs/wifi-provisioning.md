# Wi-Fi provisioning: SoftAP captive portal

**Decided 2026-10-18 (owner): a terminal gets its Wi-Fi credentials from a SoftAP captive portal
on first boot.** The SPEC had been silent on this, so the terminal never called `WiFi.begin()`
and the network path (heartbeat, upload, OTA) could not run on a board. This doc covers the
design, what is host-tested, and the bench checklist. **None of it has been run on a board.**

Code: `firmware/src/wifi_provision.h` holds all the logic, free of Arduino headers and under host
test. `firmware/src/wifi_softap.h` is the thin binding onto WiFi, DNSServer and NVS, and
`main.cpp` wires it in. It follows the same split as `ring_buffer.h` / `littlefs_storage.h` and
`ota_guard.h` / `EspBootControl`.

## Behaviour

| When | The terminal |
|---|---|
| Boot, usable credentials in NVS | Joins that network in station mode (`Wi-Fi: joining "<ssid>" (WPA2, passphrase)`). |
| Boot, nothing usable in NVS (first boot, after a reset, a torn or foreign entry) | The net task opens the setup portal. The scan task starts as usual; the portal never touches it. |
| Portal: valid form submitted | Writes the credentials to NVS and **reads them back**. Only then does it serve "Saved", and it restarts 1.5 s later into station mode. |
| Portal: invalid form | 400 with the reason, the SSID filled back in, the password field empty. The portal stays open. |
| Portal: NVS write fails or reads back different | 500 "could not store the settings". The portal stays open and nothing restarts. |
| Portal: 10 minutes pass with nothing saved | The AP, DNS and HTTP servers stop and the radio goes off. The terminal stays offline until it is power-cycled or BOOT is held. |
| BOOT held 10 s while running | Erases **only** the Wi-Fi entry, then restarts into the portal. |

### The setup network

- **SSID `presence-XXXXXX`**: the last three bytes of the station MAC (the one esptool prints and
  the router will see), so two terminals installed side by side do not collide.
- **Open (no password), channel 1, at most one client.** A second phone cannot join while the
  installer is connected.
- **DNS answers every name with the AP address (192.168.4.1).** That, plus the redirect below, is
  what makes Android, iOS and Windows pop the "sign in to network" sheet.

### The whole HTTP surface

`routePortal()` is the complete list. Anything not on it does not exist:

| Request | Answer |
|---|---|
| `GET` / `HEAD /` | The form (SSID, password) |
| `POST /save` | Validate, store, read back, "Saved" |
| Any other `GET` / `HEAD` (captive probes such as `/generate_204`, `/hotspot-detect.html`) | `302` to `http://192.168.4.1/`, empty body |
| Any other method on any other path | `404`, empty body |
| Wrong method on `/` or `/save` | `405` |

There is no OTA, no punch data, no device API, no status page, and nothing that shows the
credentials already stored. Host tests send `GET` and `POST` to `/v1/device/firmware`,
`/v1/device/events`, `/update`, `/ota`, `/punches` and others, and check that each one gets a
bodyless redirect or a 404. The page has no script, and it is sent with
`Content-Security-Policy: default-src 'none'`.

Requests are bounded: a head of 1 KB at most, a body of 512 B at most, no chunked encoding, one
`Content-Length`, 2 s to arrive (otherwise `408`), one request per connection.

### Validation

- **SSID:** 1 to 32 bytes, no control characters. UTF-8 is allowed, and leading or trailing spaces
  are kept as typed.
- **Password:** empty (an open network), 8 to 63 printable ASCII characters (a WPA2 passphrase), or
  exactly 64 hex digits (a raw PSK). A form with no password field at all is refused. It is not
  taken to mean an open network.

### NVS

One entry, `wifi_creds`, in the existing `presence` namespace: a 102-byte packed record (magic
`WIF1`, NUL-terminated SSID, NUL-terminated password). It is one entry for the same reason the
ring cursors and the OTA state are: a power cut cannot pair a new SSID with an old password. A
record whose magic, terminators or contents do not validate is treated as absent, so the portal
opens.

`WiFi.persistent(false)` comes before every `WiFi.mode()`, so the Wi-Fi driver keeps its config in
RAM and never writes its own copy to flash. That makes the NVS entry the only copy, and erasing it
really forgets the network.

### The password is never logged

- `describeWifi()` is the only formatter for credentials. It prints the SSID and the kind of
  security, never the password or its length (host-tested).
- The page never echoes the password, not even after an error.
- Request buffers and the decoded form are zeroed after use (best effort).
- **The portal does not use the Arduino `WebServer`.** At `CORE_DEBUG_LEVEL=5`, which
  `esp32dev-debug` sets, it `log_v()`s every POST body, `Plain: ssid=...&password=...`. The
  ~150-line HTTP parser in `wifi_provision.h` replaces it, and the host tests cover it.

### The reset trigger

**Hold the DevKit's BOOT button (GPIO0) for 10 seconds while the terminal is running.** GPIO0 is a
strapping pin: held at power-on or reset it puts the chip into ROM download mode, so press it
*after* the boot line. The trigger only arms once the button has been seen released, so a stuck
button cannot erase and restart the terminal every ten seconds. A release partway through
restarts the count.

It erases **only the Wi-Fi entry**. The punch buffer, sequence counter, device secret, RTC offset
and OTA floor all stay, so nothing buffered is lost and the downgrade floor cannot be reset from
the button. A full factory wipe stays `pio run -t erase` over USB.

## Design choices to confirm

The SPEC does not contradict any of these, but each one is a choice:

1. **The setup AP is open.** While the installer types the site's Wi-Fi password, it crosses the
   air unencrypted, and anyone in range during the window can join first (one-client cap) or
   submit their own network. The mitigations are the bounded window, the one-client cap, and the
   fact that the portal only opens on a first boot or a deliberate button hold. The alternative
   is a WPA2 AP with a per-device password printed on a label. That needs a per-device secret and
   a label step at manufacture, the same step as the provisioning token's QR code. It is a natural
   follow-up once that installer flow exists.
2. **No automatic return to the portal.** If the saved network cannot be joined (a typo in the
   password, or the router replaced), the terminal keeps retrying with backoff and stays offline
   until someone holds BOOT. A school whose Wi-Fi is down for a day must not end up with an open
   setup AP on every terminal.
3. **The gateway URL is not a portal field.** It stays the build constant `kApiBase`. The SPEC
   assumes one gateway per deployment, and a field anyone in range can fill in during setup would
   let them point the terminal (and, once the installer flow exists, its provisioning token) at
   their own server.
4. **The provisioning token is not collected here either.** `POST /v1/device/provision` is still
   501 by design. When the installer flow is built, this form is the obvious place for the token
   field, and the same rules apply: validated, stored in one entry, never logged.
5. **A 10-minute window** (`PRESENCE_WIFI_PORTAL_MS`; the `esp32dev-debug` env uses 2 minutes for
   the bench).
6. **Wi-Fi only on reset**, not a full factory reset (see above).

## Known gaps

- **Not run on a board.** Captive-sheet behaviour on real phones, the one-client cap, and how
  `WiFiServer` behaves with a phone that opens sockets and sends nothing are all unverified.
- **TLS to the gateway is unchanged by this.** Once the terminal is on Wi-Fi it uses `HTTPClient`
  exactly as before. Whether that verifies the gateway's certificate is a separate question, not
  answered here.
- **The credentials are in NVS in plaintext**, like the device secret. NVS encryption needs flash
  encryption, which is not enabled.
- **Wi-Fi costs flash.** Bringing the Wi-Fi driver up at all (`WiFi.mode`/`WiFi.begin`) links in
  the driver, the supplicant and lwIP, which the earlier builds never started and so never linked.
  See `docs/firmware-build.md`.

## Bench checklist (for Victor)

You need the board, a phone, a laptop with `curl` (and `nmap` if you have it), and a test network
whose SSID and password you know (a phone hotspot works). Build `esp32dev-debug`, which uses
level-5 logging, the worst case for leaks, and a 2-minute portal window.

```bash
cd firmware
pio run -e esp32dev-debug -t erase          # clean NVS: no credentials, floor 0.0.0
pio run -e esp32dev-debug -t upload          # note the MAC esptool prints
pio device monitor | tee ~/wifi-bench.log    # keep the whole capture for step 9
```

| # | Do | Expect |
|---|---|---|
| 1 | Boot the erased board | `Wi-Fi: no credentials stored; setup network "presence-XXXXXX" is open for 120 s`, with XXXXXX the last three MAC bytes |
| 2 | Look at the phone's Wi-Fi list | `presence-XXXXXX`, open. Join it: the sign-in sheet opens by itself (Android "Sign in to network", iOS captive sheet). If not, browse to `http://192.168.4.1/` and note which phone and OS. |
| 3 | Try to join from a second device while the phone is connected | Refused (one client) |
| 4 | From the laptop on the AP (disconnect the phone first): `curl -i http://192.168.4.1/v1/device/firmware`, `curl -i http://192.168.4.1/update`, `curl -i -X POST -d x=1 http://192.168.4.1/v1/device/events` | `302 Found` with `Location: http://192.168.4.1/` and no body; the same; `404` with no body |
| 5 | `nmap -p- 192.168.4.1` and `sudo nmap -sU -p 53,67 192.168.4.1` | TCP: only 80 open. UDP: 53 (DNS) and 67 (DHCP), nothing else |
| 6 | `nslookup example.com 192.168.4.1` | Resolves to `192.168.4.1` |
| 7 | Submit the form with the right SSID and a 7-character password | Error "at least 8 characters", SSID still filled in, password empty, AP still up |
| 8 | Submit the right SSID and password | "Saved" page; about 1.5 s later `Wi-Fi: credentials saved, restarting into station mode`; next boot `Wi-Fi: joining "<ssid>" (WPA2, passphrase)`; the board shows up on the test network; `presence-XXXXXX` is gone |
| 9 | `grep -c '<the test password>' ~/wifi-bench.log` | **0**, at level 5, over the whole capture |
| 10 | Power-cycle | Joins again with no portal |
| 11 | Hold BOOT for 5 s, release | Nothing happens |
| 12 | Note `punch buffer: N records, M buffered`, then hold BOOT for 10 s | `Wi-Fi: BOOT held 10 s, forgetting the network and restarting into setup`; it reboots into the portal (step 1's line), and `M buffered` is unchanged |
| 13 | `uvx --with pyserial python tools/serial_ota.py --port /dev/ttyUSB0 --status` (close the monitor first) | The OTA floor is what it was before the reset |
| 14 | In the portal, save the right SSID with a **wrong** password | Saves and restarts, then cannot join. It keeps retrying and **does not** reopen the portal. Hold BOOT 10 s to recover. |
| 15 | Let the portal sit for 2 minutes with nothing saved | `Wi-Fi: setup closed with nothing saved; ...`; the network disappears from the phone's list and does not come back until a power cycle |
| 16 | Optional: an open test network (hotspot without a password), with the password field left empty | `Wi-Fi: joining "<ssid>" (open network)` and it joins |

Afterwards, run `pio run -e esp32dev-debug -t erase` so the board does not keep the test
network, then delete `~/wifi-bench.log`, which contains the test SSID.
