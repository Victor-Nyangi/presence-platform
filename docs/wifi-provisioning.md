# Wi-Fi provisioning: WPA2 SoftAP captive portal

**Decided 2026-10-18 (owner): a terminal gets its Wi-Fi credentials from a SoftAP captive portal
on first boot.** The SPEC had been silent on this, so the terminal never called `WiFi.begin()`
and the network path (heartbeat, upload, OTA) could not run on a board.

**Revised 2026-10-19 (owner), answering the open questions from the first version:**

| | Decision |
|---|---|
| a | The setup network is **WPA2 with a per-device password printed on a label**, not open. |
| b | A terminal whose saved network cannot be joined for **5 minutes after boot** reopens the portal **without erasing anything**, then goes back to the saved network. The BOOT-hold reset is unchanged. |
| c | The gateway URL stays a build constant. |
| d | The portal **collects the provisioning token**, and the terminal exchanges it at `POST /v1/device/provision`. The gateway still answers 501, so only the firmware side is built (see *What the gateway must implement*). |

This doc covers the design, what is host-tested, and the bench checklist. **None of it has been
run on a board.**

Code: `firmware/src/wifi_provision.h` holds the portal logic and `firmware/src/provision.h` the
token and the `/provision` exchange, both free of Arduino headers and under host test.
`firmware/src/wifi_softap.h` is the thin binding onto WiFi, DNSServer and NVS, and `main.cpp`
wires it in. It follows the same split as `ring_buffer.h` / `littlefs_storage.h` and
`ota_guard.h` / `EspBootControl`. `firmware/tools/setup_label.py` is the factory tool for the
setup password.

## Behaviour

| When | The terminal |
|---|---|
| Boot, usable credentials in NVS | Joins that network in station mode (`Wi-Fi: joining "<ssid>" (WPA2, passphrase)`). |
| Boot, nothing usable in NVS (first boot, after a reset, a torn or foreign entry) | The net task opens the setup portal. The scan task starts as usual; the portal never touches it. |
| Boot, no usable credentials **and no setup key** | **No setup network at all.** It prints that it needs labelling and waits for `setup_label.py` over USB, then opens the portal. It never opens an unsecured AP. |
| Saved network not joined within 5 minutes of boot | Opens the same portal for one window. The saved credentials stay. If the window passes unused it goes back to the saved network for another 5 minutes, and alternates until one of them works. |
| Saved network joined once since boot | The fall-back is off until the next boot. A later drop is an outage and is retried with backoff, as before. |
| Portal: valid form submitted | Writes the token (if asked for), then the credentials, to NVS and **reads both back**. Only then does it serve "Saved", and it restarts 1.5 s later into station mode. |
| Portal: invalid form | 400 with the reason, the SSID filled back in, the password and token fields empty. Nothing is stored. The portal stays open. |
| Portal: NVS write fails or reads back different | 500 "could not store the settings". The portal stays open and nothing restarts. |
| Portal opened at first boot: 10 minutes pass with nothing saved | The AP, DNS and HTTP servers stop and the radio goes off. The terminal stays offline until it is power-cycled or BOOT is held (there is no saved network to go back to). |
| BOOT held 10 s while running | Erases **only** the Wi-Fi entry, then restarts into the portal. |
| On Wi-Fi with no device secret | Presents the stored token to `POST /v1/device/provision`. See *The provisioning token*. |

### The setup network

- **SSID `presence-XXXXXX`**: the last three bytes of the station MAC (the one esptool prints and
  the router will see), so two terminals installed side by side do not collide.
- **WPA2-PSK, with the password on the terminal's label**, channel 1, at most one client. A second
  phone cannot join while the installer is connected. The password is the *setup key*, below.
- **DNS answers every name with the AP address (192.168.4.1).** That, plus the redirect below, is
  what makes Android, iOS and Windows pop the "sign in to network" sheet.

### The setup key (the label password)

**Format** `xxxx-xxxx-xxxx-xxxx`: 16 characters from `23456789abcdefghijkmnpqrstuvwxyz` (no
`0`/`o`, `1`/`l`), so 80 bits that survive being read off a label and typed into a phone. It is
always lower case, and WPA2 passwords are case-sensitive.

**Derivation**, on the factory machine only:

```
setup_key = groups of 4 of base32(HMAC-SHA256(factory_secret, "presence-setup-ap/v1\0" || mac[6])[:10])
```

**Why this design.** The repo's device secret cannot be the source: SPEC §3 has the gateway issue
it at provisioning, which needs Wi-Fi, which needs the setup network. A factory secret compiled
into the firmware would be a shared password, readable from any one terminal (there is no flash
encryption) and impossible in a public repo anyway. So the factory secret stays on the factory
machine, and **only each terminal's own derived key is written to it**:

- no two terminals share a password, and a terminal read out over JTAG reveals only its own;
- the same MAC and factory secret always give the same key, so a label stays valid after
  `pio run -t erase` once the terminal is labelled again, and a lost label can be reprinted
  without the terminal (`setup_label.py derive`);
- eFuse was not used: burning it is irreversible, and none of this has run on a board yet.

The terminal never derives the key (it cannot) and never prints it. It checks the format and
stores it as one 24-byte NVS entry, `ap_key` (magic `SAK1`). The BOOT-hold reset keeps it.

**At manufacture or flash time:**

```bash
# Once per factory: the factory secret. 32 random bytes as hex, mode 0600.
# Refuses to write inside a git work tree, and refuses to replace an existing file.
python3 firmware/tools/setup_label.py keygen --out ~/presence-factory/setup-ap.key

# Per terminal, after `pio run -t upload`, with `pio device monitor` closed:
uvx --with pyserial python firmware/tools/setup_label.py label \
    --key ~/presence-factory/setup-ap.key --port /dev/ttyUSB0
#   Terminal    24:6F:28:A1:B2:C3
#   Wi-Fi       presence-A1B2C3
#   Password    xxxx-xxxx-xxxx-xxxx      <- print this on the label

# Reprint a label, no board needed:
python3 firmware/tools/setup_label.py derive --key ~/presence-factory/setup-ap.key --mac 24:6F:28:A1:B2:C3
```

`label` speaks two serial commands that are in **every** build, not only the bench one:

| Host sends | Terminal answers |
|---|---|
| `SETUP-ID` | `SETUP-ID mac=246F28A1B2C3 ssid=presence-A1B2C3 key=present\|absent` |
| `SETUP-KEY <key>` | `SETUP-KEY OK`, or `SETUP-KEY REJECT <reason>` |

The terminal never echoes the key. `label` refuses to overwrite a key that is already there unless
given `--replace`. Anyone at the USB port can already reflash or erase the terminal, so the
command grants nothing new. **Keep the factory secret like the OTA signing key**
(`docs/ota-signing.md`): offline, backed up, never in a repo. Losing it means relabelling every
terminal; leaking it means anyone with a terminal's MAC (most of it is in the SSID) can derive
that terminal's setup password, which is the open-AP exposure the label was meant to remove.

`make firmware-test` runs `setup_label.py self-test`, a golden vector, and the host tests check
that the same vector is a key the terminal accepts.

### Falling back to the portal

A terminal with saved credentials that has not joined that network within
`PRESENCE_WIFI_FALLBACK_MS` (5 minutes; 1 minute in `esp32dev-debug`) of boot opens the setup
portal, **with the saved credentials still in NVS**:

```
boot ──► station, saved network ──joined──► normal (fall-back off until the next boot)
            │ not joined within 5 min
            ▼
         setup portal, one window (10 min) ──saved──► restart into the new network
            │ nothing saved
            ▼
         station again, a fresh 5 min ... and so on
```

- **The portal and the station alternate; they never share the radio.** An ESP32 station hunting
  for a missing network hops channels, and an AP running beside it must sit on the station's
  channel, so the installer's phone would be dropped each time. While the portal is up the
  terminal is not retrying the saved network, so a router that comes back during a window is
  rejoined when that window ends: up to 10 minutes late. Punches are buffered throughout.
- **Only "not joined since boot" triggers it.** A terminal that joined once has proved its
  credentials, and a later drop is an outage, which retrying handles; a school whose Wi-Fi goes
  down mid-morning does not grow a setup network on every terminal. The case the fall-back is for
  is a router replaced (new SSID or password) or a power cut that restarts both the terminal (in
  seconds) and the router (in minutes); 5 minutes is past a router's boot.
- **Nothing is erased.** A router outage that ends restores normal operation by itself: the next
  station window joins.
- The net task's backoff never sleeps past the fall-back deadline (`StationFallback::msUntilDue`).
- No setup key stored: no fall-back network either. The terminal says so and keeps retrying.

### The whole HTTP surface

`routePortal()` is the complete list. Anything not on it does not exist:

| Request | Answer |
|---|---|
| `GET` / `HEAD /` | The form (SSID, password, and the token when asked for) |
| `POST /save` | Validate, store, read back, "Saved" |
| Any other `GET` / `HEAD` (captive probes such as `/generate_204`, `/hotspot-detect.html`) | `302` to `http://192.168.4.1/`, empty body |
| Any other method on any other path | `404`, empty body |
| Wrong method on `/` or `/save` | `405` |

There is no OTA, no punch data, no device API, no status page, and nothing that shows the
credentials or token already stored. Host tests send `GET` and `POST` to `/v1/device/firmware`,
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
- **Token:** 64 hex digits, either case, stored lower-cased. Spaces and line breaks around it (a
  pasted QR scan) are dropped. A duplicated field is refused.

### The provisioning token

The form asks for it depending on what the terminal holds when the portal opens:

| Terminal holds | Token field |
|---|---|
| A device secret (already provisioned) | Not shown. A token sent anyway is ignored and not stored. |
| No device secret, no stored token | Shown and **required**. Without a valid one nothing is saved, Wi-Fi included. |
| No device secret, a token stored from an earlier visit | Shown, optional. Empty keeps the stored one; a new value replaces it. |

It is stored as one 69-byte NVS entry, `prov_token` (magic `TOK1`), **before** the Wi-Fi
credentials: stored credentials are what keep the portal shut at the next boot, so they are the
commit. Like the password, it is a password-type field, never echoed, never logged.

Once the terminal is on Wi-Fi with no device secret (`State::Provision`), the net task makes only
this call, retrying with the usual backoff:

```
POST {kApiBase}/v1/device/provision
X-Provision-Token: <64 lower-case hex digits, as stored>
Content-Type: application/json

{"serial":"246F28A1B2C3","firmware_version":"0.1.0"}
```

`serial` is the station MAC as 12 upper-case hex digits, the same bytes the SSID ends in.

| Answer | The terminal |
|---|---|
| `200` with `device_id` (a UUID), `device_secret` (standard padded base64 of 32 bytes), `key_version` (≥ 1) and `server_time_ms` | Writes `device_id`, `key_version`, then `device_secret` (the commit, read back) to NVS, erases the token, and moves on to `TimeSync`. A malformed 200 stores nothing. |
| `401`, `403`, `409` | Erases the token ("refused, hold BOOT 10 s and enter a new one"). Retrying cannot help. |
| Anything else, `501` included | Keeps the token and retries with backoff. |

A token left in NVS beside a device secret (a power cut between the two writes) is erased at boot.

### What the gateway must implement

`POST /v1/device/provision` is still a deliberate 501 (`gateway/internal/api/api.go`) and
`store.Provision`, which its comment names, does not exist. It was not built here: the SPEC
defines the exchange but not the installer flow around it (who mints a token, for which org and
site, how it reaches the label or QR code, what config a new device gets), and it is the one
unauthenticated endpoint that hands out a secret. What the terminal now relies on:

1. **Token issue.** An installer-side action creates the `device` row in state `provisioning`
   with its `serial` (the MAC, as above) and `provision_token_hash = cryptobox.HashToken(pepper,
   token)`, and shows the token once as 64 hex digits (and a QR code). The schema already has the
   columns. Decide, and write down, whether `HashToken` hashes the hex text or the 32 decoded
   bytes; the terminal sends the hex text exactly as above.
2. **Exchange.** `POST /v1/device/provision` looks the device up by the token hash (constant-time
   compare), checks the body's `serial` against the row, and in one transaction mints the 32-byte
   secret, seals it under the current KEK with the device id as AAD (as `seed` does), clears
   `provision_token_hash`, sets `provisioned_at` and `state = 'active'`, and returns the `200`
   body above. A token already used is `409`; an unknown token or a serial mismatch is `401`.
   The secret is returned once and never again.
3. **Rate-limit it** like `GET /v1/device/time`: it is unauthenticated by HMAC by necessity.
4. **A conformance vector**: one request and response pair pinned in both
   `gateway/internal/api` and `firmware/test/host_test.cpp`, the way the HMAC canonical string is,
   so the two cannot drift.

Until then a bench terminal stays in `State::Provision` with its token stored, retrying a 501.

### NVS

| Entry | Size | Written by | Erased by |
|---|---|---|---|
| `wifi_creds` | 102 B (magic `WIF1`, NUL-terminated SSID, NUL-terminated password) | the portal | BOOT held 10 s |
| `ap_key` | 24 B (magic `SAK1`, the setup key) | `setup_label.py` over USB | `pio run -t erase` only |
| `prov_token` | 69 B (magic `TOK1`, the token) | the portal | a successful or refused `/provision`; boot, when a device secret is present |

Each is one entry for the same reason the ring cursors and the OTA state are: a power cut cannot
pair half of one value with half of another. A record whose magic, terminators or contents do not
validate is treated as absent. For `ap_key` that means **no** setup network, never an open one.

`WiFi.persistent(false)` comes before every `WiFi.mode()`, so the Wi-Fi driver keeps its config in
RAM and never writes its own copy to flash. That makes the NVS entry the only copy, and erasing it
really forgets the network.

### Secrets are never logged

- `describeWifi()` is the only formatter for credentials. It prints the SSID and the kind of
  security, never the password or its length (host-tested).
- The page never echoes the password or the token, not even after an error.
- The terminal never prints the setup key; `SETUP-ID` says only `present` or `absent`.
- Request buffers, the decoded form, the serial command line and the `/provision` response are
  zeroed after use (best effort: `HTTPClient` keeps its own copies until it is destroyed).
- **The portal does not use the Arduino `WebServer`.** At `CORE_DEBUG_LEVEL=5`, which
  `esp32dev-debug` sets, it `log_v()`s every POST body, `Plain: ssid=...&password=...`. The
  ~150-line HTTP parser in `wifi_provision.h` replaces it, and the host tests cover it.

### The reset trigger

**Hold the DevKit's BOOT button (GPIO0) for 10 seconds while the terminal is running.** GPIO0 is a
strapping pin: held at power-on or reset it puts the chip into ROM download mode, so press it
*after* the boot line. The trigger only arms once the button has been seen released, so a stuck
button cannot erase and restart the terminal every ten seconds. A release partway through
restarts the count.

It erases **only the Wi-Fi entry**. The punch buffer, sequence counter, device secret, setup key,
provisioning token, RTC offset and OTA floor all stay, so nothing buffered is lost and the
downgrade floor cannot be reset from the button. A full factory wipe stays `pio run -t erase` over
USB, and needs `setup_label.py label` again afterwards.

## Design choices (2026-10-19)

1. **WPA2, per-device key from MAC + factory secret** (above). The trade: a factory secret to keep
   safe, in exchange for labels that survive an erase and no shared secret on any terminal.
2. **Fall-back only while not joined since boot**, alternating portal and station, never both at
   once (above).
3. **The gateway URL is not a portal field.** It stays the build constant `kApiBase`. A field
   anyone in range could fill in would let them point the terminal, and its provisioning token, at
   their own server.
4. **The token is required on an unprovisioned terminal.** Without it the terminal can join Wi-Fi
   but can never sign a request, so accepting Wi-Fi alone would close the portal on a terminal
   that is still useless. On the bench, before the gateway implements `/provision`, use any 64 hex
   digits (`openssl rand -hex 32`).
5. **A 10-minute window** (`PRESENCE_WIFI_PORTAL_MS`; the `esp32dev-debug` env uses 2 minutes and
   a 1-minute fall-back for the bench).
6. **Wi-Fi only on reset**, not a full factory reset (see above).

## Known gaps

- **Not run on a board.** Captive-sheet behaviour on real phones, WPA2 association with the label
  password, the one-client cap, the fall-back alternation, and how `WiFiServer` behaves with a
  phone that opens sockets and sends nothing are all unverified.
- **`/provision` has never completed**: the gateway answers 501 (above).
- **TLS to the gateway is unchanged by this.** Once the terminal is on Wi-Fi it uses `HTTPClient`
  exactly as before, and the token now travels the same way. Whether that verifies the gateway's
  certificate is a separate question, not answered here, and it matters more now that a bearer
  token rides on it.
- **The credentials, setup key and token are in NVS in plaintext**, like the device secret. NVS
  encryption needs flash encryption, which is not enabled.
- **Wi-Fi costs flash.** See `docs/firmware-build.md`.

## Bench checklist (for Victor)

You need the board, a phone, a laptop with `curl` (and `nmap` if you have it), and a test network
whose SSID and password you know (a phone hotspot works). Build `esp32dev-debug`, which uses
level-5 logging, the worst case for leaks, a 2-minute portal window and a 1-minute fall-back.
Make a bench factory secret **outside the repo** (`keygen` refuses inside it) and a stand-in token
(the gateway's `/provision` is still 501):

```bash
cd firmware
python3 tools/setup_label.py keygen --out ~/presence-bench-setup.key
openssl rand -hex 32 > ~/presence-bench-token.txt
pio run -e esp32dev-debug -t erase          # clean NVS: no credentials, no setup key, floor 0.0.0
pio run -e esp32dev-debug -t upload          # note the MAC esptool prints
pio device monitor | tee ~/wifi-bench.log    # keep the whole capture for step 12
```

| # | Do | Expect |
|---|---|---|
| 1 | Boot the erased board | `Wi-Fi: no setup key stored, so there is no setup network...`. No `presence-XXXXXX` in the phone's Wi-Fi list, open or otherwise |
| 2 | Close the monitor. `uvx --with pyserial python tools/setup_label.py label --key ~/presence-bench-setup.key --port /dev/ttyUSB0`, then reopen the monitor (append: `tee -a`) | The tool prints the MAC (matching esptool's), `presence-XXXXXX` and a `xxxx-xxxx-xxxx-xxxx` password. The board (possibly after a reset from opening the port) shows `setup network "presence-XXXXXX" (WPA2, password on the label) is up for 120 s` |
| 3 | Run `label` again without `--replace` | Refused: `already has a setup key` |
| 4 | `python3 tools/setup_label.py derive --key ~/presence-bench-setup.key --mac <the MAC>` | The same password as step 2 |
| 5 | Phone: join `presence-XXXXXX` | It asks for a password (WPA2). A wrong one fails. The label password joins, and the sign-in sheet opens by itself (Android "Sign in to network", iOS captive sheet). If not, browse to `http://192.168.4.1/` and note which phone and OS |
| 6 | Look at the form | SSID, password and a required **Provisioning token** field |
| 7 | Try to join from a second device while the phone is connected | Refused (one client) |
| 8 | From the laptop on the AP (disconnect the phone first): `curl -i http://192.168.4.1/v1/device/firmware`, `curl -i http://192.168.4.1/update`, `curl -i -X POST -d x=1 http://192.168.4.1/v1/device/events` | `302 Found` with `Location: http://192.168.4.1/` and no body; the same; `404` with no body |
| 9 | `nmap -p- 192.168.4.1` and `sudo nmap -sU -p 53,67 192.168.4.1`; `nslookup example.com 192.168.4.1` | TCP: only 80 open. UDP: 53 (DNS) and 67 (DHCP), nothing else. The name resolves to `192.168.4.1` |
| 10 | Submit the right SSID and password with the token left empty; then with a 7-character password and the token | "Enter the provisioning token"; then "at least 8 characters". Each time the SSID is still filled in, password and token empty, AP still up, nothing restarts |
| 11 | Submit the right SSID, password and the token from `~/presence-bench-token.txt` | "Saved"; about 1.5 s later `credentials saved, restarting into station mode`; next boot `Wi-Fi: joining "<ssid>" (WPA2, passphrase)`; the board shows up on the test network; `presence-XXXXXX` is gone. Then the `/provision` attempts: no `Provision: provisioned` line, and with level 5 a `Provision: HTTP ... will retry` warning every backoff (501 from a real gateway; a transport error against the placeholder `kApiBase`) |
| 12 | `grep -c -f <(echo '<the test password>'; echo '<the label password>'; cat ~/presence-bench-token.txt) ~/wifi-bench.log` | **0**, at level 5, over the whole capture |
| 13 | Power-cycle | Joins again with no portal |
| 14 | Hold BOOT for 5 s, release | Nothing happens |
| 15 | Note `punch buffer: N records, M buffered`, then hold BOOT for 10 s | `Wi-Fi: BOOT held 10 s, forgetting the network and restarting into setup`; it reboots into the WPA2 portal (step 2's line, no labelling needed), `M buffered` is unchanged, and the form's token field now says a token is already stored (optional) |
| 16 | `uvx --with pyserial python tools/serial_ota.py --port /dev/ttyUSB0 --status` (close the monitor first) | The OTA floor is what it was before the reset |
| 17 | **Fall-back, router outage**: save the test network again, let it join, then switch the hotspot off and power-cycle the board | `joining ...`, then about 60 s later `could not join the saved network within 60 s of boot; setup network ... is up for 120 s`. The label password joins it. Turn the hotspot back on and leave the portal alone: after 120 s `Wi-Fi: back to "<ssid>" ...` and it joins with **no** re-entry |
| 18 | **Fall-back, router replaced**: power-cycle with the hotspot off, wait for the portal, join it and save a different working network | "Saved", restart, joins the new network |
| 19 | **No fall-back after a join**: with the board joined, switch the hotspot off for 3 minutes, then back on | No setup network appears; the board rejoins by itself |
| 20 | In the portal, save the right SSID with a **wrong** password | Saves and restarts, cannot join; after 60 s the portal comes back (step 17's line), alternating with 60 s of retrying |
| 21 | Hold BOOT 10 s and let the first-boot portal sit 2 minutes with nothing saved | `Wi-Fi: setup closed with nothing saved; ...`; the network disappears and does not come back until a power cycle |
| 22 | Optional: an open test network (hotspot without a password), with the password field left empty | `Wi-Fi: joining "<ssid>" (open network)` and it joins |

Afterwards, run `pio run -e esp32dev-debug -t erase` so the board does not keep the test network,
then delete `~/wifi-bench.log` (it contains the test SSID) and `~/presence-bench-token.txt`. Keep
or delete `~/presence-bench-setup.key` as you like; it is a bench secret, not the factory one.
