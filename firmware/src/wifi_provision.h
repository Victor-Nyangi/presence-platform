// wifi_provision.h — Wi-Fi provisioning over a WPA2 SoftAP captive portal.
//
// A terminal with no Wi-Fi credentials in NVS (first boot, or after the BOOT
// button is held for 10 s) opens its own access point, "presence-XXXXXX" from
// the last three bytes of its MAC, secured with WPA2 and a per-device password
// printed on its label (the setup key, below). It answers every DNS name with
// its own address and serves one page: SSID, password and, on a terminal that
// has no device secret yet, the provisioning token (provision.h). On a valid
// submission it writes them to NVS, reads them back, and only then tells the
// installer they were saved and restarts into station mode.
//
// A terminal WITH saved credentials that cannot join that network within the
// fall-back window after boot (StationFallback, 5 minutes) reopens the same
// portal for one window, without erasing anything, then goes back to trying
// the saved network, and alternates until one of them works. So a router that
// comes back restores normal operation, and a router that was replaced can be
// fixed without opening the case. docs/wifi-provisioning.md has the design and
// the bench checklist.
//
// What the portal deliberately does NOT do:
//
// - OPEN WITHOUT A PASSWORD. No setup key in NVS means no setup network at
//   all: the terminal waits for one over USB (firmware/tools/setup_label.py).
//   The key is derived on the factory machine from the MAC and a factory
//   secret that never reaches a terminal or this repo, so the label survives
//   a full erase and no two terminals share a password.
// - SERVE ANYTHING ELSE. routePortal() is the whole surface: the form, the
//   save, and a redirect to the form for every other GET (that redirect is
//   what makes phones pop the captive-portal sheet). No OTA, no punch data,
//   no status, no device API. Everything else is a 404 or 405.
// - LOG A SECRET. describeWifi() is the only formatter for credentials, and
//   it never includes the password. Neither the password nor the token is
//   echoed back into the page, and buffers that held them are zeroed. This is
//   also why the portal does not use the Arduino WebServer: at
//   CORE_DEBUG_LEVEL 5 (esp32dev-debug) it log_v()s every POST body. The HTTP
//   parsing here is small, bounded and under host test instead.
// - TAKE A GATEWAY URL. The gateway is a build constant (kApiBase). A field
//   anyone in radio range can fill in during setup would let them point the
//   terminal, and its provisioning token, at their own server.
//
// Ordering rule, in the spirit of "confirm the punch only after the flash
// write": SAY "SAVED" ONLY AFTER THE NVS WRITES READ BACK. The token is
// written first and the Wi-Fi credentials last, because stored credentials
// are what stops the portal opening at the next boot.
//
// The credentials are ONE NVS entry (like the ring cursors and the OTA
// state), so a power cut cannot pair a new SSID with an old password.
//
// Free of Arduino headers so the host tests run the same parser, router,
// validation and state machines. wifi_softap.h is the thin binding onto
// WiFi/DNSServer/NVS.
#pragma once

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <string>

#include "provision.h"  // the token record, and secureZero

namespace presence {

constexpr size_t kWifiSsidMaxBytes = 32;        // 802.11
constexpr size_t kWifiPassphraseMinBytes = 8;   // WPA2-PSK passphrase
constexpr size_t kWifiPassphraseMaxBytes = 63;
constexpr size_t kWifiPskHexChars = 64;         // a raw 256-bit PSK, as hex

// The persisted record. Changing the layout means bumping the magic: an
// entry that does not match is treated as absent, which opens the portal.
struct __attribute__((packed)) WifiCredentials {
  uint32_t magic;
  char ssid[kWifiSsidMaxBytes + 1];     // NUL-terminated
  char password[kWifiPskHexChars + 1];  // NUL-terminated; empty = open network
};
static_assert(sizeof(WifiCredentials) == 4 + 33 + 65, "WifiCredentials layout changed");
constexpr uint32_t kWifiCredentialsMagic = 0x31464957u;  // "WIF1"

class WifiCredentialStore {
 public:
  virtual ~WifiCredentialStore() = default;
  // false when nothing (or nothing of the right size) is stored
  virtual bool load(WifiCredentials* out) = 0;
  virtual bool save(const WifiCredentials& c) = 0;
  // true when nothing is stored afterwards, including when nothing was
  virtual bool erase() = 0;
};

// --------------------------------------------------------------------
// Validation
// --------------------------------------------------------------------
enum class WifiFieldError : uint8_t {
  Ok,
  SsidMissing,
  SsidTooLong,
  SsidBadByte,       // a control character
  PasswordTooShort,  // 1..7: not a WPA2 passphrase, and not empty (open)
  PasswordTooLong,
  PasswordBadByte,   // a passphrase must be printable ASCII
  PasswordBadHex,    // 64 characters is a raw PSK and must be hex
};

// Shown to the installer on the form, so written for them.
inline const char* wifiFieldErrorText(WifiFieldError e) {
  switch (e) {
    case WifiFieldError::Ok: return "";
    case WifiFieldError::SsidMissing: return "Enter the network name.";
    case WifiFieldError::SsidTooLong: return "The network name can be at most 32 bytes.";
    case WifiFieldError::SsidBadByte: return "The network name contains a control character.";
    case WifiFieldError::PasswordTooShort:
      return "A Wi-Fi password is at least 8 characters. Leave it empty only for an open network.";
    case WifiFieldError::PasswordTooLong: return "The password can be at most 63 characters (or a 64-digit hex key).";
    case WifiFieldError::PasswordBadByte: return "The password can only use printable ASCII characters.";
    case WifiFieldError::PasswordBadHex: return "A 64-character password must be a hex key (0-9, a-f).";
  }
  return "Invalid input.";
}

inline WifiFieldError validateSsid(const char* s, size_t n) {
  if (n == 0) return WifiFieldError::SsidMissing;
  if (n > kWifiSsidMaxBytes) return WifiFieldError::SsidTooLong;
  for (size_t i = 0; i < n; i++) {
    const uint8_t c = static_cast<uint8_t>(s[i]);
    if (c < 0x20 || c == 0x7F) return WifiFieldError::SsidBadByte;  // UTF-8 above 0x7F is fine
  }
  return WifiFieldError::Ok;
}

inline bool isHexDigit(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

inline WifiFieldError validatePassword(const char* s, size_t n) {
  if (n == 0) return WifiFieldError::Ok;  // an open network
  if (n < kWifiPassphraseMinBytes) return WifiFieldError::PasswordTooShort;
  if (n == kWifiPskHexChars) {
    for (size_t i = 0; i < n; i++) {
      if (!isHexDigit(s[i])) return WifiFieldError::PasswordBadHex;
    }
    return WifiFieldError::Ok;
  }
  if (n > kWifiPassphraseMaxBytes) return WifiFieldError::PasswordTooLong;
  for (size_t i = 0; i < n; i++) {
    const uint8_t c = static_cast<uint8_t>(s[i]);
    if (c < 0x20 || c > 0x7E) return WifiFieldError::PasswordBadByte;
  }
  return WifiFieldError::Ok;
}

// makeCredentials validates and fills *out. On any error *out is all zero.
inline WifiFieldError makeCredentials(const std::string& ssid, const std::string& password,
                                      WifiCredentials* out) {
  memset(out, 0, sizeof(*out));
  WifiFieldError e = validateSsid(ssid.data(), ssid.size());
  if (e == WifiFieldError::Ok) e = validatePassword(password.data(), password.size());
  if (e != WifiFieldError::Ok) return e;
  out->magic = kWifiCredentialsMagic;
  memcpy(out->ssid, ssid.data(), ssid.size());
  memcpy(out->password, password.data(), password.size());
  return WifiFieldError::Ok;
}

// credentialsUsable: what was read from NVS is a record this build wrote and
// would itself accept. Anything else, a torn or foreign entry included, is
// treated as no credentials at all, which opens the portal.
inline bool credentialsUsable(const WifiCredentials& c) {
  if (c.magic != kWifiCredentialsMagic) return false;
  const void* ssidEnd = memchr(c.ssid, '\0', sizeof(c.ssid));
  const void* passEnd = memchr(c.password, '\0', sizeof(c.password));
  if (ssidEnd == nullptr || passEnd == nullptr) return false;
  const size_t ssidLen = static_cast<const char*>(ssidEnd) - c.ssid;
  const size_t passLen = static_cast<const char*>(passEnd) - c.password;
  return validateSsid(c.ssid, ssidLen) == WifiFieldError::Ok &&
         validatePassword(c.password, passLen) == WifiFieldError::Ok;
}

// loadUsableCredentials is the boot decision: true means station mode with
// *out, false means open the portal (and *out is zeroed).
inline bool loadUsableCredentials(WifiCredentialStore* store, WifiCredentials* out) {
  if (store != nullptr && store->load(out) && credentialsUsable(*out)) return true;
  secureZero(out, sizeof(*out));
  return false;
}

// describeWifi is the ONLY way credentials reach a log line. It names the
// network and the kind of security, never the password or its length.
inline std::string describeWifi(const WifiCredentials& c) {
  std::string s = "\"";
  s.append(c.ssid, strnlen(c.ssid, sizeof(c.ssid)));
  s += "\"";
  const size_t n = strnlen(c.password, sizeof(c.password));
  if (n == 0) {
    s += " (open network)";
  } else if (n == kWifiPskHexChars) {
    s += " (WPA2, raw key)";
  } else {
    s += " (WPA2, passphrase)";
  }
  return s;
}

// softApSsid: "presence-" + the last three MAC bytes, so two terminals being
// installed side by side do not advertise the same network.
inline std::string softApSsid(const uint8_t mac[6]) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string s = "presence-";
  for (int i = 3; i < 6; i++) {
    s += kHex[mac[i] >> 4];
    s += kHex[mac[i] & 0x0F];
  }
  return s;
}

// --------------------------------------------------------------------
// The setup key: the setup network's WPA2 password, printed on the label.
// --------------------------------------------------------------------
// Format "xxxx-xxxx-xxxx-xxxx": 16 characters from a 32-letter alphabet with
// no 0/o, 1/l, so 80 bits that survive being read off a label and typed into
// a phone. The terminal never derives it -- it cannot, the factory secret is
// not on it -- it only checks the format and stores what setup_label.py sends
// (derive() there: HMAC-SHA256(factory secret, "presence-setup-ap/v1\0" ||
// MAC), first 10 bytes). One NVS entry, kept by the BOOT-button reset.
constexpr char kSetupKeyAlphabet[] = "23456789abcdefghijkmnpqrstuvwxyz";
static_assert(sizeof(kSetupKeyAlphabet) == 33, "the setup key alphabet is 32 letters");
constexpr size_t kSetupKeyChars = 19;  // 4 groups of 4, 3 dashes

struct __attribute__((packed)) SetupApKey {
  uint32_t magic;
  char key[kSetupKeyChars + 1];  // NUL-terminated
};
static_assert(sizeof(SetupApKey) == 24, "SetupApKey layout changed");
constexpr uint32_t kSetupApKeyMagic = 0x314B4153u;  // "SAK1"

inline bool validSetupKey(const char* s, size_t n) {
  if (n != kSetupKeyChars) return false;
  for (size_t i = 0; i < n; i++) {
    if (i % 5 == 4) {
      if (s[i] != '-') return false;
    } else if (s[i] == '\0' || strchr(kSetupKeyAlphabet, s[i]) == nullptr) {
      return false;
    }
  }
  return true;
}

// makeSetupKey validates and fills *out. On any error *out is all zero.
inline bool makeSetupKey(const std::string& key, SetupApKey* out) {
  memset(out, 0, sizeof(*out));
  if (!validSetupKey(key.data(), key.size())) return false;
  out->magic = kSetupApKeyMagic;
  memcpy(out->key, key.data(), key.size());
  return true;
}

inline bool setupKeyUsable(const SetupApKey& k) {
  return k.magic == kSetupApKeyMagic && k.key[kSetupKeyChars] == '\0' && validSetupKey(k.key, kSetupKeyChars);
}

class SetupKeyStore {
 public:
  virtual ~SetupKeyStore() = default;
  virtual bool load(SetupApKey* out) = 0;
  virtual bool save(const SetupApKey& k) = 0;
};

// loadUsableSetupKey: true with *out filled, or false with *out zeroed --
// and false means NO setup network, never an open one.
inline bool loadUsableSetupKey(SetupKeyStore* store, SetupApKey* out) {
  if (store != nullptr && store->load(out) && setupKeyUsable(*out)) return true;
  secureZero(out, sizeof(*out));
  return false;
}

// The USB serial commands setup_label.py speaks, in every build:
//   host: SETUP-ID\n              device: SETUP-ID mac=<12 hex> ssid=presence-XXXXXX key=present|absent
//   host: SETUP-KEY <key>\n       device: SETUP-KEY OK | SETUP-KEY REJECT <reason>
// The device never prints the key back. Anyone at the USB port can already
// reflash or erase the terminal, so this grants nothing new.
enum class SetupCommand : uint8_t { None, Id, SetKey, Malformed };

inline SetupCommand parseSetupCommand(const char* line, size_t n, std::string* key) {
  key->clear();
  if (n < 6 || memcmp(line, "SETUP-", 6) != 0) return SetupCommand::None;
  if (n == 8 && memcmp(line, "SETUP-ID", 8) == 0) return SetupCommand::Id;
  if (n > 10 && memcmp(line, "SETUP-KEY ", 10) == 0) {
    key->assign(line + 10, n - 10);
    return SetupCommand::SetKey;
  }
  return SetupCommand::Malformed;
}

inline std::string setupIdLine(const uint8_t mac[6], bool keyPresent) {
  std::string s = "SETUP-ID mac=";
  s += deviceSerial(mac);
  s += " ssid=";
  s += softApSsid(mac);
  s += keyPresent ? " key=present" : " key=absent";
  return s;
}

// --------------------------------------------------------------------
// Falling back to the portal when the saved network cannot be joined.
// --------------------------------------------------------------------
// The terminal and the portal never run the radio at the same time: an
// ESP32 station hunting for a missing network hops channels, and the AP
// (which must share the station's channel) drops the installer's phone each
// time. So they alternate:
//
//   boot ──► station, saved network ──joined──► normal (fall-back disarmed)
//               │ not joined within windowMs
//               ▼
//            setup portal, one window ──saved──► restart into the new network
//               │ window over, nothing saved
//               ▼
//            station again, a fresh windowMs ... and so on
//
// Disarmed for good once the station has joined since boot. A link that
// drops later is an outage, which retrying handles; a site whose Wi-Fi goes
// down mid-day does not grow a setup network on every terminal. A power
// cut is the common case anyway: the terminal boots in seconds and the
// router takes minutes, which is what the window is sized for.
class StationFallback {
 public:
  explicit StationFallback(uint32_t windowMs) : windowMs_(windowMs) {}

  void begin(uint32_t nowMs) {
    started_ = true;
    joined_ = false;
    windowStartMs_ = nowMs;
  }

  // portalDue: true while the portal should be opened (level, not edge: the
  // caller opens it and then calls restart()).
  bool portalDue(bool connected, uint32_t nowMs) {
    if (!started_ || joined_) return false;
    if (connected) {
      joined_ = true;
      return false;
    }
    return nowMs - windowStartMs_ >= windowMs_;
  }

  // restart: the portal closed with nothing saved; the station gets a fresh
  // window on the saved network.
  void restart(uint32_t nowMs) { windowStartMs_ = nowMs; }

  // msUntilDue bounds the net task's sleep, so a long backoff cannot delay
  // the portal. UINT32_MAX when it can never come due.
  uint32_t msUntilDue(uint32_t nowMs) const {
    if (!started_ || joined_) return UINT32_MAX;
    const uint32_t elapsed = nowMs - windowStartMs_;
    return elapsed >= windowMs_ ? 0 : windowMs_ - elapsed;
  }

  bool joined() const { return joined_; }
  uint32_t windowMs() const { return windowMs_; }

 private:
  uint32_t windowMs_;
  uint32_t windowStartMs_ = 0;
  bool started_ = false;
  bool joined_ = false;
};

// --------------------------------------------------------------------
// application/x-www-form-urlencoded
// --------------------------------------------------------------------
// Decoded field values are capped well above anything valid, so validation
// reports "too long" precisely, but a hostile body cannot grow a string.
constexpr size_t kFormFieldCap = 128;

inline int hexValue(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

// percentDecode: '+' is a space, %XX a byte. false on a malformed escape or
// when the result would exceed cap.
inline bool percentDecode(const char* s, size_t n, std::string* out, size_t cap) {
  out->clear();
  for (size_t i = 0; i < n; i++) {
    char c = s[i];
    if (c == '+') {
      c = ' ';
    } else if (c == '%') {
      if (i + 2 >= n) return false;
      const int hi = hexValue(s[i + 1]);
      const int lo = hexValue(s[i + 2]);
      if (hi < 0 || lo < 0) return false;
      c = static_cast<char>((hi << 4) | lo);
      i += 2;
    }
    if (out->size() >= cap) return false;
    *out += c;
  }
  return true;
}

enum class FormError : uint8_t { Ok, Malformed, Duplicate, Missing, FieldTooLong };

struct WifiForm {
  std::string ssid;
  std::string password;
  std::string token;  // the provisioning token; empty when not sent
  bool haveToken = false;
  ~WifiForm() {
    secureZero(&password);
    secureZero(&token);
  }
};

// parseWifiForm requires exactly one ssid and one password field, and at
// most one token field (whether it is required is the portal's decision).
// Unknown fields are ignored (a browser may send the submit button), but must
// still be well-formed. A missing password field is an error, not an open
// network: the form always sends one, so its absence is not a choice.
inline FormError parseWifiForm(const char* body, size_t len, WifiForm* out) {
  bool haveSsid = false, havePassword = false, haveToken = false;
  std::string key, value;
  size_t pos = 0;
  FormError result = FormError::Ok;
  while (pos <= len && result == FormError::Ok) {
    const char* amp = static_cast<const char*>(memchr(body + pos, '&', len - pos));
    const size_t end = amp ? static_cast<size_t>(amp - body) : len;
    if (end > pos) {
      const char* eq = static_cast<const char*>(memchr(body + pos, '=', end - pos));
      const size_t keyEnd = eq ? static_cast<size_t>(eq - body) : end;
      const size_t valStart = eq ? keyEnd + 1 : end;
      if (!percentDecode(body + pos, keyEnd - pos, &key, 32)) {
        result = FormError::Malformed;
      } else if (!percentDecode(body + valStart, end - valStart, &value, kFormFieldCap)) {
        // Distinguish an over-long value from a bad escape for the message.
        result = FormError::FieldTooLong;
        for (size_t i = valStart; i < end; i++) {
          if (body[i] == '%' && (i + 2 >= end || hexValue(body[i + 1]) < 0 || hexValue(body[i + 2]) < 0)) {
            result = FormError::Malformed;
            break;
          }
        }
      } else if (key == "ssid") {
        if (haveSsid) {
          result = FormError::Duplicate;
        } else {
          haveSsid = true;
          out->ssid.swap(value);
        }
      } else if (key == "password") {
        if (havePassword) {
          result = FormError::Duplicate;
        } else {
          havePassword = true;
          out->password.swap(value);
        }
      } else if (key == "token") {
        if (haveToken) {
          result = FormError::Duplicate;
        } else {
          haveToken = true;
          out->token.swap(value);
        }
      }
    }
    if (amp == nullptr) break;
    pos = end + 1;
  }
  secureZero(&value);
  if (result == FormError::Ok && (!haveSsid || !havePassword)) result = FormError::Missing;
  if (result != FormError::Ok) {
    out->ssid.clear();
    secureZero(&out->password);
    secureZero(&out->token);
    haveToken = false;
  }
  out->haveToken = haveToken;
  return result;
}

inline const char* formErrorText(FormError e) {
  switch (e) {
    case FormError::Ok: return "";
    case FormError::Malformed: return "The form could not be read. Please try again.";
    case FormError::Duplicate: return "The form was sent with a field twice. Please try again.";
    case FormError::Missing: return "Enter the network name and password.";
    case FormError::FieldTooLong: return "A field is too long.";
  }
  return "Invalid input.";
}

// --------------------------------------------------------------------
// HTTP: just enough of HTTP/1.x to read one request per connection.
// --------------------------------------------------------------------
constexpr size_t kPortalMaxHead = 1024;
constexpr size_t kPortalMaxBody = 512;

enum class HttpParse : uint8_t {
  Incomplete,  // keep reading (or, when the read timed out, 408)
  Ok,
  Bad,         // 400
  TooLarge,    // 413 / 431
};

struct HttpRequest {
  std::string method;
  std::string path;  // without the query string
  std::string body;  // exactly Content-Length bytes
  ~HttpRequest() { secureZero(&body); }
};

inline bool asciiIEquals(const char* a, size_t n, const char* b) {
  if (strlen(b) != n) return false;
  for (size_t i = 0; i < n; i++) {
    char x = a[i], y = b[i];
    if (x >= 'A' && x <= 'Z') x = static_cast<char>(x - 'A' + 'a');
    if (y >= 'A' && y <= 'Z') y = static_cast<char>(y - 'A' + 'a');
    if (x != y) return false;
  }
  return true;
}

// parseHttpRequest is called on the whole buffer after every read. It never
// reads past len, and it reports TooLarge as soon as the head or the declared
// body is over its cap, so the caller's buffer is bounded too.
inline HttpParse parseHttpRequest(const char* buf, size_t len, HttpRequest* out) {
  size_t headEnd = 0;  // index of the "\r\n\r\n"
  bool found = false;
  for (size_t i = 0; i + 3 < len && i <= kPortalMaxHead; i++) {
    if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
      headEnd = i;
      found = true;
      break;
    }
  }
  if (!found) return len > kPortalMaxHead + 3 ? HttpParse::TooLarge : HttpParse::Incomplete;

  // Request line: METHOD SP target SP HTTP/1.x
  const char* lineEnd = static_cast<const char*>(memchr(buf, '\r', headEnd + 1));
  const size_t lineLen = static_cast<size_t>(lineEnd - buf);
  if (buf[lineLen + 1] != '\n') return HttpParse::Bad;
  const char* sp1 = static_cast<const char*>(memchr(buf, ' ', lineLen));
  if (sp1 == nullptr) return HttpParse::Bad;
  const size_t methodLen = static_cast<size_t>(sp1 - buf);
  if (methodLen == 0 || methodLen > 8) return HttpParse::Bad;
  for (size_t i = 0; i < methodLen; i++) {
    if (buf[i] < 'A' || buf[i] > 'Z') return HttpParse::Bad;
  }
  const size_t targetStart = methodLen + 1;
  const char* sp2 = static_cast<const char*>(memchr(buf + targetStart, ' ', lineLen - targetStart));
  if (sp2 == nullptr) return HttpParse::Bad;
  const size_t targetLen = static_cast<size_t>(sp2 - (buf + targetStart));
  if (targetLen == 0 || buf[targetStart] != '/') return HttpParse::Bad;
  const size_t versionStart = static_cast<size_t>(sp2 - buf) + 1;
  if (lineLen - versionStart != 8 || memcmp(buf + versionStart, "HTTP/1.", 7) != 0) return HttpParse::Bad;
  for (size_t i = targetStart; i < targetStart + targetLen; i++) {
    const uint8_t c = static_cast<uint8_t>(buf[i]);
    if (c <= 0x20 || c >= 0x7F) return HttpParse::Bad;
  }
  size_t pathLen = targetLen;
  for (size_t i = 0; i < targetLen; i++) {
    if (buf[targetStart + i] == '?' || buf[targetStart + i] == '#') {
      pathLen = i;
      break;
    }
  }

  // Headers: only Content-Length and Transfer-Encoding matter.
  bool haveLength = false;
  size_t contentLength = 0;
  size_t p = lineLen + 2;
  while (p < headEnd + 2) {
    const char* e = static_cast<const char*>(memchr(buf + p, '\r', headEnd + 2 - p));
    const size_t end = e ? static_cast<size_t>(e - buf) : headEnd;
    if (end + 1 >= len || buf[end + 1] != '\n') return HttpParse::Bad;
    const char* colon = static_cast<const char*>(memchr(buf + p, ':', end - p));
    if (colon == nullptr || colon == buf + p) return HttpParse::Bad;
    const size_t nameLen = static_cast<size_t>(colon - (buf + p));
    size_t v = static_cast<size_t>(colon - buf) + 1;
    while (v < end && (buf[v] == ' ' || buf[v] == '\t')) v++;
    size_t vEnd = end;
    while (vEnd > v && (buf[vEnd - 1] == ' ' || buf[vEnd - 1] == '\t')) vEnd--;

    if (asciiIEquals(buf + p, nameLen, "transfer-encoding")) {
      return HttpParse::Bad;  // no chunked bodies; a form never needs one
    }
    if (asciiIEquals(buf + p, nameLen, "content-length")) {
      if (haveLength || v == vEnd) return HttpParse::Bad;
      haveLength = true;
      for (size_t i = v; i < vEnd; i++) {
        if (buf[i] < '0' || buf[i] > '9') return HttpParse::Bad;
        contentLength = contentLength * 10 + static_cast<size_t>(buf[i] - '0');
        if (contentLength > kPortalMaxBody) return HttpParse::TooLarge;
      }
    }
    p = end + 2;
  }

  const size_t bodyStart = headEnd + 4;
  if (len - bodyStart < contentLength) return HttpParse::Incomplete;
  out->method.assign(buf, methodLen);
  out->path.assign(buf + targetStart, pathLen);
  secureZero(&out->body);
  out->body.assign(buf + bodyStart, contentLength);
  return HttpParse::Ok;
}

// --------------------------------------------------------------------
// Routing: the entire surface of the portal.
// --------------------------------------------------------------------
enum class PortalRoute : uint8_t {
  Form,              // GET/HEAD /
  Save,              // POST /save
  Redirect,          // any other GET/HEAD: send the browser to the form
  NotFound,          // any other method on any other path
  MethodNotAllowed,  // a known path with the wrong method
};

inline PortalRoute routePortal(const std::string& method, const std::string& path) {
  const bool get = method == "GET" || method == "HEAD";
  if (path == "/") return get ? PortalRoute::Form : PortalRoute::MethodNotAllowed;
  if (path == "/save") {
    if (method == "POST") return PortalRoute::Save;
    return get ? PortalRoute::Redirect : PortalRoute::MethodNotAllowed;
  }
  // Captive-portal probes (/generate_204, /hotspot-detect.html,
  // /connecttest.txt, ...) are GETs to other paths. A redirect is what tells
  // the phone it is behind a portal. It reveals nothing but the form.
  return get ? PortalRoute::Redirect : PortalRoute::NotFound;
}

// --------------------------------------------------------------------
// Responses
// --------------------------------------------------------------------
inline std::string htmlEscape(const std::string& s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s) {
    switch (c) {
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      default: out += c;
    }
  }
  return out;
}

inline std::string httpResponse(int status, const char* reason, const std::string& body, bool includeBody,
                                const char* extraHeaders = "") {
  std::string r = "HTTP/1.1 ";
  r += std::to_string(status);
  r += ' ';
  r += reason;
  r += "\r\nContent-Type: text/html; charset=utf-8\r\n"
       "Cache-Control: no-store\r\n"
       "Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'\r\n"
       "X-Content-Type-Options: nosniff\r\n"
       "Referrer-Policy: no-referrer\r\n"
       "Connection: close\r\n";
  r += extraHeaders;
  r += "Content-Length: ";
  r += std::to_string(body.size());
  r += "\r\n\r\n";
  if (includeBody) r += body;
  return r;
}

inline std::string portalPage(const std::string& title, const std::string& inner) {
  std::string s =
      "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
      "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
      "<title>";
  s += htmlEscape(title);
  s += "</title><style>"
       "body{font-family:system-ui,sans-serif;max-width:26rem;margin:2rem auto;padding:0 1rem;color:#222}"
       "label{display:block;margin-top:1rem;font-weight:600}"
       "input{width:100%;box-sizing:border-box;padding:.6rem;font-size:1rem;margin-top:.3rem}"
       "button{margin-top:1.5rem;padding:.7rem 1.2rem;font-size:1rem}"
       ".err{background:#fde8e8;border:1px solid #e0a0a0;padding:.6rem;margin-top:1rem}"
       ".muted{color:#666;font-size:.9rem}"
       "</style></head><body>";
  s += inner;
  s += "</body></html>";
  return s;
}

// Whether the form asks for the provisioning token. Decided by main.cpp when
// the portal opens: a terminal with a device secret has been provisioned and
// has no use for one (Hidden: no field, and a submitted one is ignored); one
// without a secret needs it (Required), unless one is already stored from an
// earlier visit (Optional: empty keeps it, a new value replaces it).
enum class TokenField : uint8_t { Hidden, Required, Optional };

// The form. prefillSsid is echoed back (escaped) after an error so the
// installer does not retype it; the password and the token never are.
inline std::string portalFormPage(const std::string& apSsid, const std::string& prefillSsid, const char* error,
                                  TokenField token = TokenField::Hidden) {
  std::string inner = "<h1>Connect this terminal to Wi-Fi</h1><p class=\"muted\">Terminal ";
  inner += htmlEscape(apSsid);
  inner += "</p>";
  if (error != nullptr && error[0] != '\0') {
    inner += "<p class=\"err\" role=\"alert\">";
    inner += htmlEscape(error);
    inner += "</p>";
  }
  inner +=
      "<form method=\"post\" action=\"/save\">"
      "<label for=\"ssid\">Network name (SSID)</label>"
      "<input id=\"ssid\" name=\"ssid\" maxlength=\"32\" required autocapitalize=\"none\" autocorrect=\"off\" value=\"";
  inner += htmlEscape(prefillSsid);
  inner +=
      "\">"
      "<label for=\"password\">Password</label>"
      "<input id=\"password\" name=\"password\" type=\"password\" maxlength=\"64\" autocomplete=\"off\">"
      "<p class=\"muted\">Leave the password empty only for an open network.</p>";
  if (token != TokenField::Hidden) {
    inner +=
        "<label for=\"token\">Provisioning token</label>"
        "<input id=\"token\" name=\"token\" type=\"password\" maxlength=\"80\" autocomplete=\"off\" "
        "autocapitalize=\"none\" autocorrect=\"off\" spellcheck=\"false\"";
    inner += token == TokenField::Required ? " required>" : ">";
    inner += token == TokenField::Required
                 ? "<p class=\"muted\">The 64-character code from this terminal's installation sheet.</p>"
                 : "<p class=\"muted\">A token is already stored. Leave this empty to keep it.</p>";
  }
  inner +=
      "<button type=\"submit\">Save and restart</button>"
      "</form>";
  return portalPage("Terminal Wi-Fi setup", inner);
}

inline std::string portalSavedPage(const std::string& ssid) {
  std::string inner = "<h1>Saved</h1><p>The terminal is restarting to join <strong>";
  inner += htmlEscape(ssid);
  inner +=
      "</strong>. This setup network will disappear.</p>"
      "<p class=\"muted\">If the terminal cannot join that network, this setup network comes back after a few "
      "minutes, with the same password. Holding its BOOT button for 10 seconds also starts setup again.</p>";
  return portalPage("Saved", inner);
}

// --------------------------------------------------------------------
// The portal state machine. The binding owns the radio and sockets; this
// owns every decision. Clock values are millis(), wrap-safe.
// --------------------------------------------------------------------
enum class PortalState : uint8_t { Idle, Open, Saved, Closed };
enum class PortalAction : uint8_t { None, Reboot, Close };

class WifiPortal {
 public:
  WifiPortal(WifiCredentialStore* store, const std::string& apSsid, uint32_t timeoutMs,
             uint32_t rebootDelayMs = 1500)
      : store_(store), apSsid_(apSsid), timeoutMs_(timeoutMs), rebootDelayMs_(rebootDelayMs) {}

  // origin is where redirects point, e.g. "http://192.168.4.1/".
  void begin(uint32_t nowMs, const std::string& origin) {
    startMs_ = nowMs;
    origin_ = origin;
    state_ = PortalState::Open;
  }

  // setTokenField: ask for the provisioning token, and where to keep it.
  // Without a call the field is Hidden.
  void setTokenField(ProvisionTokenStore* store, TokenField mode) {
    tokenStore_ = store;
    tokenField_ = mode;
  }

  PortalState state() const { return state_; }
  const std::string& apSsid() const { return apSsid_; }
  uint32_t timeoutMs() const { return timeoutMs_; }
  TokenField tokenField() const { return tokenField_; }

  // handle answers one request. parsed is what parseHttpRequest returned
  // (Incomplete meaning the read timed out); req is only read when it is Ok.
  std::string handle(HttpParse parsed, const HttpRequest& req, uint32_t nowMs) {
    if (state_ == PortalState::Idle || state_ == PortalState::Closed) {
      return httpResponse(503, "Service Unavailable", portalPage("Closed", "<p>Setup is closed.</p>"), true);
    }
    switch (parsed) {
      case HttpParse::Incomplete:
        return httpResponse(408, "Request Timeout", std::string(), false);
      case HttpParse::Bad:
        return httpResponse(400, "Bad Request", std::string(), false);
      case HttpParse::TooLarge:
        return httpResponse(413, "Content Too Large", std::string(), false);
      case HttpParse::Ok:
        break;
    }
    const bool head = req.method == "HEAD";
    switch (routePortal(req.method, req.path)) {
      case PortalRoute::Form:
        if (state_ == PortalState::Saved) return httpResponse(200, "OK", portalSavedPage(savedSsid_), !head);
        return httpResponse(200, "OK", portalFormPage(apSsid_, std::string(), nullptr, tokenField_), !head);
      case PortalRoute::Redirect: {
        const std::string loc = "Location: " + origin_ + "\r\n";
        return httpResponse(302, "Found", std::string(), false, loc.c_str());
      }
      case PortalRoute::NotFound:
        return httpResponse(404, "Not Found", std::string(), false);
      case PortalRoute::MethodNotAllowed:
        return httpResponse(405, "Method Not Allowed", std::string(), false,
                            req.path == "/save" ? "Allow: POST\r\n" : "Allow: GET, HEAD\r\n");
      case PortalRoute::Save:
        return save(req, nowMs);
    }
    return httpResponse(404, "Not Found", std::string(), false);
  }

  // tick: Reboot once a save has had time to reach the browser; Close once
  // the window has passed with nothing saved.
  PortalAction tick(uint32_t nowMs) {
    if (state_ == PortalState::Saved && nowMs - savedMs_ >= rebootDelayMs_) return PortalAction::Reboot;
    if (state_ == PortalState::Open && nowMs - startMs_ >= timeoutMs_) {
      state_ = PortalState::Closed;
      return PortalAction::Close;
    }
    return PortalAction::None;
  }

 private:
  std::string save(const HttpRequest& req, uint32_t nowMs) {
    if (state_ == PortalState::Saved) return httpResponse(200, "OK", portalSavedPage(savedSsid_), true);
    WifiForm form;
    const FormError fe = parseWifiForm(req.body.data(), req.body.size(), &form);
    if (fe != FormError::Ok) {
      return httpResponse(400, "Bad Request", portalFormPage(apSsid_, std::string(), formErrorText(fe), tokenField_),
                          true);
    }
    // Echo the SSID back only if it is printable; a control byte stays out.
    const std::string prefill = validateSsid(form.ssid.data(), form.ssid.size()) == WifiFieldError::SsidBadByte
                                    ? std::string()
                                    : form.ssid.substr(0, kWifiSsidMaxBytes);
    WifiCredentials creds;
    const WifiFieldError ve = makeCredentials(form.ssid, form.password, &creds);
    if (ve != WifiFieldError::Ok) {
      return httpResponse(400, "Bad Request", portalFormPage(apSsid_, prefill, wifiFieldErrorText(ve), tokenField_),
                          true);
    }

    // The token, when this portal asks for one. Hidden ignores whatever was
    // sent: a provisioned terminal has no use for a token and keeps none.
    ProvisionTokenRecord tok;
    memset(&tok, 0, sizeof(tok));
    bool saveToken = false;
    if (tokenField_ != TokenField::Hidden) {
      std::string t = form.token;
      trimSpaces(&t);
      const bool empty = t.empty();
      secureZero(&t);
      if (!(empty && tokenField_ == TokenField::Optional)) {
        const TokenError te = makeTokenRecord(form.token, &tok);
        if (te != TokenError::Ok) {
          secureZero(&creds, sizeof(creds));
          return httpResponse(400, "Bad Request", portalFormPage(apSsid_, prefill, tokenErrorText(te), tokenField_),
                              true);
        }
        saveToken = true;
      }
    }

    // Token first, Wi-Fi last: stored credentials are what keep the portal
    // shut at the next boot, so they are the commit.
    bool stored = true;
    if (saveToken) {
      stored = tokenStore_ != nullptr && tokenStore_->save(tok);
      if (stored) {
        ProvisionTokenRecord back;
        stored = tokenStore_->load(&back) && memcmp(&back, &tok, sizeof(tok)) == 0;
        secureZero(&back, sizeof(back));
      }
    }
    secureZero(&tok, sizeof(tok));
    stored = stored && store_ != nullptr && store_->save(creds);
    if (stored) {
      WifiCredentials back;
      stored = store_->load(&back) && memcmp(&back, &creds, sizeof(creds)) == 0;
      secureZero(&back, sizeof(back));
    }
    secureZero(&creds, sizeof(creds));
    if (!stored) {
      return httpResponse(500, "Internal Server Error",
                          portalFormPage(apSsid_, prefill, "The terminal could not store the settings. Try again.",
                                         tokenField_),
                          true);
    }
    savedSsid_ = form.ssid;
    savedMs_ = nowMs;
    state_ = PortalState::Saved;
    return httpResponse(200, "OK", portalSavedPage(savedSsid_), true);
  }

  WifiCredentialStore* store_;
  ProvisionTokenStore* tokenStore_ = nullptr;
  TokenField tokenField_ = TokenField::Hidden;
  std::string apSsid_;
  std::string origin_;
  std::string savedSsid_;
  uint32_t timeoutMs_;
  uint32_t rebootDelayMs_;
  uint32_t startMs_ = 0;
  uint32_t savedMs_ = 0;
  PortalState state_ = PortalState::Idle;
};

// --------------------------------------------------------------------
// The Wi-Fi reset trigger: the BOOT button held continuously for holdMs.
// --------------------------------------------------------------------
// It arms only after the button has been seen released once, so a button
// that is stuck down (or a pin wired low) cannot erase the credentials and
// restart the terminal every ten seconds forever.
class HoldTrigger {
 public:
  explicit HoldTrigger(uint32_t holdMs) : holdMs_(holdMs) {}

  // true exactly once per continuous hold of at least holdMs
  bool update(bool pressed, uint32_t nowMs) {
    if (!pressed) {
      armed_ = true;
      holding_ = false;
      fired_ = false;
      return false;
    }
    if (!armed_) return false;
    if (!holding_) {
      holding_ = true;
      sinceMs_ = nowMs;
    }
    if (!fired_ && nowMs - sinceMs_ >= holdMs_) {
      fired_ = true;
      return true;
    }
    return false;
  }

 private:
  uint32_t holdMs_;
  uint32_t sinceMs_ = 0;
  bool armed_ = false;
  bool holding_ = false;
  bool fired_ = false;
};

}  // namespace presence
