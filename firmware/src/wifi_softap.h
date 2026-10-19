// wifi_softap.h — the on-device binding for Wi-Fi provisioning.
//
// Like littlefs_storage.h, this cannot compile on the host and is kept thin
// for that reason: it owns the radio, the sockets and NVS, and nothing else.
// Every decision -- what is a valid SSID, password, token or setup key, how a
// request is parsed, which paths exist, when the window closes, when to fall
// back to the portal, when to restart -- is in wifi_provision.h and
// provision.h under host test.
//
// Not the Arduino WebServer: at CORE_DEBUG_LEVEL 5 (esp32dev-debug) it logs
// every POST body with log_v, which here is the Wi-Fi password.
#pragma once

#include <Arduino.h>
#include <DNSServer.h>
#include <Preferences.h>
#include <WiFi.h>

#include "wifi_provision.h"

namespace presence {

// Read the request within this, or answer 408. One client at a time, so a
// phone that opens a socket and sends nothing cannot hold the portal long.
constexpr uint32_t kPortalReadTimeoutMs = 2000;

// The credentials as ONE NVS entry, in the namespace main.cpp already opened.
class NvsWifiCredentialStore : public WifiCredentialStore {
 public:
  explicit NvsWifiCredentialStore(Preferences* nvs, const char* key = "wifi_creds") : nvs_(nvs), key_(key) {}

  bool load(WifiCredentials* out) override {
    if (!nvs_->isKey(key_) || nvs_->getBytesLength(key_) != sizeof(*out)) return false;
    return nvs_->getBytes(key_, out, sizeof(*out)) == sizeof(*out);
  }
  bool save(const WifiCredentials& c) override { return nvs_->putBytes(key_, &c, sizeof(c)) == sizeof(c); }
  bool erase() override { return !nvs_->isKey(key_) || nvs_->remove(key_); }

 private:
  Preferences* nvs_;
  const char* key_;
};

// One NVS entry each, like the credentials. The setup key is written once at
// manufacture (setup_label.py) and kept by the BOOT-button reset; the token
// lives only until the gateway has exchanged it for a device secret.
class NvsSetupKeyStore : public SetupKeyStore {
 public:
  explicit NvsSetupKeyStore(Preferences* nvs, const char* key = "ap_key") : nvs_(nvs), key_(key) {}
  bool load(SetupApKey* out) override {
    if (!nvs_->isKey(key_) || nvs_->getBytesLength(key_) != sizeof(*out)) return false;
    return nvs_->getBytes(key_, out, sizeof(*out)) == sizeof(*out);
  }
  bool save(const SetupApKey& k) override { return nvs_->putBytes(key_, &k, sizeof(k)) == sizeof(k); }

 private:
  Preferences* nvs_;
  const char* key_;
};

class NvsProvisionTokenStore : public ProvisionTokenStore {
 public:
  explicit NvsProvisionTokenStore(Preferences* nvs, const char* key = "prov_token") : nvs_(nvs), key_(key) {}
  bool load(ProvisionTokenRecord* out) override {
    if (!nvs_->isKey(key_) || nvs_->getBytesLength(key_) != sizeof(*out)) return false;
    return nvs_->getBytes(key_, out, sizeof(*out)) == sizeof(*out);
  }
  bool save(const ProvisionTokenRecord& r) override { return nvs_->putBytes(key_, &r, sizeof(r)) == sizeof(r); }
  bool erase() override { return !nvs_->isKey(key_) || nvs_->remove(key_); }

 private:
  Preferences* nvs_;
  const char* key_;
};

// startStation joins the stored network. persistent(false) keeps the Wi-Fi
// driver from writing its own copy of the credentials to flash, so the NVS
// entry above is the only one and erasing it really forgets the network.
// The driver copies the config, so the caller may zero c afterwards.
inline void startStation(const WifiCredentials& c) {
  WiFi.persistent(false);
  WiFi.mode(WIFI_STA);
  WiFi.setAutoReconnect(true);
  WiFi.begin(c.ssid, c.password[0] != '\0' ? c.password : nullptr);
}

inline void serveOne(WiFiClient& client, WifiPortal& portal) {
  std::string buf;
  HttpRequest req;
  HttpParse parsed = HttpParse::Incomplete;
  uint8_t chunk[128];
  const uint32_t start = millis();
  while (client.connected() && millis() - start < kPortalReadTimeoutMs) {
    const int n = client.read(chunk, sizeof(chunk));
    if (n <= 0) {
      vTaskDelay(pdMS_TO_TICKS(2));
      continue;
    }
    buf.append(reinterpret_cast<const char*>(chunk), static_cast<size_t>(n));
    parsed = parseHttpRequest(buf.data(), buf.size(), &req);
    if (parsed != HttpParse::Incomplete) break;
  }
  secureZero(chunk, sizeof(chunk));
  secureZero(&buf);  // may hold the password
  const std::string resp = portal.handle(parsed, req, millis());
  client.write(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
  client.stop();
}

// runSoftApPortal opens the setup network and serves it. It does not return
// once credentials are saved: it restarts into station mode. It returns when
// the window closes with nothing saved, with the AP and both servers down
// and the radio off. idle runs between requests (main.cpp keeps the OTA
// confirm deadline there). There is no open variant: the caller must hold a
// usable setup key, and without one there is no setup network.
inline void runSoftApPortal(WifiPortal& portal, const SetupApKey& key, void (*idle)()) {
  if (!setupKeyUsable(key)) {
    Serial.println("Wi-Fi: no usable setup key; the setup network stays off");
    return;
  }
  WiFi.persistent(false);
  WiFi.disconnect(true);  // stop a station still retrying the saved network
  WiFi.mode(WIFI_AP);
  // WPA2-PSK (the core's default for a non-empty passphrase), channel 1,
  // visible, ONE client: a second phone cannot join while the installer is
  // using it. The driver copies the passphrase.
  if (!WiFi.softAP(portal.apSsid().c_str(), key.key, 1, 0, 1)) {
    Serial.println("Wi-Fi: could not start the setup network");
    WiFi.mode(WIFI_OFF);
    return;
  }
  const IPAddress ip = WiFi.softAPIP();
  DNSServer dns;
  dns.start(53, "*", ip);  // every name resolves to us: the captive-portal trigger
  WiFiServer http(80);
  http.begin();
  portal.begin(millis(), std::string("http://") + ip.toString().c_str() + "/");

  for (;;) {
    dns.processNextRequest();
    WiFiClient client = http.available();
    if (client) serveOne(client, portal);
    const PortalAction action = portal.tick(millis());
    if (action == PortalAction::Reboot) {
      Serial.println("Wi-Fi: credentials saved, restarting into station mode");
      Serial.flush();
      esp_restart();
    }
    if (action == PortalAction::Close) break;
    if (idle) idle();
    vTaskDelay(pdMS_TO_TICKS(5));
  }
  http.stop();
  dns.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);
}

}  // namespace presence
