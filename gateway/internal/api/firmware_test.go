package api

// Unit tests for GET /v1/device/firmware and the image route. They need no
// database: the handlers are called with a *store.Device directly, as the
// signed() middleware would hand them one, and the route test only reaches
// the part of signed() that runs before any lookup. The signed end-to-end
// path is in integration_test.go (TestFirmwareOverTheSignedRoutes).

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"presence/internal/auth"
	"presence/internal/firmware"
	"presence/internal/fwsign"
	"presence/internal/model"
	"presence/internal/store"
)

type fwFixture struct {
	srv   *Server
	pub   ed25519.PublicKey
	image []byte
	m     model.FirmwareManifest
}

// writeRelease publishes version on channel under dir, as the release steps
// in docs/ota-signing.md do, signed with a key that exists only in memory.
func writeRelease(t *testing.T, dir string, priv ed25519.PrivateKey, channel, version string, n int) (model.FirmwareManifest, []byte) {
	t.Helper()
	img := append(bytes.Repeat([]byte{0xE9, 0x01, 0x02, 0x03}, n), []byte(fwsign.VersionMarker+version+"\x00")...)
	m, err := fwsign.Sign(priv, img, version, "")
	if err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(filepath.Join(dir, "images"), 0o755)
	os.MkdirAll(filepath.Join(dir, channel), 0o755)
	os.WriteFile(filepath.Join(dir, "images", m.SHA256+".bin"), img, 0o644)
	var buf bytes.Buffer
	fwsign.WriteManifest(&buf, m)
	os.WriteFile(filepath.Join(dir, channel, "manifest.json"), buf.Bytes(), 0o644)
	return m, img
}

func newFirmwareFixture(t *testing.T) *fwFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	m, img := writeRelease(t, dir, priv, "stable", "0.2.0", 50_000)
	cat, err := firmware.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	s := NewServer(nil, auth.NewMemoryNonceCache(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.SetFirmware(cat)
	return &fwFixture{srv: s, pub: pub, image: img, m: m}
}

func device(channel string) *store.Device {
	return &store.Device{ID: "55555555-5555-5555-5555-555555555555", FirmwareChannel: channel}
}

func (f *fwFixture) manifest(t *testing.T, dev *store.Device, query string) (int, model.FirmwareManifest, string) {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/device/firmware"+query, nil)
	f.srv.handleFirmware(w, r, dev, nil)
	var m model.FirmwareManifest
	raw := w.Body.String()
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
			t.Fatalf("decode %q: %v", raw, err)
		}
	}
	return w.Code, m, raw
}

func TestFirmwareManifestForANewerRelease(t *testing.T) {
	f := newFirmwareFixture(t)
	code, m, raw := f.manifest(t, device("stable"), "?current=0.1.0")
	if code != http.StatusOK || !m.Available {
		t.Fatalf("%d %s", code, raw)
	}
	if m.URL != "/v1/device/firmware/images/"+f.m.SHA256 {
		t.Fatalf("url %q", m.URL)
	}
	if err := fwsign.Verify(f.pub, f.image, m); err != nil {
		t.Fatalf("the served manifest does not verify: %v", err)
	}
	// The firmware's JSON reader refuses \u escapes and needs every field.
	for _, k := range []string{`"available":true`, `"version":"0.2.0"`, `"url":"/v1/device/firmware/images/`, `"size":`, `"sha256":"`, `"signature":"`} {
		if !strings.Contains(raw, k) {
			t.Errorf("response lacks %s: %s", k, raw)
		}
	}
	if strings.Contains(raw, `\u`) {
		t.Errorf("response has a \\u escape: %s", raw)
	}
}

func TestFirmwareNothingNewer(t *testing.T) {
	f := newFirmwareFixture(t)
	for _, cur := range []string{"0.2.0", "0.2.1", "3.0.0"} {
		code, m, raw := f.manifest(t, device("stable"), "?current="+cur)
		if code != http.StatusOK || m.Available || strings.TrimSpace(raw) != `{"available":false}` {
			t.Errorf("current %s: %d %s", cur, code, raw)
		}
	}
	// A channel with nothing published.
	if code, m, _ := f.manifest(t, device("beta"), "?current=0.1.0"); code != http.StatusOK || m.Available {
		t.Errorf("empty channel: %d %+v", code, m)
	}
	// A gateway with no release directory configured.
	bare := NewServer(nil, auth.NewMemoryNonceCache(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	w := httptest.NewRecorder()
	bare.handleFirmware(w, httptest.NewRequest("GET", "/v1/device/firmware?current=0.1.0", nil), device("stable"), nil)
	if w.Code != http.StatusOK || strings.TrimSpace(w.Body.String()) != `{"available":false}` {
		t.Errorf("no catalog: %d %s", w.Code, w.Body.String())
	}
}

func TestFirmwareRejectsABadCurrent(t *testing.T) {
	f := newFirmwareFixture(t)
	for _, q := range []string{"", "?current=", "?current=0.1.0-dev", "?current=latest"} {
		if code, _, raw := f.manifest(t, device("stable"), q); code != http.StatusBadRequest {
			t.Errorf("%q: %d %s", q, code, raw)
		}
	}
}

func TestHeartbeatFirmwareAvailable(t *testing.T) {
	f := newFirmwareFixture(t)
	for _, tc := range []struct {
		channel, current string
		want             bool
	}{
		{"stable", "0.1.0", true},
		{"stable", "0.2.0", false},
		{"stable", "", false},
		{"stable", "0.1.0-dev", false},
		{"beta", "0.1.0", false},
	} {
		if got := f.srv.firmwareAvailable(device(tc.channel), tc.current); got != tc.want {
			t.Errorf("%s %q: %v, want %v", tc.channel, tc.current, got, tc.want)
		}
	}
}

func (f *fwFixture) image200(t *testing.T, sha string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/v1/device/firmware/images/"+sha, nil)
	r.SetPathValue("sha256", sha)
	f.srv.handleFirmwareImage(w, r, device("stable"), nil)
	return w
}

func TestFirmwareImageIsServedFromTheDirectory(t *testing.T) {
	f := newFirmwareFixture(t)
	w := f.image200(t, f.m.SHA256)
	if w.Code != http.StatusOK || !bytes.Equal(w.Body.Bytes(), f.image) {
		t.Fatalf("%d, %d bytes", w.Code, w.Body.Len())
	}
	if w.Header().Get("Content-Length") != "200026" || w.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("headers %v", w.Header())
	}
	for _, sha := range []string{strings.Repeat("0", 64), "nope", "..%2fstable%2fmanifest.json"} {
		if w := f.image200(t, sha); w.Code != http.StatusNotFound {
			t.Errorf("%q: %d", sha, w.Code)
		}
	}
}

// Both routes go through signed(): with no signature there is no manifest
// and no image, and the 401 carries server_time_ms like every other.
func TestFirmwareRoutesRequireASignature(t *testing.T) {
	f := newFirmwareFixture(t)
	ts := httptest.NewServer(f.srv.Routes())
	defer ts.Close()
	for _, path := range []string{"/v1/device/firmware?current=0.1.0", "/v1/device/firmware/images/" + f.m.SHA256} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !bytes.Contains(body, []byte(`"server_time_ms"`)) || bytes.Contains(body, f.image[:16]) {
			t.Errorf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
}

func TestFirmwareHandlersConcurrently(t *testing.T) {
	f := newFirmwareFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				if code, m, _ := f.manifest(t, device("stable"), "?current=0.1.0"); code != http.StatusOK || !m.Available {
					t.Errorf("manifest %d", code)
				}
				return
			}
			if w := f.image200(t, f.m.SHA256); w.Code != http.StatusOK || w.Body.Len() != len(f.image) {
				t.Errorf("image %d", w.Code)
			}
		}(i)
	}
	wg.Wait()
}
