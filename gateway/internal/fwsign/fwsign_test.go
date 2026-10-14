package fwsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"presence/internal/model"
)

// The golden vector shared with firmware/test/host_test.cpp
// (testSigningToolGoldenVector). It was produced once with a key generated in
// memory and never written anywhere, so only the public half exists. If this
// package ever signs something other than the raw image bytes, the firmware
// side of the vector fails.
const (
	goldenPublicKey = "3cd093728d823e9acc0bff6a7d13fa56ebb1ec74919534be98cb7a0621dd1858"
	goldenSignature = "5c4bcc9ae75f0e50435e512ff754ba38ba074890774fff7eabe74be5963b3415" +
		"f7627f50e35ee73fb7b80137a92228bbaf3b864592b325064ba881bd8c247d08"
	goldenSHA256 = "85ba634afbe9acad2774ce77b6e5ac24b29d85cdaaef6bff544d87d548f50557"
)

func goldenImage() []byte {
	img := make([]byte, 4099)
	for i := range img {
		img[i] = byte((i*167 + 13) ^ (i >> 8))
	}
	return img
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, pemBytes, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func pubOf(k ed25519.PrivateKey) ed25519.PublicKey { return k.Public().(ed25519.PublicKey) }

func TestGoldenVectorMatchesFirmware(t *testing.T) {
	m := model.FirmwareManifest{
		Available: true, Version: "0.0.0", URL: "https://x/y.bin",
		Size: 4099, SHA256: goldenSHA256, Signature: goldenSignature,
	}
	if err := Verify(mustHex(t, goldenPublicKey), goldenImage(), m); err != nil {
		t.Fatalf("golden vector does not verify: %v", err)
	}
	bad := goldenImage()
	bad[len(bad)-1] ^= 1
	m.SHA256 = hexSHA(bad) // so it is the signature check that fails
	if err := Verify(mustHex(t, goldenPublicKey), bad, m); err == nil {
		t.Fatal("tampered golden image verified")
	}
	if ed25519.Verify(mustHex(t, goldenPublicKey), bad, mustHex(t, goldenSignature)) {
		t.Fatal("tampered golden image verified at the primitive")
	}
}

func TestSignThenVerify(t *testing.T) {
	priv := newKey(t)
	img := bytes.Repeat([]byte("presence firmware "), 5000)
	m, err := Sign(priv, img, "0.2.0", "https://fw.example.com/0.2.0.bin?sig=a&exp=b")
	if err != nil {
		t.Fatal(err)
	}
	if !m.Available || m.Size != int64(len(img)) || len(m.SHA256) != 64 || len(m.Signature) != 128 {
		t.Fatalf("bad manifest shape: %+v", m)
	}
	if err := Verify(pubOf(priv), img, m); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRejects(t *testing.T) {
	priv := newKey(t)
	img := bytes.Repeat([]byte{0xA5, 0x5A, 0x00}, 10000)
	m, err := Sign(priv, img, "0.2.0", "https://fw.example.com/a.bin")
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), img...)
	tampered[len(tampered)/2] ^= 0x01
	retagged := m
	sum := hexSHA(tampered)
	retagged.SHA256 = sum // an attacker can recompute the sha256; not the signature

	truncSig := m
	truncSig.Signature = m.Signature[:126]

	cases := []struct {
		name  string
		pub   ed25519.PublicKey
		image []byte
		m     model.FirmwareManifest
	}{
		{"tampered image", pubOf(priv), tampered, m},
		{"tampered image with a recomputed sha256", pubOf(priv), tampered, retagged},
		{"wrong key", pubOf(newKey(t)), img, m},
		{"truncated signature", pubOf(priv), img, truncSig},
		{"empty image", pubOf(priv), nil, m},
		{"truncated image", pubOf(priv), img[:len(img)-1], m},
		{"unprovisioned key", make(ed25519.PublicKey, 32), img, m},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := Verify(c.pub, c.image, c.m); err == nil {
				t.Fatal("verified")
			}
		})
	}
}

func hexSHA(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestSignRefusesBadInput(t *testing.T) {
	priv := newKey(t)
	for name, f := range map[string]func() error{
		"empty image":  func() error { _, err := Sign(priv, nil, "1", "https://x"); return err },
		"no version":   func() error { _, err := Sign(priv, []byte{1}, "", "https://x"); return err },
		"long version": func() error { _, err := Sign(priv, []byte{1}, strings.Repeat("9", 33), "https://x"); return err },
		"ftp url":      func() error { _, err := Sign(priv, []byte{1}, "1", "ftp://x"); return err },
	} {
		if f() == nil {
			t.Errorf("%s: signed anyway", name)
		}
	}
}

func TestManifestJSONIsWhatTheFirmwareParses(t *testing.T) {
	priv := newKey(t)
	m, err := Sign(priv, []byte{1, 2, 3}, "0.2.0", "https://fw.example.com/a.bin?x=1&y=2")
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := WriteManifest(&buf, m); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), `\u0026`) || !strings.Contains(buf.String(), "x=1&y=2") {
		t.Fatalf("& was HTML-escaped; the firmware refuses \\u escapes:\n%s", buf.String())
	}
	var fields map[string]any
	if err := json.Unmarshal(buf.Bytes(), &fields); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"available", "version", "url", "size", "sha256", "signature"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("manifest lacks %q", k)
		}
	}
}

func TestPEMRoundTripAndRejectsOtherKeyTypes(t *testing.T) {
	pub, pemBytes, err := GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ParsePrivateKeyPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("round trip changed the key")
	}

	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	der, _ := x509.MarshalPKCS8PrivateKey(ec)
	if _, err := ParsePrivateKeyPEM(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err == nil {
		t.Fatal("accepted an ECDSA key")
	}
	if _, err := ParsePrivateKeyPEM([]byte("not pem")); err == nil {
		t.Fatal("accepted garbage")
	}
}

func TestKeyFileSafety(t *testing.T) {
	_, pemBytes, _ := GenerateKey(rand.Reader)
	dir := t.TempDir()
	if insideGitWorkTree(dir) {
		t.Skip("TMPDIR is inside a git work tree; cannot test the outside case here")
	}

	path := filepath.Join(dir, "release.pem")
	if err := WriteNewKeyFile(path, pemBytes); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %#o, want 0600", info.Mode().Perm())
	}
	if _, err := LoadPrivateKeyFile(path); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewKeyFile(path, pemBytes); err == nil {
		t.Fatal("overwrote an existing key")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyFile(path); err == nil {
		t.Fatal("loaded a world-readable key")
	}

	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(repo, "keys"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewKeyFile(filepath.Join(repo, "keys", "release.pem"), pemBytes); err == nil {
		t.Fatal("wrote a private key inside a git work tree")
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	pub := pubOf(newKey(t))
	src := "// old key: 0x01, 0x02\nstatic const uint8_t kOtaReleasePublicKey[32] = {\n" +
		"    /* rotated 2026-10 */\n" + CArray(pub) + "};\n"
	got, err := ParseHeaderKey(src)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Equal(pub) {
		t.Fatalf("got %x want %x", got, pub)
	}
	if _, err := ParseHeaderKey("static const uint8_t kOtaReleasePublicKey[32] = {0x01};"); err == nil {
		t.Fatal("accepted a 1-byte key")
	}
}

// The committed header must parse, so `fwsign sign -header` works against
// the real file and not just a test fixture.
func TestCommittedHeaderParses(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "firmware", "src", "ota_pubkey.h"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseHeaderKey(string(src)); err != nil {
		t.Fatal(err)
	}
}
