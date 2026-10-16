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
// memory and never written anywhere, so only the public half exists. It signs
// Preamble("1.2.3", 4099) followed by goldenImage(). If this package ever
// signs anything else (the bare image, a hash, a different preamble), the
// firmware side of the vector fails.
const (
	goldenVersion   = "1.2.3"
	goldenPublicKey = "084dbbdd1f539f42a53792f892b2b6fd3d876c5ff6689420bb7d402ae51a28d9"
	goldenSignature = "0a44e507c61010f4416b476813bb337b4cbcdd9f7845067a8c90a1401bf3bb1a" +
		"11bfa94df02146f193932a021f506229479b024911a4930b590e9acebfcd2f0e"
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
		Available: true, Version: goldenVersion,
		Size: 4099, SHA256: goldenSHA256, Signature: goldenSignature,
	}
	if err := Verify(mustHex(t, goldenPublicKey), goldenImage(), m); err != nil {
		t.Fatalf("golden vector does not verify: %v", err)
	}
	relabelled := m
	relabelled.Version = "1.2.4"
	if err := Verify(mustHex(t, goldenPublicKey), goldenImage(), relabelled); err == nil {
		t.Fatal("golden image verified under a version it was not signed for")
	}
	bad := goldenImage()
	bad[len(bad)-1] ^= 1
	m.SHA256 = hexSHA(bad) // so it is the signature check that fails
	if err := Verify(mustHex(t, goldenPublicKey), bad, m); err == nil {
		t.Fatal("tampered golden image verified")
	}
	if ed25519.Verify(mustHex(t, goldenPublicKey), signedMessage(goldenVersion, bad), mustHex(t, goldenSignature)) {
		t.Fatal("tampered golden image verified at the primitive")
	}
}

// The preamble bytes are a wire format shared with the firmware; pin them
// literally rather than only through the vector.
func TestPreambleBytes(t *testing.T) {
	got := string(Preamble("0.2.0", 770992))
	want := "presence-ota-image/v1\nversion=0.2.0\nsize=770992\n"
	if got != want {
		t.Fatalf("preamble %q, want %q", got, want)
	}
}

// Downgrade protection rests on the version being covered by the signature.
// An attacker holding a validly signed 0.1.0 manifest and image must not be
// able to present them as 0.9.0.
func TestVersionIsBoundIntoTheSignature(t *testing.T) {
	priv := newKey(t)
	old := bytes.Repeat([]byte("old firmware "), 3000)
	m, err := Sign(priv, old, "0.1.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(pubOf(priv), old, m); err != nil {
		t.Fatal(err)
	}
	replay := m
	replay.Version = "0.9.0"
	if err := Verify(pubOf(priv), old, replay); err == nil {
		t.Fatal("an old signed image verified under a newer version")
	}

	// A signature over the bare image (the scheme before versions were
	// signed) must not verify either, or old manifests stay replayable.
	bare := m
	bare.Signature = hex.EncodeToString(ed25519.Sign(priv, old))
	if err := Verify(pubOf(priv), old, bare); err == nil {
		t.Fatal("a bare-image signature verified")
	}
}

func TestImageVersionMarker(t *testing.T) {
	build := func(parts ...string) []byte {
		var b []byte
		b = append(b, bytes.Repeat([]byte{0xE9, 0x00}, 64)...)
		for _, p := range parts {
			b = append(b, p...)
			b = append(b, 0, 0xFF, 0x13)
		}
		return b
	}
	if v, err := ImageVersion(build(VersionMarker + "0.2.0")); err != nil || v != "0.2.0" {
		t.Fatalf("got %q, %v", v, err)
	}
	if v, err := ImageVersion(build(VersionMarker+"0.2.0", VersionMarker+"0.2.0")); err != nil || v != "0.2.0" {
		t.Fatalf("a repeated identical marker: %q, %v", v, err)
	}
	for name, img := range map[string][]byte{
		"no marker":       build("presence terminal"),
		"two versions":    build(VersionMarker+"0.2.0", VersionMarker+"0.3.0"),
		"not a version":   build(VersionMarker + "0.2.0-dev"),
		"unterminated":    append(build(), []byte(VersionMarker+"0.2.0")...),
		"absurdly long":   build(VersionMarker + strings.Repeat("1", 40)),
		"empty version":   build(VersionMarker),
		"leading zero":    build(VersionMarker + "0.02.0"),
		"bare prefix end": []byte(VersionMarker),
	} {
		if v, err := ImageVersion(img); err == nil {
			t.Errorf("%s: accepted %q", name, v)
		}
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

	// Gateway-hosted: no URL, and the signature does not depend on it.
	hosted, err := Sign(priv, img, "0.2.0", "")
	if err != nil {
		t.Fatal(err)
	}
	if hosted.URL != "" || hosted.Signature != m.Signature {
		t.Fatalf("the URL leaked into the signature, or was invented: %+v", hosted)
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
		"empty image":      func() error { _, err := Sign(priv, nil, "1.0.0", "https://x"); return err },
		"no version":       func() error { _, err := Sign(priv, []byte{1}, "", "https://x"); return err },
		"long version":     func() error { _, err := Sign(priv, []byte{1}, strings.Repeat("9", 33), "https://x"); return err },
		"two-part version": func() error { _, err := Sign(priv, []byte{1}, "1.0", "https://x"); return err },
		"dev suffix":       func() error { _, err := Sign(priv, []byte{1}, "0.0.0-dev", "https://x"); return err },
		"ftp url":          func() error { _, err := Sign(priv, []byte{1}, "1.0.0", "ftp://x"); return err },
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

	// Not a regular file, and implausibly large: refused from the handle.
	if _, err := LoadPrivateKeyFile(dir); err == nil {
		t.Fatal("loaded a directory as a key")
	}
	big := filepath.Join(dir, "big.pem")
	os.WriteFile(big, bytes.Repeat([]byte("A"), maxKeyFileBytes+1), 0o600)
	if _, err := LoadPrivateKeyFile(big); err == nil {
		t.Fatal("loaded a 64 KiB key file")
	}
	// The file read is the file checked: a world-readable key behind a
	// symlink is refused, because the mode comes from the open handle.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.pem")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPrivateKeyFile(link); err == nil {
		t.Fatal("loaded a world-readable key through a symlink")
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
// the real file and not just a test fixture. And the key in it must be the
// sentinel or a real key: today it is the sentinel, and this fails the
// moment someone pastes a small-order key.
func TestCommittedHeaderParses(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "firmware", "src", "ota_pubkey.h"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseHeaderKey(string(src))
	if err != nil {
		t.Fatal(err)
	}
	if !IsSentinel(pub) && IsSmallOrder(pub) {
		t.Fatalf("ota_pubkey.h holds a small-order key %x", pub)
	}
}

// Every encoding of a small-order point, canonical and not; the same list as
// kSmallOrderKeys in firmware/test/host_test.cpp, recomputed from the curve.
var smallOrderKeys = []string{
	"0000000000000000000000000000000000000000000000000000000000000000",
	"0000000000000000000000000000000000000000000000000000000000000080",
	"0100000000000000000000000000000000000000000000000000000000000000",
	"0100000000000000000000000000000000000000000000000000000000000080",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
	"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
	"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
	"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
}

func TestSmallOrderKeysAreUnusable(t *testing.T) {
	img := goldenImage()
	forged := make([]byte, 64)
	forged[0] = 0x01 // R = identity, S = 0: verifies under any small-order key in a cofactored check
	sum := sha256.Sum256(img)
	m := model.FirmwareManifest{Available: true, Version: "1.2.3", Size: int64(len(img)),
		SHA256: hex.EncodeToString(sum[:]), Signature: hex.EncodeToString(forged)}
	for _, k := range smallOrderKeys {
		pub := ed25519.PublicKey(mustHex(t, k))
		if !IsUnusable(pub) || !IsSmallOrder(pub) {
			t.Errorf("%s is not flagged", k)
		}
		if err := Verify(pub, img, m); err == nil || !strings.Contains(err.Error(), "sentinel") && !strings.Contains(err.Error(), "small-order") {
			t.Errorf("%s: Verify did not refuse the key itself: %v", k, err)
		}
	}
	near := mustHex(t, smallOrderKeys[4])
	near[0] ^= 1
	if IsUnusable(near) {
		t.Error("a key one bit off an order-8 point was flagged")
	}
	for i := 0; i < 200; i++ {
		if pub := pubOf(newKey(t)); IsUnusable(pub) {
			t.Fatalf("a real key %x was flagged", pub)
		}
	}
}
