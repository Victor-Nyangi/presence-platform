package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"presence/internal/fwsign"
)

func writeHeader(t *testing.T, pub []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ota_pubkey.h")
	src := "static const uint8_t kOtaReleasePublicKey[32] = {\n" + fwsign.CArray(pub) + "};\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// -header must refuse every key a terminal would refuse, so a release can
// never be signed for a header nobody can use, or one anybody can forge for.
func TestHeaderKeyRefusesUnusableKeys(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := headerKey(writeHeader(t, pub)); err != nil || !got.Equal(pub) {
		t.Fatalf("a real key: %v", err)
	}
	if _, err := headerKey(writeHeader(t, make([]byte, 32))); err == nil || !strings.Contains(err.Error(), "unprovisioned") {
		t.Fatalf("sentinel: %v", err)
	}
	for _, k := range []string{
		"0100000000000000000000000000000000000000000000000000000000000000",
		"26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
		"c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
		"ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
		"eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
	} {
		b, _ := hex.DecodeString(k)
		if _, err := headerKey(writeHeader(t, b)); err == nil || !strings.Contains(err.Error(), "small-order") {
			t.Errorf("%s: %v", k, err)
		}
	}
}
