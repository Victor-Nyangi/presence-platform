package cryptobox

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func ring(t *testing.T) *Keyring {
	t.Helper()
	k1 := bytes.Repeat([]byte{0x11}, 32)
	k2 := bytes.Repeat([]byte{0x22}, 32)
	r, err := NewKeyring("k2", map[string][]byte{"k1": k1, "k2": k2})
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	return r
}

func TestSealOpenRoundTrip(t *testing.T) {
	r := ring(t)
	secret := []byte("device-hmac-secret-32-bytes-long")

	ct, nonce, keyID, err := r.Seal(secret, []byte("device-1"))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if keyID != "k2" {
		t.Errorf("new writes should use the primary key, got %q", keyID)
	}
	if bytes.Contains(ct, secret) {
		t.Fatal("plaintext is visible in the ciphertext")
	}

	got, err := r.Open(ct, nonce, keyID, []byte("device-1"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("round trip changed the plaintext")
	}
}

// The AAD is what stops a stolen secret row being pasted into another
// device's row to impersonate it.
func TestOpenFailsWithWrongAAD(t *testing.T) {
	r := ring(t)
	ct, nonce, keyID, _ := r.Seal([]byte("secret"), []byte("device-1"))

	if _, err := r.Open(ct, nonce, keyID, []byte("device-2")); err == nil {
		t.Fatal("ciphertext bound to device-1 must not open as device-2")
	}
}

func TestOpenFailsOnTamper(t *testing.T) {
	r := ring(t)
	ct, nonce, keyID, _ := r.Seal([]byte("secret"), []byte("d"))
	ct[0] ^= 0xFF

	if _, err := r.Open(ct, nonce, keyID, []byte("d")); err == nil {
		t.Fatal("GCM must reject a modified ciphertext")
	}
}

// Rotation: rows written under an old KEK must still decrypt after the
// primary moves on, or a key roll becomes a mass re-encryption outage.
func TestOldKeyStillDecryptsAfterRotation(t *testing.T) {
	k1 := bytes.Repeat([]byte{0x11}, 32)
	old, err := NewKeyring("k1", map[string][]byte{"k1": k1})
	if err != nil {
		t.Fatal(err)
	}
	ct, nonce, keyID, _ := old.Seal([]byte("legacy"), []byte("d"))

	rotated := ring(t) // primary is now k2, k1 retained
	got, err := rotated.Open(ct, nonce, keyID, []byte("d"))
	if err != nil {
		t.Fatalf("old ciphertext should still open: %v", err)
	}
	if string(got) != "legacy" {
		t.Fatalf("got %q", got)
	}
}

func TestUnknownKeyIDIsReported(t *testing.T) {
	r := ring(t)
	ct, nonce, _, _ := r.Seal([]byte("x"), nil)
	if _, err := r.Open(ct, nonce, "k9", nil); err == nil {
		t.Fatal("want an error for an unknown key id")
	}
}

func TestKeyringRejectsBadInput(t *testing.T) {
	if _, err := NewKeyring("missing", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)}); err == nil {
		t.Error("primary key not in the ring should fail fast")
	}
	if _, err := NewKeyring("k1", map[string][]byte{"k1": []byte("too short")}); err == nil {
		t.Error("a non-32-byte key should fail fast")
	}
}

func TestNoncesAreUnique(t *testing.T) {
	r := ring(t)
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		_, nonce, _, err := r.Seal([]byte("x"), nil)
		if err != nil {
			t.Fatal(err)
		}
		// GCM nonce reuse under the same key is catastrophic, not merely bad.
		if seen[string(nonce)] {
			t.Fatal("nonce reused")
		}
		seen[string(nonce)] = true
	}
}

func TestTokenHashing(t *testing.T) {
	pepper := []byte("pepper")
	a := HashToken(pepper, []byte("token"))
	b := HashToken(pepper, []byte("token"))
	c := HashToken(pepper, []byte("other"))

	if !EqualToken(a, b) {
		t.Error("same input should hash equal")
	}
	if EqualToken(a, c) {
		t.Error("different tokens must not collide")
	}
	if EqualToken(HashToken([]byte("p2"), []byte("token")), a) {
		t.Error("the pepper must affect the digest")
	}
}

// The provisioning token is hashed as its 32 decoded bytes, not its hex text
// (decided 2026-10-19). The digest is pinned so a later "simplification" to
// HashToken(pepper, []byte(header)) fails here rather than at every install.
func TestHashProvisionTokenHashesTheDecodedBytes(t *testing.T) {
	pepper := []byte("pepper")
	const tokenHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	raw, _ := hex.DecodeString(tokenHex)

	got, err := HashProvisionToken(pepper, tokenHex)
	if err != nil {
		t.Fatal(err)
	}
	// sha256("pepper" || 00 01 .. 1f)
	const golden = "08cfaaf62bf7a451cf0c91b3b6e40c5d4c0960c0c4361b260835fb1a825de0f8"
	if hex.EncodeToString(got) != golden {
		t.Fatalf("digest = %x, want %s", got, golden)
	}
	if !EqualToken(got, HashToken(pepper, raw)) {
		t.Error("should equal HashToken over the decoded bytes")
	}
	if EqualToken(got, HashToken(pepper, []byte(tokenHex))) {
		t.Error("must not equal HashToken over the hex text")
	}

	upper, err := HashProvisionToken(pepper, strings.ToUpper(tokenHex))
	if err != nil || !EqualToken(upper, got) {
		t.Error("upper-case hex is the same token and must hash the same")
	}

	for _, bad := range []string{
		"",
		tokenHex[:63],
		tokenHex[:62],
		tokenHex + "00",
		tokenHex[:62] + "zz",
		" " + tokenHex[:63],
		"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", // base64 of the same bytes
	} {
		if _, err := HashProvisionToken(pepper, bad); !errors.Is(err, ErrTokenFormat) {
			t.Errorf("HashProvisionToken(%q) err = %v, want ErrTokenFormat", bad, err)
		}
	}
}

// The same golden vector is in firmware/test/host_test.cpp
// (benchSecretFingerprint), so seed's printout and the terminal's
// BENCH-SECRET OK line agree.
func TestSecretFingerprintGoldenVector(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	if got := SecretFingerprint(secret); got != "3d94eea4" {
		t.Fatalf("fingerprint = %s, want 3d94eea4", got)
	}
	secret[31] ^= 1
	if SecretFingerprint(secret) == "3d94eea4" {
		t.Error("a flipped bit must change the fingerprint")
	}
}

func TestNewSecretIsRandomAndCorrectLength(t *testing.T) {
	a, aHex, err := NewSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _, _ := NewSecret()
	if len(a) != 32 {
		t.Fatalf("want 32 bytes, got %d", len(a))
	}
	if len(aHex) != 64 {
		t.Fatalf("want 64 hex chars, got %d", len(aHex))
	}
	if bytes.Equal(a, b) {
		t.Fatal("two generated secrets were identical")
	}
}
