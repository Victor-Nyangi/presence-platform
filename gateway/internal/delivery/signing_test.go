package delivery

import "testing"

// Golden vector, independent of this package's own implementation — the hex
// digest below was computed with `openssl dgst -sha256 -hmac`, not with
// SignatureHeader itself, mirroring the discipline internal/auth uses for
// the device protocol's own canonical-string vector: a signing format bug
// that happens to be self-consistent (wrong on both the "compute" and
// "check" sides) would slip past a test that only compares the function
// against itself.
//
//	key:     test-secret
//	message: 1755500000000.hello
//	openssl dgst -sha256 -hmac test-secret <<< printf '1755500000000.hello'
const goldenHexDigest = "310920cfe8710ad18c10f072b00120d1e751be2f91e51741db1bab4b47bcfc39"

func TestSignatureHeaderGoldenVector(t *testing.T) {
	got := SignatureHeader([]byte("test-secret"), 1755500000000, []byte("hello"))
	want := "t=1755500000000,v1=" + goldenHexDigest
	if got != want {
		t.Fatalf("golden vector drift:\n got %q\nwant %q", got, want)
	}
}

func TestVerifySignatureHeaderRoundTrips(t *testing.T) {
	secret := []byte("test-secret")
	body := []byte(`{"event_id":"abc"}`)
	header := SignatureHeader(secret, 1755500000000, body)

	if !VerifySignatureHeader(secret, header, body) {
		t.Error("a header produced by SignatureHeader must verify against the same secret and body")
	}
	if VerifySignatureHeader([]byte("wrong-secret"), header, body) {
		t.Error("must not verify against the wrong secret")
	}
	if VerifySignatureHeader(secret, header, []byte(`{"event_id":"tampered"}`)) {
		t.Error("must not verify a body that was tampered with after signing")
	}
	if VerifySignatureHeader(secret, "garbage", body) {
		t.Error("must not verify a malformed header")
	}
}

func TestCutHeaderHandlesFieldOrderAndExtraFields(t *testing.T) {
	// A consumer's own implementation, or a future revision here, might not
	// preserve field order — the parser must not depend on it.
	ts, sig, ok := cutHeader("v1=abc,t=123")
	if !ok || ts != "123" || sig != "abc" {
		t.Errorf("cutHeader(reordered) = (%q,%q,%v)", ts, sig, ok)
	}
	if _, _, ok := cutHeader("v1=abc"); ok {
		t.Error("must not accept a header missing the timestamp field")
	}
	if _, _, ok := cutHeader(""); ok {
		t.Error("must not accept an empty header")
	}
}
