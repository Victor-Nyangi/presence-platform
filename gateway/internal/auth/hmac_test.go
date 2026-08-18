package auth

import (
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

func TestCanonicalStringShape(t *testing.T) {
	got := CanonicalString("post", "/v1/device/events", 1755500000000, "abc123", []byte(`{"a":1}`))
	lines := strings.Split(got, "\n")
	if len(lines) != 6 {
		t.Fatalf("want 6 lines, got %d: %q", len(lines), got)
	}
	if lines[0] != "v1" {
		t.Errorf("version line = %q", lines[0])
	}
	if lines[1] != "POST" {
		t.Errorf("method should be upper-cased, got %q", lines[1])
	}
	// sha256("{\"a\":1}")
	if len(lines[5]) != 64 {
		t.Errorf("body digest should be 64 hex chars, got %d", len(lines[5]))
	}
}

// The body digest must be part of the signature, otherwise an attacker can
// swap the payload of a captured request while keeping its headers.
func TestSignatureCoversBody(t *testing.T) {
	a := Sign(testSecret, "POST", "/v1/device/events", 1, "n", []byte(`{"seq":1}`))
	b := Sign(testSecret, "POST", "/v1/device/events", 1, "n", []byte(`{"seq":2}`))
	if a == b {
		t.Fatal("signature did not change when body changed")
	}
}

func TestSignatureCoversMethodAndPath(t *testing.T) {
	base := Sign(testSecret, "POST", "/v1/device/events", 1, "n", nil)
	if Sign(testSecret, "GET", "/v1/device/events", 1, "n", nil) == base {
		t.Error("signature did not change with method")
	}
	if Sign(testSecret, "POST", "/v1/device/roster", 1, "n", nil) == base {
		t.Error("signature did not change with path")
	}
}

func signedRequest(t *testing.T, secret []byte, keyVersion int, ts time.Time, nonce string, body []byte) Credentials {
	t.Helper()
	r := httptest.NewRequest("POST", "/v1/device/events", nil)
	r.Header.Set(HeaderDeviceID, "dev-1")
	r.Header.Set(HeaderKeyVersion, strconv.Itoa(keyVersion))
	r.Header.Set(HeaderTimestamp, strconv.FormatInt(ts.UnixMilli(), 10))
	r.Header.Set(HeaderNonce, nonce)
	r.Header.Set(HeaderSignature, Sign(secret, "POST", "/v1/device/events", ts.UnixMilli(), nonce, body))
	c, err := Extract(r)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	return c
}

func TestVerifyHappyPath(t *testing.T) {
	now := time.Now()
	body := []byte(`{"events":[]}`)
	c := signedRequest(t, testSecret, 1, now, "nonce-1", body)

	err := Verify(c, now, "POST", "/v1/device/events", body, NewMemoryNonceCache(), map[int][]byte{1: testSecret})
	if err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

// A device with a dead RTC must get ErrClockSkew specifically, because the
// handler answers that with the server's time so the device can self-correct.
// Returning a generic signature error would strand it permanently.
func TestVerifyClockSkewIsDistinguishable(t *testing.T) {
	now := time.Now()
	for _, offset := range []time.Duration{MaxSkew + time.Second, -(MaxSkew + time.Second)} {
		deviceTime := now.Add(offset)
		c := signedRequest(t, testSecret, 1, deviceTime, "n", nil)
		err := Verify(c, now, "POST", "/v1/device/events", nil, NewMemoryNonceCache(), map[int][]byte{1: testSecret})
		if err != ErrClockSkew {
			t.Errorf("offset %v: want ErrClockSkew, got %v", offset, err)
		}
	}
}

func TestVerifyWithinSkewWindowPasses(t *testing.T) {
	now := time.Now()
	c := signedRequest(t, testSecret, 1, now.Add(-MaxSkew+time.Second), "n", nil)
	if err := Verify(c, now, "POST", "/v1/device/events", nil, NewMemoryNonceCache(), map[int][]byte{1: testSecret}); err != nil {
		t.Fatalf("want nil, got %v", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	now := time.Now()
	cache := NewMemoryNonceCache()
	c := signedRequest(t, testSecret, 1, now, "same-nonce", nil)

	if err := Verify(c, now, "POST", "/v1/device/events", nil, cache, map[int][]byte{1: testSecret}); err != nil {
		t.Fatalf("first use should succeed, got %v", err)
	}
	if err := Verify(c, now, "POST", "/v1/device/events", nil, cache, map[int][]byte{1: testSecret}); err != ErrNonceReplay {
		t.Fatalf("second use: want ErrNonceReplay, got %v", err)
	}
}

// The nonce must only be consumed once the signature is known good, or an
// unauthenticated caller could burn nonces a real device intends to use.
func TestBadSignatureDoesNotConsumeNonce(t *testing.T) {
	now := time.Now()
	cache := NewMemoryNonceCache()

	bad := signedRequest(t, []byte("wrong-secret-wrong-secret-wrong!"), 1, now, "nonce-x", nil)
	if err := Verify(bad, now, "POST", "/v1/device/events", nil, cache, map[int][]byte{1: testSecret}); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}

	good := signedRequest(t, testSecret, 1, now, "nonce-x", nil)
	if err := Verify(good, now, "POST", "/v1/device/events", nil, cache, map[int][]byte{1: testSecret}); err != nil {
		t.Fatalf("legitimate reuse of that nonce should still work, got %v", err)
	}
}

// During rotation the server accepts both generations, so a terminal that has
// not yet picked up the new key is not bricked.
func TestVerifyAcceptsPreviousKeyVersion(t *testing.T) {
	now := time.Now()
	oldSecret := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	candidates := map[int][]byte{2: testSecret, 1: oldSecret}

	c := signedRequest(t, oldSecret, 1, now, "n1", nil)
	if err := Verify(c, now, "POST", "/v1/device/events", nil, NewMemoryNonceCache(), candidates); err != nil {
		t.Fatalf("old key should still verify during rotation, got %v", err)
	}
	c2 := signedRequest(t, testSecret, 2, now, "n2", nil)
	if err := Verify(c2, now, "POST", "/v1/device/events", nil, NewMemoryNonceCache(), candidates); err != nil {
		t.Fatalf("new key should verify, got %v", err)
	}
}

func TestVerifyRejectsUnknownKeyVersion(t *testing.T) {
	now := time.Now()
	c := signedRequest(t, testSecret, 9, now, "n", nil)
	if err := Verify(c, now, "POST", "/v1/device/events", nil, NewMemoryNonceCache(), map[int][]byte{1: testSecret}); err != ErrBadSignature {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
}

func TestExtractRequiresHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/device/events", nil)
	if _, err := Extract(r); err != ErrMissingHeaders {
		t.Fatalf("want ErrMissingHeaders, got %v", err)
	}
}

func TestExtractDefaultsKeyVersionToOne(t *testing.T) {
	r := httptest.NewRequest("POST", "/v1/device/events", nil)
	r.Header.Set(HeaderDeviceID, "d")
	r.Header.Set(HeaderNonce, "n")
	r.Header.Set(HeaderSignature, "s")
	r.Header.Set(HeaderTimestamp, "1755500000000")
	c, err := Extract(r)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if c.KeyVersion != 1 {
		t.Errorf("want default key version 1, got %d", c.KeyVersion)
	}
}

func TestNonceCacheIsolatesDevices(t *testing.T) {
	cache := NewMemoryNonceCache()
	now := time.Now()
	if !cache.Claim("device-a", "shared", now) {
		t.Fatal("first claim should succeed")
	}
	if !cache.Claim("device-b", "shared", now) {
		t.Fatal("a different device using the same nonce must not collide")
	}
	if cache.Claim("device-a", "shared", now) {
		t.Fatal("same device reusing a nonce must be rejected")
	}
}
