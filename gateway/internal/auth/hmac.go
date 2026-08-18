// Package auth implements device request signing and verification.
//
// Devices hold a 32-byte shared secret issued once at provisioning. Every
// request is signed with HMAC-SHA256 over a canonical string. mTLS would be
// stronger, but client-cert provisioning and rotation on an ESP32 is a real
// time sink; HMAC gives device identity, replay protection and key rotation
// with far less machinery.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// SigVersion prefixes the canonical string so the scheme can evolve
	// without ambiguity.
	SigVersion = "v1"

	// MaxSkew is how far a device clock may be from the server's before the
	// request is rejected. Devices lose power and RTC batteries die, so the
	// rejection is recoverable rather than fatal: see ErrClockSkew.
	MaxSkew = 300 * time.Second

	HeaderDeviceID   = "X-Device-Id"
	HeaderKeyVersion = "X-Key-Version"
	HeaderTimestamp  = "X-Timestamp"
	HeaderNonce      = "X-Nonce"
	HeaderSignature  = "X-Signature"
	HeaderRequestID  = "X-Request-Id"
)

var (
	ErrMissingHeaders = errors.New("auth: missing required signing headers")
	ErrBadTimestamp   = errors.New("auth: malformed timestamp")
	ErrClockSkew      = errors.New("auth: timestamp outside accepted window")
	ErrNonceReplay    = errors.New("auth: nonce already used")
	ErrBadSignature   = errors.New("auth: signature mismatch")
)

// Credentials carries the signing material for one request.
type Credentials struct {
	DeviceID   string
	KeyVersion int
	Timestamp  time.Time
	Nonce      string
	Signature  string
	RequestID  string
}

// CanonicalString builds the exact byte sequence that gets signed.
//
//	v1
//	{METHOD}
//	{PATH}
//	{timestamp_ms}
//	{nonce}
//	{sha256_hex(body)}
//
// Method is upper-cased and the path excludes the query string, so a device
// and server that disagree about query ordering still agree on the signature.
func CanonicalString(method, path string, tsMillis int64, nonce string, body []byte) string {
	sum := sha256.Sum256(body)
	return strings.Join([]string{
		SigVersion,
		strings.ToUpper(method),
		path,
		strconv.FormatInt(tsMillis, 10),
		nonce,
		hex.EncodeToString(sum[:]),
	}, "\n")
}

// Sign returns the hex-encoded HMAC-SHA256 of the canonical string. Exported
// because the device simulator and tests need to produce identical output.
func Sign(secret []byte, method, path string, tsMillis int64, nonce string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(CanonicalString(method, path, tsMillis, nonce, body)))
	return hex.EncodeToString(mac.Sum(nil))
}

// Extract pulls signing headers off a request without validating them.
func Extract(r *http.Request) (Credentials, error) {
	c := Credentials{
		DeviceID:  r.Header.Get(HeaderDeviceID),
		Nonce:     r.Header.Get(HeaderNonce),
		Signature: r.Header.Get(HeaderSignature),
		RequestID: r.Header.Get(HeaderRequestID),
	}
	rawTS := r.Header.Get(HeaderTimestamp)
	if c.DeviceID == "" || c.Nonce == "" || c.Signature == "" || rawTS == "" {
		return c, ErrMissingHeaders
	}
	ms, err := strconv.ParseInt(rawTS, 10, 64)
	if err != nil {
		return c, ErrBadTimestamp
	}
	c.Timestamp = time.UnixMilli(ms)

	// Key version is optional and defaults to 1, so a device that predates
	// rotation keeps working.
	c.KeyVersion = 1
	if kv := r.Header.Get(HeaderKeyVersion); kv != "" {
		n, err := strconv.Atoi(kv)
		if err != nil {
			return c, fmt.Errorf("auth: bad key version %q", kv)
		}
		c.KeyVersion = n
	}
	return c, nil
}

// Verify checks skew, replay and signature, in that order.
//
// Order matters: skew is checked first so a device with a dead RTC gets back
// ErrClockSkew (which the handler answers with the server's time, letting the
// device self-correct) rather than an unhelpful signature error.
//
// candidates holds the secrets to try — normally the current key, plus the
// previous one during rotation so a terminal in the field is never bricked by
// a key roll it hasn't picked up yet.
func Verify(c Credentials, now time.Time, method, path string, body []byte, nonces NonceCache, candidates map[int][]byte) error {
	if delta := now.Sub(c.Timestamp); delta > MaxSkew || delta < -MaxSkew {
		return ErrClockSkew
	}
	secret, ok := candidates[c.KeyVersion]
	if !ok {
		return ErrBadSignature
	}
	want := Sign(secret, method, path, c.Timestamp.UnixMilli(), c.Nonce, body)

	// Constant-time compare: a timing-variable comparison here leaks the
	// signature one byte at a time.
	if !hmac.Equal([]byte(want), []byte(c.Signature)) {
		return ErrBadSignature
	}
	// Replay check happens last, after the signature is known good. Checking
	// it earlier would let an unauthenticated caller poison the cache with
	// nonces a legitimate device might later want to use.
	if !nonces.Claim(c.DeviceID, c.Nonce, now) {
		return ErrNonceReplay
	}
	return nil
}

// NonceCache blocks replay of a captured request inside the skew window.
type NonceCache interface {
	// Claim records the nonce and reports whether it was previously unused.
	Claim(deviceID, nonce string, now time.Time) bool
}

// MemoryNonceCache is a single-process implementation. It is correct for one
// gateway instance; behind a load balancer you need shared state, so swap in
// Redis SETNX with a TTL of MaxSkew*2 before scaling out horizontally.
type MemoryNonceCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	lastPurge time.Time
	ttl       time.Duration
}

func NewMemoryNonceCache() *MemoryNonceCache {
	return &MemoryNonceCache{seen: make(map[string]time.Time), ttl: 2 * MaxSkew}
}

func (m *MemoryNonceCache) Claim(deviceID, nonce string, now time.Time) bool {
	key := deviceID + "\x00" + nonce
	m.mu.Lock()
	defer m.mu.Unlock()

	// Amortised sweep. Nonces are only meaningful for the skew window, so
	// anything older than the TTL cannot be replayed anyway.
	if now.Sub(m.lastPurge) > m.ttl {
		for k, t := range m.seen {
			if now.Sub(t) > m.ttl {
				delete(m.seen, k)
			}
		}
		m.lastPurge = now
	}
	if _, exists := m.seen[key]; exists {
		return false
	}
	m.seen[key] = now
	return true
}
