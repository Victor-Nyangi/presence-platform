// Package delivery drains outbox_event and pushes signed events to the one
// configured downstream endpoint: at-least-once, with retry/backoff and a
// dead-letter path.
package delivery

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// Headers a delivery carries. Named after the device protocol's own
// X-Device-Id/X-Signature headers (internal/auth) but distinct, since this
// is presence-platform acting as an HTTP client, not a server verifying one.
const (
	HeaderEventID   = "X-Presence-Event-Id" // the idempotency key; == outbox_event.id
	HeaderEventType = "X-Presence-Event-Type"
	HeaderSignature = "X-Presence-Signature"
)

// SignatureHeader returns the X-Presence-Signature value:
//
//	t=<unix_ms>,v1=<hex hmac-sha256(secret, "<t>.<body>")>
//
// Same shape Stripe and GitHub use for outbound webhook signing, and the
// same shape fhir-facade's own Subscription delivery already uses
// (internal/subscription/signing.go there) — chosen for the same reason: it
// lets a consumer verify both authenticity and freshness without this
// service needing a nonce-replay cache of its own. Checking the timestamp
// window is the receiver's job, same as those providers' schemes; this
// service only supplies it.
func SignatureHeader(secret []byte, tsMillis int64, body []byte) string {
	return fmt.Sprintf("t=%d,v1=%s", tsMillis, sign(secret, tsMillis, body))
}

func sign(secret []byte, tsMillis int64, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(strconv.FormatInt(tsMillis, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifySignatureHeader is exported for tests and for anyone standing up a
// reference consumer — this service is the sender, not the verifier, in
// production, but the format needs to be checkable independent of a live
// HTTP round trip.
func VerifySignatureHeader(secret []byte, header string, body []byte) bool {
	tsPart, sigPart, ok := cutHeader(header)
	if !ok {
		return false
	}
	ts, err := strconv.ParseInt(tsPart, 10, 64)
	if err != nil {
		return false
	}
	want := sign(secret, ts, body)
	return hmac.Equal([]byte(want), []byte(sigPart))
}

// cutHeader splits "t=123,v1=abc" into ("123", "abc", true).
func cutHeader(header string) (ts, sig string, ok bool) {
	for _, part := range strings.Split(header, ",") {
		k, v, found := strings.Cut(part, "=")
		if !found {
			continue
		}
		switch k {
		case "t":
			ts = v
		case "v1":
			sig = v
		}
	}
	return ts, sig, ts != "" && sig != ""
}
