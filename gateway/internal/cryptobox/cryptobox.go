// Package cryptobox wraps AES-256-GCM for the two secrets this system stores
// at rest: device HMAC keys and biometric templates.
//
// Why encryption and not hashing, for device secrets: HMAC verification
// requires the server to possess the raw key. A hash would be unverifiable.
// Bearer-style values that the client presents verbatim (the one-time
// provisioning token) ARE hashed — see HashToken.
//
// Biometric templates are encrypted because a template is personal data under
// most data-protection regimes. Fingerprint IMAGES are never stored, never
// transmitted, and never leave the sensor module.
package cryptobox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

var (
	ErrKeyUnknown = errors.New("cryptobox: unknown key id")
	ErrKeySize    = errors.New("cryptobox: key must be 32 bytes")
)

// Keyring holds versioned keys so you can rotate the KEK without a downtime
// window: new writes use the primary, old rows still decrypt under their
// recorded key id.
type Keyring struct {
	primary string
	keys    map[string][]byte
}

func NewKeyring(primaryID string, keys map[string][]byte) (*Keyring, error) {
	if _, ok := keys[primaryID]; !ok {
		return nil, fmt.Errorf("cryptobox: primary key %q not in keyring", primaryID)
	}
	for id, k := range keys {
		if len(k) != 32 {
			return nil, fmt.Errorf("%w (key %q is %d)", ErrKeySize, id, len(k))
		}
	}
	return &Keyring{primary: primaryID, keys: keys}, nil
}

func (r *Keyring) PrimaryID() string { return r.primary }

// Seal encrypts plaintext under the primary key. aad binds the ciphertext to
// its context (we pass the device or credential id) so a row cannot be lifted
// from one record and pasted into another.
func (r *Keyring) Seal(plaintext, aad []byte) (ciphertext, nonce []byte, keyID string, err error) {
	key := r.keys[r.primary]
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, "", err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, "", err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nonce, r.primary, nil
}

func (r *Keyring) Open(ciphertext, nonce []byte, keyID string, aad []byte) ([]byte, error) {
	key, ok := r.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrKeyUnknown, keyID)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// HashToken is for values the client presents verbatim and the server only
// ever compares: the one-time provisioning token. Peppered SHA-256 rather
// than a slow KDF, because these are 32 bytes of CSPRNG output, not
// human-chosen passwords — there is no dictionary to defend against.
func HashToken(pepper, token []byte) []byte {
	h := sha256.New()
	h.Write(pepper)
	h.Write(token)
	return h.Sum(nil)
}

// ProvisionTokenBytes is the length of a provisioning token: 32 bytes of
// CSPRNG output, carried on the wire (X-Provision-Token) and on the label as
// 64 hex digits.
const ProvisionTokenBytes = 32

// ErrTokenFormat is returned for a provisioning token that is not exactly 64
// hex digits.
var ErrTokenFormat = errors.New("cryptobox: provisioning token is not 64 hex digits")

// HashProvisionToken hashes a provisioning token as presented in
// X-Provision-Token. It hashes the 32 DECODED bytes, not the hex text
// (decided 2026-10-19, docs/wifi-provisioning.md): one token has one digest
// whether it was typed in upper or lower case, and the stored hash is a
// function of the secret itself, not of how it happened to be spelled.
// Issuing a token (storing provision_token_hash) and exchanging one at POST
// /v1/device/provision must both go through this function, never through
// HashToken on the header text, or no token will ever match.
func HashProvisionToken(pepper []byte, tokenHex string) ([]byte, error) {
	if len(tokenHex) != 2*ProvisionTokenBytes {
		return nil, ErrTokenFormat
	}
	raw, err := hex.DecodeString(tokenHex)
	if err != nil {
		return nil, ErrTokenFormat
	}
	defer clear(raw)
	return HashToken(pepper, raw), nil
}

// SecretFingerprint is the first 4 bytes of SHA-512 over a device secret, as
// 8 lower-case hex digits: enough to check by eye that a bench terminal holds
// the secret seed issued (the firmware's BENCH-SECRET prints the same value;
// one golden vector pins both), nowhere near enough to recover it.
func SecretFingerprint(secret []byte) string {
	sum := sha512.Sum512(secret)
	return hex.EncodeToString(sum[:4])
}

// EqualToken compares in constant time.
func EqualToken(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// NewSecret returns 32 bytes of CSPRNG output and its hex form.
func NewSecret() ([]byte, string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, "", err
	}
	return b, hex.EncodeToString(b), nil
}
