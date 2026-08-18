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
