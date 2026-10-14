// Package fwsign signs firmware images for the terminal's OTA channel.
//
// SPEC §3: OTA is a security boundary. A terminal boots a new image only if
// a detached Ed25519 signature over the image's exact bytes verifies against
// the public key compiled into its current firmware
// (firmware/src/ota_pubkey.h). This package is the other half: it holds the
// private key for exactly as long as it takes to sign, and emits the
// manifest the gateway serves from GET /v1/device/firmware.
//
// Pure Ed25519 (RFC 8032), not Ed25519ph and not a signature over the
// sha256: the firmware streams the image through SHA-512 itself, so it needs
// no prehash variant, and the sha256 in the manifest is an integrity check
// for a corrupt download, not the thing that is trusted.
//
// The private key never belongs in a repository. See docs/ota-signing.md.
package fwsign

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"presence/internal/model"
)

const pemType = "PRIVATE KEY" // PKCS#8, the same as `openssl genpkey -algorithm ed25519`

// GenerateKey returns a new key pair, the private half PKCS#8 PEM-encoded.
func GenerateKey(rand io.Reader) (ed25519.PublicKey, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand)
	if err != nil {
		return nil, nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pub, pem.EncodeToMemory(&pem.Block{Type: pemType, Bytes: der}), nil
}

// ParsePrivateKeyPEM accepts a PKCS#8 Ed25519 key and nothing else.
func ParsePrivateKeyPEM(b []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(b)
	if block == nil || block.Type != pemType {
		return nil, errors.New("not a PEM \"PRIVATE KEY\" (PKCS#8) block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is %T, not Ed25519", key)
	}
	return priv, nil
}

// insideGitWorkTree reports whether dir or any parent holds a .git entry.
func insideGitWorkTree(dir string) bool {
	for {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			return true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return false
		}
		dir = parent
	}
}

// WriteNewKeyFile writes a private key with mode 0600. It refuses to
// overwrite an existing file (a lost release key strands every terminal
// that trusts it) and refuses any path inside a git work tree, so the key
// cannot be committed by accident from a checkout.
func WriteNewKeyFile(path string, pemBytes []byte) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if insideGitWorkTree(filepath.Dir(abs)) {
		return fmt.Errorf("%s is inside a git work tree; keep the private key offline, outside any repository", abs)
	}
	f, err := os.OpenFile(abs, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(pemBytes); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// LoadPrivateKeyFile reads a key written by WriteNewKeyFile. Like ssh, it
// refuses a file that group or others can read.
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %#o; a signing key must be readable by its owner only (chmod 600)", path, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateKeyPEM(b)
}

// Sign produces the manifest for image. It verifies its own signature before
// returning, so a manifest that leaves this function is one a terminal
// holding the matching public key will accept.
func Sign(priv ed25519.PrivateKey, image []byte, version, url string) (model.FirmwareManifest, error) {
	switch {
	case len(image) == 0:
		return model.FirmwareManifest{}, errors.New("empty image")
	case version == "" || len(version) > 32:
		return model.FirmwareManifest{}, errors.New("version must be 1-32 characters")
	case !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://"):
		return model.FirmwareManifest{}, errors.New("url must be http(s)")
	}
	sum := sha256.Sum256(image)
	m := model.FirmwareManifest{
		Available: true,
		Version:   version,
		URL:       url,
		Size:      int64(len(image)),
		SHA256:    hex.EncodeToString(sum[:]),
		Signature: hex.EncodeToString(ed25519.Sign(priv, image)),
	}
	if err := Verify(priv.Public().(ed25519.PublicKey), image, m); err != nil {
		return model.FirmwareManifest{}, fmt.Errorf("self-check failed: %w", err)
	}
	return m, nil
}

// Verify applies the terminal's checks to an image and its manifest: size,
// sha256, then the Ed25519 signature. Release scripts run it against the
// public key in ota_pubkey.h before publishing anything.
func Verify(pub ed25519.PublicKey, image []byte, m model.FirmwareManifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key is not 32 bytes")
	}
	if IsUnprovisioned(pub) {
		return errors.New("public key is the unprovisioned all-zero sentinel")
	}
	if len(image) == 0 {
		return errors.New("empty image")
	}
	if m.Size != int64(len(image)) {
		return fmt.Errorf("manifest size %d, image is %d bytes", m.Size, len(image))
	}
	sum := sha256.Sum256(image)
	if m.SHA256 != hex.EncodeToString(sum[:]) {
		return errors.New("sha256 does not match manifest")
	}
	sig, err := hex.DecodeString(m.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return errors.New("signature is not 128 hex characters")
	}
	if !ed25519.Verify(pub, image, sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// IsUnprovisioned matches the firmware's "no release key compiled in" sentinel.
func IsUnprovisioned(pub ed25519.PublicKey) bool {
	return bytes.Equal(pub, make([]byte, ed25519.PublicKeySize))
}

// WriteManifest writes m as JSON. HTML escaping is off: Go would otherwise
// write & in a URL as \u0026, which the firmware's deliberately small JSON
// reader refuses.
func WriteManifest(w io.Writer, m model.FirmwareManifest) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(m)
}

// CArray renders pub as the initializer body for kOtaReleasePublicKey.
func CArray(pub ed25519.PublicKey) string {
	var b strings.Builder
	for i, c := range pub {
		if i%12 == 0 {
			b.WriteString("    ")
		}
		fmt.Fprintf(&b, "0x%02x,", c)
		if i%12 == 11 || i == len(pub)-1 {
			b.WriteString("\n")
		} else {
			b.WriteString(" ")
		}
	}
	return b.String()
}

var headerKey = regexp.MustCompile(`kOtaReleasePublicKey\[32\]\s*=\s*\{([^}]*)\}`)
var headerByte = regexp.MustCompile(`0x([0-9a-fA-F]{2})`)

// ParseHeaderKey extracts kOtaReleasePublicKey from the source of
// firmware/src/ota_pubkey.h, so a release can be checked against the key the
// firmware actually compiles in rather than one someone remembers.
func ParseHeaderKey(src string) (ed25519.PublicKey, error) {
	m := headerKey.FindStringSubmatch(src)
	if m == nil {
		return nil, errors.New("kOtaReleasePublicKey[32] initializer not found")
	}
	body := m[1]
	// Strip comments so a commented-out old key cannot be read as bytes.
	body = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(body, "")
	body = regexp.MustCompile(`//[^\n]*`).ReplaceAllString(body, "")
	var out []byte
	for _, b := range headerByte.FindAllStringSubmatch(body, -1) {
		v, _ := hex.DecodeString(b[1])
		out = append(out, v[0])
	}
	if len(out) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("kOtaReleasePublicKey has %d bytes, want 32", len(out))
	}
	return ed25519.PublicKey(out), nil
}
