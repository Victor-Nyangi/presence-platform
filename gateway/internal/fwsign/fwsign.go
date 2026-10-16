// Package fwsign signs firmware images for the terminal's OTA channel.
//
// SPEC §3: OTA is a security boundary. A terminal boots a new image only if
// a detached Ed25519 signature verifies against the public key compiled into
// its current firmware (firmware/src/ota_pubkey.h). This package is the other
// half: it holds the private key for exactly as long as it takes to sign, and
// emits the manifest the gateway serves from GET /v1/device/firmware.
//
// What is signed is Preamble(version, size) followed by the image's exact
// bytes. Signing the version is what gives the terminal downgrade
// protection: it refuses any image whose signed version is not newer than
// what it runs, and a validly signed old image cannot be relabelled as new
// without breaking the signature.
//
// Pure Ed25519 (RFC 8032), not Ed25519ph and not a signature over the
// sha256: the firmware streams the message through SHA-512 itself, so it
// needs no prehash variant, and the sha256 in the manifest is an integrity
// check for a corrupt download, not the thing that is trusted.
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

	"presence/internal/fwversion"
	"presence/internal/model"
)

// PreambleTag starts every signed message. It doubles as domain separation:
// a signature over a bare image (the scheme before versions were signed)
// does not verify under this one.
const PreambleTag = "presence-ota-image/v1\n"

// Preamble is the signed text that precedes the image bytes. It must match
// otaSignedPreamble in firmware/src/ota_verify.h byte for byte; the golden
// vector in fwsign_test.go and host_test.cpp pins the two.
func Preamble(version string, size int64) []byte {
	return []byte(fmt.Sprintf("%sversion=%s\nsize=%d\n", PreambleTag, version, size))
}

func signedMessage(version string, image []byte) []byte {
	pre := Preamble(version, int64(len(image)))
	msg := make([]byte, 0, len(pre)+len(image))
	return append(append(msg, pre...), image...)
}

// VersionMarker prefixes the version string every build embeds
// (kPresenceVersionMarker in firmware/src/main.cpp).
const VersionMarker = "PRESENCE_FW_VERSION="

// ImageVersion returns the version a firmware image says it was built as.
// The release tool compares it with -version, so an image cannot be signed
// under a version it does not run as: the terminal trusts the signed version,
// and a mislabelled release would confuse every comparison after it.
func ImageVersion(image []byte) (string, error) {
	var found string
	rest := image
	for {
		i := bytes.Index(rest, []byte(VersionMarker))
		if i < 0 {
			break
		}
		rest = rest[i+len(VersionMarker):]
		end := bytes.IndexByte(rest, 0)
		if end < 0 || end > fwversion.MaxLen {
			return "", errors.New("version marker is not NUL-terminated within 17 bytes")
		}
		v := string(rest[:end])
		if found != "" && v != found {
			return "", fmt.Errorf("image carries two version markers, %q and %q", found, v)
		}
		found = v
	}
	if found == "" {
		return "", fmt.Errorf("image has no %s marker; is it a presence build from this tree?", VersionMarker)
	}
	if !fwversion.Valid(found) {
		return "", fmt.Errorf("image version %q: %w", found, fwversion.ErrInvalid)
	}
	return found, nil
}

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

// maxKeyFileBytes bounds the read: a PKCS#8 Ed25519 PEM is 119 bytes.
const maxKeyFileBytes = 64 << 10

// LoadPrivateKeyFile reads a key written by WriteNewKeyFile. Like ssh, it
// refuses anything but a regular file owned by the caller that group and
// others cannot read.
//
// The checks run on the open handle (fstat), and the key is read from that
// same handle. Stat-then-open would check one file and read another if the
// path were swapped in between (a symlink, a rename on shared media).
func LoadPrivateKeyFile(path string) (ed25519.PrivateKey, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if err := ownedByCaller(info); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is mode %#o; a signing key must be readable by its owner only (chmod 600)", path, info.Mode().Perm())
	}
	b, err := io.ReadAll(io.LimitReader(f, maxKeyFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxKeyFileBytes {
		return nil, fmt.Errorf("%s is larger than any Ed25519 key file", path)
	}
	return ParsePrivateKeyPEM(b)
}

// Sign produces the manifest for image. It verifies its own signature before
// returning, so a manifest that leaves this function is one a terminal
// holding the matching public key will accept, provided version is newer
// than what that terminal runs.
//
// url is empty for an image the gateway hosts (it fills in its own path when
// it serves the manifest), or an absolute http(s) URL for one hosted
// elsewhere. The URL is not signed; the image is.
func Sign(priv ed25519.PrivateKey, image []byte, version, url string) (model.FirmwareManifest, error) {
	switch {
	case len(image) == 0:
		return model.FirmwareManifest{}, errors.New("empty image")
	case !fwversion.Valid(version):
		return model.FirmwareManifest{}, fmt.Errorf("version %q: %w", version, fwversion.ErrInvalid)
	case url != "" && !strings.HasPrefix(url, "https://") && !strings.HasPrefix(url, "http://"):
		return model.FirmwareManifest{}, errors.New("url must be empty (gateway-hosted) or http(s)")
	}
	sum := sha256.Sum256(image)
	m := model.FirmwareManifest{
		Available: true,
		Version:   version,
		URL:       url,
		Size:      int64(len(image)),
		SHA256:    hex.EncodeToString(sum[:]),
		Signature: hex.EncodeToString(ed25519.Sign(priv, signedMessage(version, image))),
	}
	if err := Verify(priv.Public().(ed25519.PublicKey), image, m); err != nil {
		return model.FirmwareManifest{}, fmt.Errorf("self-check failed: %w", err)
	}
	return m, nil
}

// Verify applies the terminal's checks to an image and its manifest: version
// grammar, size, sha256, then the Ed25519 signature over the preamble and
// the image. It cannot check "newer than the running build"; only a terminal
// knows that. Release scripts run it against the public key in ota_pubkey.h
// before publishing anything.
func Verify(pub ed25519.PublicKey, image []byte, m model.FirmwareManifest) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("public key is not 32 bytes")
	}
	if err := CheckUsableKey(pub); err != nil {
		return err
	}
	if len(image) == 0 {
		return errors.New("empty image")
	}
	if !fwversion.Valid(m.Version) {
		return fmt.Errorf("manifest version %q: %w", m.Version, fwversion.ErrInvalid)
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
	if !ed25519.Verify(pub, signedMessage(m.Version, image), sig) {
		return errors.New("signature does not verify")
	}
	return nil
}

// IsSentinel matches the firmware's "no release key compiled in" placeholder.
func IsSentinel(pub ed25519.PublicKey) bool {
	return bytes.Equal(pub, make([]byte, ed25519.PublicKeySize))
}

// smallOrderY are the y coordinates (x sign bit cleared) of every point of
// order 1, 2, 4 or 8, plus the non-canonical p and p+1. The same list as
// isSmallOrderKey in firmware/src/ota_verify.h.
var smallOrderY = [][]byte{
	mustDecodeHex("0000000000000000000000000000000000000000000000000000000000000000"), // y = 0, order 4
	mustDecodeHex("0100000000000000000000000000000000000000000000000000000000000000"), // y = 1, identity
	mustDecodeHex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"), // order 8
	mustDecodeHex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"), // order 8
	mustDecodeHex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p-1, order 2
	mustDecodeHex("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p, non-canonical 0
	mustDecodeHex("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"), // y = p+1, non-canonical 1
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// IsSmallOrder reports whether pub encodes a point of small order, canonically
// or not (14 encodings). The terminal's verifier is cofactored, so under such
// a key the signature R = identity, S = 0 verifies on every message: a
// small-order release key would let anyone sign firmware.
func IsSmallOrder(pub ed25519.PublicKey) bool {
	if len(pub) != ed25519.PublicKeySize {
		return false
	}
	y := append([]byte(nil), pub...)
	y[31] &= 0x7f
	for _, bad := range smallOrderY {
		if bytes.Equal(y, bad) {
			return true
		}
	}
	return false
}

// IsUnusable is the firmware's isUnusableKey: the sentinel or a small-order
// point. A terminal refuses every update under such a key.
func IsUnusable(pub ed25519.PublicKey) bool { return IsSentinel(pub) || IsSmallOrder(pub) }

// CheckUsableKey explains why a key is unusable, or returns nil.
func CheckUsableKey(pub ed25519.PublicKey) error {
	switch {
	case len(pub) != ed25519.PublicKeySize:
		return errors.New("public key is not 32 bytes")
	case IsSentinel(pub):
		return errors.New("public key is the unprovisioned all-zero sentinel")
	case IsSmallOrder(pub):
		return errors.New("public key is a small-order point; it would accept forged signatures, and terminals refuse it")
	}
	return nil
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
