// Command fwsign manages the OTA release key and signs firmware images.
//
//	fwsign keygen -out /offline/presence-ota-release.pem
//	fwsign pubkey -key /offline/presence-ota-release.pem
//	fwsign sign   -key /offline/presence-ota-release.pem -image firmware.bin \
//	              -version 0.2.0 -header ../firmware/src/ota_pubkey.h > manifest.json
//	fwsign verify -image firmware.bin -manifest manifest.json \
//	              -header ../firmware/src/ota_pubkey.h
//
// keygen refuses to write inside a git work tree or over an existing file;
// sign and pubkey refuse a key file readable by group or others. The private
// key lives offline, never in this repository: docs/ota-signing.md has the
// procedure, including rotation.
//
// Pass -header to sign so it fails if the key does not match the public key
// the firmware compiles in. Without that check it is possible to publish an
// image that every terminal will (correctly) refuse.
//
// -version is signed, and terminals refuse anything not newer than what they
// run, so sign and verify both require it to equal the version the image was
// built as (its PRESENCE_FW_VERSION marker). Leave -url out for an image the
// gateway hosts from PRESENCE_FIRMWARE_DIR; the gateway supplies the path.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"presence/internal/fwsign"
	"presence/internal/model"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "pubkey":
		err = pubkey(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "fwsign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fwsign keygen|pubkey|sign|verify [flags]  (fwsign <cmd> -h for flags)")
	os.Exit(2)
}

func printPublicKey(pub ed25519.PublicKey) {
	fmt.Printf("public key: %s\n\n", hex.EncodeToString(pub))
	fmt.Printf("Paste into firmware/src/ota_pubkey.h:\n\nstatic const uint8_t kOtaReleasePublicKey[32] = {\n%s};\n", fwsign.CArray(pub))
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "where to write the PRIVATE key (offline media, outside any repository)")
	fs.Parse(args)
	if *out == "" {
		return errors.New("-out is required")
	}
	pub, pemBytes, err := fwsign.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err := fwsign.WriteNewKeyFile(*out, pemBytes); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "private key written to %s (mode 0600). Back it up offline; do not commit it.\n", *out)
	printPublicKey(pub)
	return nil
}

func pubkey(args []string) error {
	fs := flag.NewFlagSet("pubkey", flag.ExitOnError)
	key := fs.String("key", "", "private key file")
	fs.Parse(args)
	priv, err := fwsign.LoadPrivateKeyFile(*key)
	if err != nil {
		return err
	}
	printPublicKey(priv.Public().(ed25519.PublicKey))
	return nil
}

func headerKey(path string) (ed25519.PublicKey, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pub, err := fwsign.ParseHeaderKey(string(src))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	switch {
	case fwsign.IsSentinel(pub):
		return nil, fmt.Errorf("%s holds the unprovisioned all-zero key; every terminal built from it refuses all updates", path)
	case fwsign.IsSmallOrder(pub):
		return nil, fmt.Errorf("%s holds a small-order key, which accepts forged signatures; every terminal built from it refuses all updates", path)
	}
	return pub, nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	key := fs.String("key", "", "private key file")
	image := fs.String("image", "", "firmware image (.pio/build/<env>/firmware.bin)")
	version := fs.String("version", "", "MAJOR.MINOR.PATCH; must equal the FIRMWARE_VERSION the image was built with")
	url := fs.String("url", "", "absolute URL of an externally hosted image; omit when the gateway hosts it")
	header := fs.String("header", "", "firmware/src/ota_pubkey.h; fail unless the key matches it")
	fs.Parse(args)

	priv, err := fwsign.LoadPrivateKeyFile(*key)
	if err != nil {
		return err
	}
	if *header != "" {
		want, err := headerKey(*header)
		if err != nil {
			return err
		}
		if !want.Equal(priv.Public()) {
			return fmt.Errorf("signing key does not match %s; terminals would reject this image", *header)
		}
	}
	img, err := os.ReadFile(*image)
	if err != nil {
		return err
	}
	if err := checkImageVersion(img, *version); err != nil {
		return err
	}
	m, err := fwsign.Sign(priv, img, *version, *url)
	if err != nil {
		return err
	}
	return fwsign.WriteManifest(os.Stdout, m)
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	image := fs.String("image", "", "firmware image")
	manifest := fs.String("manifest", "", "manifest JSON from fwsign sign")
	header := fs.String("header", "", "firmware/src/ota_pubkey.h to verify against")
	pubHex := fs.String("pub", "", "or: the public key as 64 hex characters")
	fs.Parse(args)

	var pub ed25519.PublicKey
	switch {
	case *header != "":
		p, err := headerKey(*header)
		if err != nil {
			return err
		}
		pub = p
	case *pubHex != "":
		b, err := hex.DecodeString(*pubHex)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return errors.New("-pub must be 64 hex characters")
		}
		pub = b
	default:
		return errors.New("one of -header or -pub is required")
	}

	img, err := os.ReadFile(*image)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*manifest)
	if err != nil {
		return err
	}
	var m model.FirmwareManifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return err
	}
	if err := checkImageVersion(img, m.Version); err != nil {
		return err
	}
	if err := fwsign.Verify(pub, img, m); err != nil {
		return err
	}
	fmt.Printf("ok: version %s verifies against %s\n", m.Version, hex.EncodeToString(pub))
	return nil
}

// checkImageVersion refuses to sign (or bless) an image under a version it was
// not built as. Terminals trust the signed version for downgrade protection,
// so a 0.2.0 build signed as 0.3.0 would install, report 0.2.0, and be offered
// 0.3.0 again on every heartbeat.
func checkImageVersion(img []byte, version string) error {
	built, err := fwsign.ImageVersion(img)
	if err != nil {
		return err
	}
	if built != version {
		return fmt.Errorf("the image was built as %s, not %s; set FIRMWARE_VERSION in platformio.ini and rebuild", built, version)
	}
	return nil
}
