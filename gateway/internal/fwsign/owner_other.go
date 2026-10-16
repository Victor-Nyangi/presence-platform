//go:build !unix

package fwsign

import "os"

// ownedByCaller: no portable owner check outside unix; the mode check still
// runs.
func ownedByCaller(os.FileInfo) error { return nil }
