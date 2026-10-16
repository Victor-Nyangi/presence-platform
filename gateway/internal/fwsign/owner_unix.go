//go:build unix

package fwsign

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// ownedByCaller refuses a key file someone else owns: they could replace it,
// or read it through a group they control.
func ownedByCaller(info os.FileInfo) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the file owner")
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("owned by uid %d, not by you (uid %d)", st.Uid, os.Getuid())
	}
	return nil
}
