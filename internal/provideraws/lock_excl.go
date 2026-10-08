//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package provideraws

import (
	"errors"
	"io/fs"
	"os"
	"time"
)

// staleLockAge is how old a lock file must be before another process may
// break it. A full clone of the provider takes well under this.
const staleLockAge = 30 * time.Minute

// lockFile takes an exclusive lock on path by creating it with O_EXCL. It
// polls until the file is gone. A lock file older than staleLockAge is
// treated as left behind by a crashed run and removed.
func lockFile(path string) (unlock func(), err error) {
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_ = f.Close()
			return func() { _ = os.Remove(path) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) > staleLockAge {
			_ = os.Remove(path)
			continue
		}
		time.Sleep(200 * time.Millisecond)
	}
}
