//go:build !(darwin || dragonfly || freebsd || linux || netbsd || openbsd)

package provideraws

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"time"
)

// staleLockAge is how old a lock file must be before another process may
// break it. A full clone of the provider takes well under this.
const staleLockAge = 30 * time.Minute

// lockFile takes an exclusive lock on path by creating it with O_EXCL. It
// polls until the file is gone, and says so after lockWaitNotice. The
// holder refreshes the file's modification time while it holds the lock, so
// a lock file older than staleLockAge was left behind by a crashed run, and
// is removed.
func lockFile(path string) (unlock func(), err error) {
	start := time.Now()
	said := false
	for {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
		if err == nil {
			_ = f.Close()
			// Refresh the lock while it is held, so a clone that runs longer
			// than staleLockAge is not taken for a crashed run.
			stop := keepFresh(path, staleLockAge/10)
			return func() {
				stop()
				_ = os.Remove(path)
			}, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, err
		}
		info, statErr := os.Stat(path)
		if statErr == nil && time.Since(info.ModTime()) > staleLockAge {
			_ = os.Remove(path)
			continue
		}
		if !said && time.Since(start) >= lockWaitNotice {
			said = true
			detail := "if no other run is active, delete the file to go on"
			if statErr == nil {
				left := (staleLockAge - time.Since(info.ModTime())).Round(time.Second)
				detail = fmt.Sprintf("a lock left by a crashed run expires in %v; if no other run is active, delete the file to go on now", left)
			}
			sayWaiting(path, detail)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
