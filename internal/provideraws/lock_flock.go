//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package provideraws

import (
	"errors"
	"os"
	"syscall"
)

// lockFile takes an exclusive lock on path, creating the file if needed. It
// blocks until the lock is free. The kernel drops the lock when the process
// exits, so a crashed run never leaves the cache locked.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
