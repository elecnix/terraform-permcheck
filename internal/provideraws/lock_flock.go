//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd

package provideraws

import (
	"errors"
	"os"
	"syscall"
	"time"
)

// lockFile takes an exclusive lock on path, creating the file if needed. It
// blocks until the lock is free, and says so after lockWaitNotice. The
// kernel drops the lock when the process exits, so a crashed run never
// leaves the cache locked.
func lockFile(path string) (unlock func(), err error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		return nil, err
	}
	err = flock(f, syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) {
		notice := time.AfterFunc(lockWaitNotice, func() { sayWaiting(path, "") })
		err = flock(f, syscall.LOCK_EX)
		notice.Stop()
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

// flock applies how to f, retrying when a signal interrupts the call.
func flock(f *os.File, how int) error {
	for {
		err := syscall.Flock(int(f.Fd()), how)
		if !errors.Is(err, syscall.EINTR) {
			return err
		}
	}
}
