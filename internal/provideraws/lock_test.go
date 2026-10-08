package provideraws

import (
	"bytes"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// syncBuffer is a bytes.Buffer safe for one writer and one reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestLockFile_SaysWhileWaiting checks that a run waiting for the provider
// cache lock says so, naming the lock file, instead of hanging in silence.
func TestLockFile_SaysWhileWaiting(t *testing.T) {
	var out syncBuffer
	origOut, origNotice := lockWaitOutput, lockWaitNotice
	lockWaitOutput, lockWaitNotice = &out, 10*time.Millisecond
	t.Cleanup(func() { lockWaitOutput, lockWaitNotice = origOut, origNotice })

	path := filepath.Join(t.TempDir(), "cache.lock")
	unlock, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan error, 1)
	go func() {
		unlock2, err := lockFile(path)
		if err == nil {
			unlock2()
		}
		got <- err
	}()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(out.String(), path) && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "waiting") || !strings.Contains(out.String(), path) {
		t.Errorf("output = %q, want a waiting message naming %s", out.String(), path)
	}
	unlock()
	if err := <-got; err != nil {
		t.Fatalf("second lockFile: %v", err)
	}
}

// TestLockFile_QuietWhenFree checks that a free lock prints nothing.
func TestLockFile_QuietWhenFree(t *testing.T) {
	var out syncBuffer
	origOut := lockWaitOutput
	lockWaitOutput = &out
	t.Cleanup(func() { lockWaitOutput = origOut })

	unlock, err := lockFile(filepath.Join(t.TempDir(), "cache.lock"))
	if err != nil {
		t.Fatal(err)
	}
	unlock()
	if out.String() != "" {
		t.Errorf("output = %q, want none", out.String())
	}
}
