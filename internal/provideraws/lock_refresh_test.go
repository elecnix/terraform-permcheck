package provideraws

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestKeepFresh_RefreshesUntilStopped checks that the refresher moves the
// modification time forward while it runs and leaves it alone after stop.
func TestKeepFresh_RefreshesUntilStopped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ref.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}

	stop := keepFresh(path, 10*time.Millisecond)
	deadline := time.Now().Add(2 * time.Second)
	for {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if time.Since(info.ModTime()) < time.Minute {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("modification time was not refreshed")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stop()
	stop() // a second call is safe

	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if time.Since(info.ModTime()) < time.Minute {
		t.Error("modification time changed after stop")
	}
}
