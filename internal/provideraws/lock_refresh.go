package provideraws

import (
	"os"
	"sync"
	"time"
)

// keepFresh sets the modification time of path to now every interval until
// the returned stop function runs. A lock held by mtime, as on platforms
// without flock, then never looks stale while its holder is alive, however
// long the clone behind it takes. stop waits for the refresher to end.
func keepFresh(path string, interval time.Duration) (stop func()) {
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case now := <-t.C:
				_ = os.Chtimes(path, now, now)
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			wg.Wait()
		})
	}
}
