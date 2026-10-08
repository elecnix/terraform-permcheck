package provideraws

import (
	"fmt"
	"io"
	"os"
	"time"
)

// lockFile prints a message to lockWaitOutput when it has waited
// lockWaitNotice for a lock another run holds, so a long wait does not look
// like a hang. Tests replace both.
var (
	lockWaitNotice           = 2 * time.Second
	lockWaitOutput io.Writer = os.Stderr
)

// sayWaiting prints the waiting message for the lock file path, followed by
// detail when it is not empty.
func sayWaiting(path, detail string) {
	msg := fmt.Sprintf("terraform-permcheck: waiting for another run to release the provider cache lock %s", path)
	if detail != "" {
		msg += "; " + detail
	}
	fmt.Fprintln(lockWaitOutput, msg)
}
