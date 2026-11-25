package core

import (
	"fmt"
	"sync/atomic"
)

// Callback is implemented on the Kotlin side.
type Callback interface {
	// UidFor maps a flow to its owning app (ConnectivityManager.getConnectionOwnerUid); -1 if unknown.
	UidFor(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	Log(msg string)
}

// Atomic: flows mid-dial and WireGuard's logger can outlive Stop and race the next Start.
var cb atomic.Pointer[Callback]

func logf(format string, a ...any) {
	if c := cb.Load(); c != nil {
		(*c).Log(fmt.Sprintf(format, a...))
	}
}
