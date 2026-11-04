package core

import "fmt"

// Callback is implemented on the Kotlin side.
type Callback interface {
	// UidFor maps a flow to its owning app (ConnectivityManager.getConnectionOwnerUid); -1 if unknown.
	UidFor(proto int, srcIP string, srcPort int, dstIP string, dstPort int) int
	Log(msg string)
}

var cb Callback

func logf(format string, a ...any) {
	if c := cb; c != nil {
		c.Log(fmt.Sprintf(format, a...))
	}
}
