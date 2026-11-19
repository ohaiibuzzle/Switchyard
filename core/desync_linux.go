//go:build linux

package core

import (
	"io"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Socket-level desync, after byedpi (github.com/hufrea/byedpi, desync.c). Plain
// setsockopt/send flags, so no root. Only real sockets qualify: tunnels pass through.

// sockMethod is how head goes out; "split" and unknown names are a plain write.
type sockMethod struct{ ttl1, oob bool }

var sockMethods = map[string]sockMethod{
	"disorder": {ttl1: true},
	"oob":      {oob: true},
	"disoob":   {ttl1: true, oob: true},
}

// writeFirstFlight sends head the way method says, then tail. Without a cut
// (empty tail) there's nothing to desync, so head goes out plain.
func writeFirstFlight(out net.Conn, head, tail []byte, method string) error {
	m, ok := sockMethods[method]
	tc, isTCP := out.(*net.TCPConn)
	var err error
	if ok && isTCP && len(tail) > 0 {
		err = sendDesynced(tc, head, m)
	} else {
		_, err = out.Write(head)
	}
	if err == nil && len(tail) > 0 {
		_, err = out.Write(tail)
	}
	return err
}

func sendDesynced(tc *net.TCPConn, b []byte, m sockMethod) error {
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	if m.ttl1 {
		// TTL 1 dies at the first hop; the kernel resends it after the rest, at normal TTL.
		if err := setTTL(rc, 1); err != nil {
			return err
		}
		defer setTTL(rc, -1)
	}
	if m.oob {
		err = sendOOB(rc, b)
	} else {
		_, err = tc.Write(b)
	}
	if err == nil {
		waitSent(rc) // TTL and segment boundaries hold only once it has left the socket
	}
	return err
}

// setTTL sets the unicast TTL / hop limit; -1 restores the system default.
// One of the two fails depending on the socket's family.
func setTTL(rc syscall.RawConn, ttl int) error {
	var e4, e6 error
	if err := rc.Control(func(fd uintptr) {
		e4 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TTL, ttl)
		e6 = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
	}); err != nil {
		return err
	}
	if e4 != nil && e6 != nil {
		return e4
	}
	return nil
}

// sendOOB sends b plus one junk byte as TCP urgent data. Without SO_OOBINLINE the
// server's kernel drops that byte; a DPI box reassembling the stream keeps it.
func sendOOB(rc syscall.RawConn, b []byte) error {
	p := append(b[:len(b):len(b)], 'a')
	var n int
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		n, serr = unix.SendmsgN(int(fd), p, nil, nil, unix.MSG_OOB)
		return serr != unix.EAGAIN
	}); err != nil {
		return err
	}
	if serr == nil && n != len(p) {
		return io.ErrShortWrite // the urgent byte would land mid-stream
	}
	return serr
}

// waitSent polls until the socket has nothing left unsent, for at most ~200ms.
func waitSent(rc syscall.RawConn) {
	for range 100 {
		var left uint32
		rc.Control(func(fd uintptr) {
			if ti, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				left = ti.Notsent_bytes
			}
		})
		if left == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// fakeUDP sends byedpi's default decoy, 64 zero bytes, at a TTL meant to reach
// the DPI box but not the server. An invalid ttl (0) just sends nothing.
func fakeUDP(out net.Conn, ttl int) {
	uc, ok := out.(*net.UDPConn)
	if !ok {
		return
	}
	rc, err := uc.SyscallConn()
	if err != nil || setTTL(rc, ttl) != nil {
		return
	}
	uc.Write(make([]byte, 64))
	setTTL(rc, -1)
}
