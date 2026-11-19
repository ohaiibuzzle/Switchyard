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

// writeFirstFlight sends head the way p says, then tail. Without a cut
// (empty tail) there's nothing to desync, so head goes out plain.
func writeFirstFlight(out net.Conn, head, tail []byte, p sendPlan) error {
	tc, isTCP := out.(*net.TCPConn)
	var err error
	if !p.plain() && isTCP && len(tail) > 0 {
		err = sendDesynced(tc, head, p)
	} else {
		_, err = out.Write(head)
	}
	if err == nil && len(tail) > 0 {
		_, err = out.Write(tail)
	}
	return err
}

func sendDesynced(tc *net.TCPConn, b []byte, p sendPlan) error {
	rc, err := tc.SyscallConn()
	if err != nil {
		return err
	}
	if p.ttl > 0 {
		// A low TTL dies before the server; the kernel resends it after the rest, at normal TTL.
		if err := setTTL(rc, p.ttl); err != nil {
			return err
		}
		defer setTTL(rc, -1)
	}
	switch {
	case p.decoy != nil:
		return sendFake(rc, b, p.decoy) // waits itself, since the swap must follow the send
	case p.oob:
		err = sendOOB(rc, b)
	default:
		_, err = tc.Write(b)
	}
	if err == nil {
		waitSent(rc) // TTL and segment boundaries hold only once it has left the socket
	}
	return err
}

// sendFake sends len(real) bytes of decoy (at the low TTL the caller set), then
// rewrites them to real. splice hands the kernel our page rather than a copy, so
// the resend that follows reads the real bytes from it.
// shortcut: the rewrite races a NIC still holding the fake (byedpi takes the same
// race), wait for the qdisc to drain too if fakes ever go out real.
func sendFake(rc syscall.RawConn, real, decoy []byte) error {
	page, err := unix.Mmap(-1, 0, len(real), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return err
	}
	defer unix.Munmap(page) // the kernel holds its own reference to the page
	copy(page, decoy)       // a shorter decoy is zero-padded
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		return err
	}
	defer unix.Close(pipe[0])
	defer unix.Close(pipe[1])
	iov := unix.Iovec{Base: &page[0]}
	iov.SetLen(len(page))
	n, err := unix.Vmsplice(pipe[1], []unix.Iovec{iov}, unix.SPLICE_F_GIFT)
	if err != nil {
		return err
	}
	if n != len(page) {
		return io.ErrShortWrite
	}
	var serr error
	if err := rc.Write(func(fd uintptr) bool {
		for n > 0 {
			m, err := unix.Splice(pipe[0], nil, int(fd), nil, n, 0)
			if err == unix.EAGAIN {
				return false
			}
			if err != nil {
				serr = err
				return true
			}
			n -= int(m)
		}
		return true
	}); err != nil {
		return err
	}
	if serr != nil {
		return serr
	}
	waitSent(rc)
	copy(page, real)
	return nil
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
// the DPI box but not the server.
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
