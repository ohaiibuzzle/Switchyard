//go:build linux

package core

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"os"
	"testing"
)

// Over loopback TTL 1 still arrives, so every method must deliver the stream intact
// (the OOB byte stripped) and leave the socket usable. Fake's decoy arrives too, but
// the server reads only after the swap, and its queue shares our page, so it must
// see the real bytes: that checks the swap itself.
func TestSendFirst(t *testing.T) {
	for _, m := range []string{"", "split", "disorder", "oob", "disoob", "fake"} {
		p := planFor(config{TLSMethod: m, FakeTTL: 8})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan []byte)
		sent := make(chan struct{})
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- nil
				return
			}
			<-sent
			b, _ := io.ReadAll(c)
			got <- b
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFirstFlight(c, []byte("hello "), []byte("world"), p); err != nil {
			t.Fatalf("%q: %v", m, err)
		}
		close(sent)
		c.(*net.TCPConn).CloseWrite()
		if b := <-got; string(b) != "hello world" {
			t.Errorf("%q: server got %q", m, b)
		}
		c.Close()
		ln.Close()
	}
}

func TestFakeUDP(t *testing.T) {
	srv, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	c, err := net.DialUDP("udp", nil, srv.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fakeUDP(c, 8)
	c.Write([]byte("real"))
	b := make([]byte, 100)
	n, _ := srv.Read(b)
	if !bytes.Equal(b[:n], make([]byte, 64)) {
		t.Errorf("decoy = %x", b[:n])
	}
	n, _ = srv.Read(b)
	if string(b[:n]) != "real" {
		t.Errorf("real = %q", b[:n])
	}
}

// TestFakeHandshake needs the internet: SNF_NET_TEST=1. The decoy dies at the
// first hop (TTL 1), so the handshake only completes if the kernel's resend
// carries the real bytes we swapped in. It can't pass behind a user-mode NAT (the
// emulator's slirp) that ignores TTL: the decoy is delivered and the server chokes.
func TestFakeHandshake(t *testing.T) {
	if os.Getenv("SNF_NET_TEST") == "" {
		t.Skip("set SNF_NET_TEST=1")
	}
	raw, err := net.Dial("tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	c := tls.Client(&fakeFirst{Conn: raw, plan: sendPlan{ttl: 1, decoy: fakeHello()}}, &tls.Config{ServerName: "example.com"})
	if err := c.Handshake(); err != nil {
		t.Fatalf("handshake through fake: %v", err)
	}
}

// fakeFirst cuts its first write the way forwardTCP does.
type fakeFirst struct {
	net.Conn
	plan sendPlan
	done bool
}

func (f *fakeFirst) Write(b []byte) (int, error) {
	if f.done {
		return f.Conn.Write(b)
	}
	f.done = true
	head, tail := desyncTLS(b, true, false)
	return len(b), writeFirstFlight(f.Conn, head, tail, f.plan)
}
