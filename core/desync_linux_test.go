//go:build linux

package core

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// Over loopback TTL 1 still arrives, so every method must deliver the stream intact
// (the OOB byte stripped) and leave the socket usable.
func TestSendFirst(t *testing.T) {
	for _, m := range []string{"", "split", "disorder", "oob", "disoob"} {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		got := make(chan []byte)
		go func() {
			c, err := ln.Accept()
			if err != nil {
				got <- nil
				return
			}
			b, _ := io.ReadAll(c)
			got <- b
		}()
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := replyReader(c, true).(*sackReader); !ok || !setDropSACK(c.(*net.TCPConn), false) {
			t.Errorf("%q: drop SACK filter didn't attach/detach", m)
		}
		if err := writeFirstFlight(c, []byte("hello "), []byte("world"), m); err != nil {
			t.Fatalf("%q: %v", m, err)
		}
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
