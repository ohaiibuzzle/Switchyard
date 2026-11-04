package core

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestBlocklist(t *testing.T) {
	s := domainSet{}
	s.parseList(strings.NewReader(`# comment
0.0.0.0 ads.example.com
127.0.0.1 localhost
::1 ip6-localhost
||tracker.net^
||example.org/path^
@@||allowed.com^
*.wild.io
plain.com # trailing comment
! adblock comment
`))
	for _, d := range []string{"ads.example.com", "x.ads.example.com", "tracker.net", "a.b.tracker.net", "wild.io", "plain.com.", "PLAIN.com"} {
		if !s.has(d) {
			t.Errorf("want blocked: %s", d)
		}
	}
	for _, d := range []string{"example.com", "localhost", "allowed.com", "example.org", "com", "notplain.com"} {
		if s.has(d) {
			t.Errorf("want allowed: %s", d)
		}
	}
}

// clientHello captures a real ClientHello from crypto/tls.
func clientHello(t *testing.T, sni string) []byte {
	a, b := net.Pipe()
	go tls.Client(a, &tls.Config{ServerName: sni}).Handshake()
	hdr := make([]byte, 5)
	io.ReadFull(b, hdr)
	body := make([]byte, recordLen(hdr)-5)
	io.ReadFull(b, body)
	a.Close()
	return append(hdr, body...)
}

func TestSNI(t *testing.T) {
	ch := clientHello(t, "blocked.example.com")
	off, n, ok := sniOffset(ch)
	if !ok || string(ch[off:off+n]) != "blocked.example.com" {
		t.Fatalf("sniOffset: %v %q", ok, ch[off:off+n])
	}
	if _, _, ok := sniOffset(ch[:len(ch)-1]); ok {
		t.Fatal("truncated hello must not parse")
	}

	trailer := []byte("extra")
	in := append(append([]byte{}, ch...), trailer...)

	sp := desyncTLS(in, true, false)
	if len(sp) != 2 || !bytes.Equal(bytes.Join(sp, nil), in) || bytes.Contains(sp[0], []byte("blocked.example.com")) {
		t.Fatal("split must be lossless and cut the SNI")
	}

	fr := desyncTLS(in, true, true)
	if len(fr) != 2 {
		t.Fatal("frag+split wants 2 chunks")
	}
	// Reassembling record payloads must give back the original handshake.
	var payload []byte
	rest := bytes.Join(fr, nil)
	for i := 0; i < 2; i++ {
		l := recordLen(rest)
		payload = append(payload, rest[5:l]...)
		rest = rest[l:]
	}
	if !bytes.Equal(payload, ch[5:]) || !bytes.Equal(rest, trailer) {
		t.Fatal("fragmented records don't reassemble")
	}
	if got := desyncTLS(in, false, true); len(got) != 1 || !bytes.Equal(got[0], bytes.Join(fr, nil)) {
		t.Fatal("frag-only should be one write of both records")
	}
}

func TestHTTP(t *testing.T) {
	in := []byte("GET / HTTP/1.1\r\nHost: blocked.com\r\nAccept: */*\r\n\r\n")
	out := desyncHTTP(in)
	if len(out) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(out))
	}
	j := string(bytes.Join(out, nil))
	if j != "GET / HTTP/1.1\r\nhoSt:blocked.com\r\nAccept: */*\r\n\r\n" {
		t.Fatalf("got %q", j)
	}
	if strings.Contains(string(out[0]), "blocked.com") {
		t.Fatal("hostname must be split")
	}
	if o := desyncHTTP([]byte("\x16\x03\x01junk")); len(o) != 1 {
		t.Fatal("non-HTTP must pass through")
	}
}

// echoServer accepts one conn on loopback and echoes it.
func echoServer(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		c, err := l.Accept()
		if err == nil {
			io.Copy(c, c)
		}
	}()
	return l.Addr().String()
}

func TestHTTPConnectDialer(t *testing.T) {
	target := echoServer(t)
	pl, _ := net.Listen("tcp", "127.0.0.1:0")
	defer pl.Close()
	go func() { // minimal CONNECT proxy that also sends a byte early to exercise bufConn
		c, _ := pl.Accept()
		br := bufio.NewReader(c)
		req, _ := http.ReadRequest(br)
		if req.Header.Get("Proxy-Authorization") == "" || req.Host != target {
			c.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
			return
		}
		up, _ := net.Dial("tcp", target)
		c.Write([]byte("HTTP/1.1 200 OK\r\n\r\n!"))
		go io.Copy(up, br)
		io.Copy(c, up)
	}()
	d, err := newDialer("http://u:p@" + pl.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := d(target)
	if err != nil {
		t.Fatal(err)
	}
	c.Write([]byte("hi"))
	got := make([]byte, 3)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "!hi" {
		t.Fatalf("got %q %v", got, err)
	}
	if _, err := newDialer("ftp://x"); err == nil {
		t.Fatal("bad scheme must error")
	}
}
