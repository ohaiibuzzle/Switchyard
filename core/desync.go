package core

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// sendPlan is how the head of a cut first flight goes out; the zero value is a plain write.
type sendPlan struct {
	ttl   int    // >0: head goes out at this TTL, dies before the server, and the kernel resends it after the tail
	oob   bool   // plus one urgent junk byte the server drops (out-of-band)
	decoy []byte // sent in head's place, then swapped for the real bytes before the resend (fake)
}

func (p sendPlan) plain() bool { return p.ttl == 0 && !p.oob }

// planFor turns the TLS method into a sendPlan; "split" and unknown names send plainly.
func planFor(c config) sendPlan {
	switch c.TLSMethod {
	case "disorder":
		return sendPlan{ttl: 1}
	case "oob":
		return sendPlan{oob: true}
	case "disoob":
		return sendPlan{ttl: 1, oob: true}
	case "fake":
		if d := fakeHello(); d != nil {
			return sendPlan{ttl: c.FakeTTL, decoy: d} // newState keeps FakeTTL in 1..255
		}
	}
	return sendPlan{}
}

// shortcut: fixed decoy name (byedpi's default), add a setting if a network blocks it.
var fakeHello = sync.OnceValue(func() []byte { return clientHello("www.iana.org") })

// clientHello captures the ClientHello record crypto/tls sends for sni, or nil.
func clientHello(sni string) []byte {
	a, b := net.Pipe()
	defer a.Close()
	go tls.Client(a, &tls.Config{ServerName: sni}).Handshake()
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(b, hdr); err != nil {
		return nil
	}
	body := make([]byte, recordLen(hdr)-5)
	if _, err := io.ReadFull(b, body); err != nil {
		return nil
	}
	return append(hdr, body...)
}

// sniOffset returns the offset and length of the SNI hostname inside a TLS
// ClientHello record, or ok=false if b isn't a complete parseable ClientHello.
func sniOffset(b []byte) (off, n int, ok bool) {
	if len(b) < 5+4 || b[0] != 0x16 || b[5] != 0x01 {
		return
	}
	end := 5 + int(binary.BigEndian.Uint16(b[3:5]))
	if end > len(b) {
		return
	}
	p := 5 + 4 + 2 + 32 // record hdr, handshake hdr, version, random
	skip := func(lenBytes int) bool {
		if p+lenBytes > end {
			return false
		}
		l := 0
		for i := 0; i < lenBytes; i++ {
			l = l<<8 | int(b[p+i])
		}
		p += lenBytes + l
		return p <= end
	}
	if !skip(1) || !skip(2) || !skip(1) { // session id, cipher suites, compression
		return
	}
	p += 2 // extensions length
	for p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if p+l > end {
			return
		}
		if typ == 0 && l >= 5 { // server_name: list len(2) type(1) name len(2) name
			n = int(binary.BigEndian.Uint16(b[p+3:]))
			if p+5+n > end {
				return
			}
			return p + 5, n, true
		}
		p += l
	}
	return
}

// recordLen is the full length of the first TLS record, header included.
func recordLen(b []byte) int {
	return 5 + int(binary.BigEndian.Uint16(b[3:5]))
}

// desyncTLS cuts one ClientHello inside its SNI into head and tail, each sent as
// its own TCP segment; tail is nil when there's no cut. Bytes after the first record ride in tail.
func desyncTLS(b []byte, split, frag bool) (head, tail []byte) {
	off, n, ok := sniOffset(b)
	if !ok || (!split && !frag) {
		return b, nil
	}
	mid := off + n/2 // cut inside the hostname so no segment/record holds it whole
	end := recordLen(b)
	if !frag {
		return b[:mid], b[mid:]
	}
	rec := func(payload []byte) []byte {
		h := []byte{0x16, b[1], b[2], 0, 0}
		binary.BigEndian.PutUint16(h[3:], uint16(len(payload)))
		return append(h, payload...)
	}
	r1, r2 := rec(b[5:mid]), append(rec(b[mid:end]), b[end:]...)
	if split {
		return r1, r2
	}
	return append(r1, r2...), nil
}

var hostHdr = []byte("\r\nhost:")

// desyncHTTP mixes the Host header's case, drops the space after the colon and
// cuts it inside the hostname. Non-HTTP or Host-less data passes through whole.
func desyncHTTP(b []byte) (head, tail []byte) {
	i := bytes.Index(bytes.ToLower(b), hostHdr)
	if i < 0 {
		return b, nil
	}
	out := append([]byte{}, b[:i]...)
	out = append(out, "\r\nhoSt:"...)
	rest := b[i+len(hostHdr):]
	rest = bytes.TrimLeft(rest, " \t")
	cut := len(out) + min(bytes.IndexByte(rest, '\r'), len(rest))/2
	out = append(out, rest...)
	if cut <= len(out)-len(rest) { // empty host value
		return out, nil
	}
	return out[:cut], out[cut:]
}
