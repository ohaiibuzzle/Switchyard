package core

import (
	"bytes"
	"encoding/binary"
)

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

// desyncTLS turns one ClientHello record into the chunks to write, each
// sent as its own TCP segment. Bytes after the first record pass through.
func desyncTLS(b []byte, split, frag bool) [][]byte {
	off, n, ok := sniOffset(b)
	if !ok || (!split && !frag) {
		return [][]byte{b}
	}
	mid := off + n/2 // cut inside the hostname so no segment/record holds it whole
	end := recordLen(b)
	if !frag {
		return [][]byte{b[:mid], b[mid:]}
	}
	rec := func(payload []byte) []byte {
		h := []byte{0x16, b[1], b[2], 0, 0}
		binary.BigEndian.PutUint16(h[3:], uint16(len(payload)))
		return append(h, payload...)
	}
	r1, r2 := rec(b[5:mid]), append(rec(b[mid:end]), b[end:]...)
	if split {
		return [][]byte{r1, r2}
	}
	return [][]byte{append(r1, r2...)}
}

var hostHdr = []byte("\r\nhost:")

// desyncHTTP mixes the Host header's case, drops the space after the colon and
// splits the write inside the hostname. Non-HTTP or Host-less data passes through.
func desyncHTTP(b []byte) [][]byte {
	i := bytes.Index(bytes.ToLower(b), hostHdr)
	if i < 0 {
		return [][]byte{b}
	}
	out := append([]byte{}, b[:i]...)
	out = append(out, "\r\nhoSt:"...)
	rest := b[i+len(hostHdr):]
	rest = bytes.TrimLeft(rest, " \t")
	cut := len(out) + min(bytes.IndexByte(rest, '\r'), len(rest))/2
	out = append(out, rest...)
	if cut <= len(out)-len(rest) { // empty host value
		return [][]byte{out}
	}
	return [][]byte{out[:cut], out[cut:]}
}
