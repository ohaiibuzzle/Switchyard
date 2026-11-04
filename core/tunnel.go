//go:build linux

// Package core is the gomobile-bound packet engine: a gVisor netstack on the
// VpnService tun fd that filters per app, answers all DNS and forwards the rest.
package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/fdbased"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

var (
	mu  sync.Mutex
	stk *stack.Stack
	tun int
)

func swap(s *state) {
	if old := cur.Swap(s); old != nil {
		old.up.Close()
	}
}

// Start runs the engine on a tun fd; the engine takes ownership of fd.
func Start(fd, mtu int, cfg string, c Callback) error {
	mu.Lock()
	defer mu.Unlock()
	if stk != nil {
		return errors.New("already running")
	}
	cb = c
	s, err := newState(cfg)
	if err != nil {
		return err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		return err
	}
	ep, err := fdbased.New(&fdbased.Options{FDs: []int{fd}, MTU: uint32(mtu)})
	if err != nil {
		return err
	}
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
	})
	sack := tcpip.TCPSACKEnabled(true)
	st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack)
	if e := st.CreateNIC(1, ep); e != nil {
		return fmt.Errorf("nic: %v", e)
	}
	// Accept packets for any destination and reply from it: we impersonate the whole internet.
	st.SetPromiscuousMode(1, true)
	st.SetSpoofing(1, true)
	st.SetRouteTable([]tcpip.Route{{Destination: header.IPv4EmptySubnet, NIC: 1}, {Destination: header.IPv6EmptySubnet, NIC: 1}})
	st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcp.NewForwarder(st, 0, 4096, onTCP).HandlePacket)
	st.SetTransportProtocolHandler(udp.ProtocolNumber, udp.NewForwarder(st, onUDP).HandlePacket)
	swap(s)
	stk, tun = st, fd
	logf("started, upstream %s", s.cfg.DNSUpstream)
	return nil
}

// Reconfigure swaps settings without dropping the tunnel. Existing flows keep their verdicts.
func Reconfigure(cfg string) error {
	s, err := newState(cfg)
	if err != nil {
		return err
	}
	swap(s)
	logf("reconfigured, upstream %s", s.cfg.DNSUpstream)
	return nil
}

func Stop() {
	mu.Lock()
	defer mu.Unlock()
	if stk == nil {
		return
	}
	stk.Close()
	stk.Wait()
	unix.Close(tun) // fdbased doesn't own the fd
	stk = nil
	swap(nil)
	ClearEvents()
	wgFor("")
	logf("stopped")
}

func addrPort(a tcpip.Address, p uint16) netip.AddrPort {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return netip.AddrPortFrom(ip.Unmap(), p)
}

// verdict returns the owning uid and, if the flow must be dropped, why (else "").
func verdict(s *state, proto int, name string, src, dst netip.AddrPort) (int, string) {
	uid := -1
	if c := cb; c != nil {
		uid = c.UidFor(proto, src.Addr().String(), int(src.Port()), dst.Addr().String(), int(dst.Port()))
	}
	why := ""
	switch p := dst.Port(); {
	case s.blocked[uid]:
		why = "app"
	case s.cfg.BlockBypass && p == 853:
		why = "dot"
	case s.cfg.BlockBypass && p == 443 && bypassIPs[dst.Addr()]:
		why = "doh"
	case s.cfg.BlockQUIC && proto == unix.IPPROTO_UDP && p == 443:
		why = "quic"
	}
	if why != "" {
		logFlow(uid, name, dst, "block", why, nil)
	}
	return uid, why
}

func onTCP(r *tcp.ForwarderRequest) {
	s := cur.Load()
	id := r.ID()
	src, dst := addrPort(id.RemoteAddress, id.RemotePort), addrPort(id.LocalAddress, id.LocalPort)
	if s == nil {
		r.Complete(true)
		return
	}
	uid, why := verdict(s, unix.IPPROTO_TCP, "tcp", src, dst)
	if why != "" {
		r.Complete(true)
		return
	}
	if dst.Port() == 53 {
		if c := accept(r); c != nil {
			go serveDNSTCP(c, uid)
		}
		return
	}
	// Dial before accepting so an unreachable target becomes a clean RST to the app.
	out, rt, err := upstreamDial(s, uid, dst)
	logFlow(uid, "tcp", dst, "allow", rt, err)
	if err != nil {
		logf("dial %s: %v", dst, err)
		r.Complete(true)
		return
	}
	c := accept(r)
	if c == nil {
		out.Close()
		return
	}
	forwardTCP(s, c, out, dst)
}

func accept(r *tcp.ForwarderRequest) *gonet.TCPConn {
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		r.Complete(true)
		return nil
	}
	r.Complete(false)
	return gonet.NewTCPConn(&wq, ep)
}

func onUDP(r *udp.ForwarderRequest) bool {
	s := cur.Load()
	id := r.ID()
	src, dst := addrPort(id.RemoteAddress, id.RemotePort), addrPort(id.LocalAddress, id.LocalPort)
	if s == nil {
		return true
	}
	uid, why := verdict(s, unix.IPPROTO_UDP, "udp", src, dst)
	if why != "" {
		return true // handled = silently dropped
	}
	var wq waiter.Queue
	ep, e := r.CreateEndpoint(&wq)
	if e != nil {
		return true
	}
	c := gonet.NewUDPConn(&wq, ep)
	go forwardUDP(s, c, uid, dst)
	return true
}

// resolve answers one DNS query: sinkhole if blocked, else ask the secure upstream.
func resolve(q []byte, uid int) []byte {
	s := cur.Load()
	m := new(dns.Msg)
	if s == nil || m.Unpack(q) != nil {
		return nil
	}
	resp := new(dns.Msg)
	why, name := "", ""
	if len(m.Question) == 1 {
		name = normName(m.Question[0].Name)
		why = dnsDecision(s, name)
	}
	ev := event{UID: uid, Proto: "dns", Host: name, Action: "allow"}
	if why != "" {
		resp.SetRcode(m, dns.RcodeNameError)
		ev.Action, ev.Reason = "block", why
	} else if r, err := s.up.Exchange(context.Background(), m); err != nil {
		logf("dns %v: %v", m.Question, err)
		resp.SetRcode(m, dns.RcodeServerFailure)
		ev.Action, ev.Err = "fail", err.Error()
	} else {
		r.Id = m.Id
		resp = r
		noteAnswer(r)
	}
	record(ev)
	out, _ := resp.Pack()
	return out
}

func serveDNSTCP(c net.Conn, uid int) {
	defer c.Close()
	dc := &dns.Conn{Conn: c}
	for {
		c.SetDeadline(time.Now().Add(30 * time.Second))
		q, err := dc.ReadMsgHeader(nil)
		if err != nil {
			return
		}
		a := resolve(q, uid)
		if a == nil {
			return
		}
		if _, err := dc.Write(a); err != nil {
			return
		}
	}
}

const udpIdle = 60 * time.Second

func forwardUDP(s *state, c *gonet.UDPConn, uid int, dst netip.AddrPort) {
	defer c.Close()
	buf := make([]byte, 65535)
	if dst.Port() == 53 {
		for {
			c.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := c.Read(buf)
			if err != nil {
				return
			}
			go func(q []byte) {
				if a := resolve(q, uid); a != nil {
					c.Write(a)
				}
			}(append([]byte(nil), buf[:n]...))
		}
	}
	// shortcut: with a proxy UDP still goes direct (no SOCKS5 UDP ASSOCIATE); WireGuard does carry UDP.
	var out net.Conn
	var err error
	rt := "direct"
	if wg := viaWG(s, uid, dst); wg != nil {
		rt = "wireguard"
		out, err = wg.tnet.DialUDPAddrPort(netip.AddrPort{}, dst)
	} else {
		out, err = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(dst))
	}
	logFlow(uid, "udp", dst, "allow", rt, err)
	if err != nil {
		return
	}
	defer out.Close()
	go func() {
		b := make([]byte, 65535)
		for {
			out.SetReadDeadline(time.Now().Add(udpIdle))
			n, err := out.Read(b)
			if err != nil {
				c.Close()
				return
			}
			c.Write(b[:n])
		}
	}()
	for {
		c.SetReadDeadline(time.Now().Add(udpIdle))
		n, err := c.Read(buf)
		if err != nil {
			out.Close()
			return
		}
		out.Write(buf[:n])
	}
}

func forwardTCP(s *state, c *gonet.TCPConn, out net.Conn, dst netip.AddrPort) {
	defer c.Close()
	defer out.Close()

	// Server->client starts first so server-speaks-first protocols aren't stalled by firstFlight.
	done := make(chan struct{})
	go func() {
		io.Copy(c, out)
		c.CloseWrite()
		close(done)
	}()

	// Desync only touches the client's first flight; everything after is a plain copy.
	var chunks [][]byte
	switch {
	case dst.Port() == 443 && (s.cfg.SNISplit || s.cfg.TLSFrag):
		chunks = desyncTLS(firstFlight(c), s.cfg.SNISplit, s.cfg.TLSFrag)
	case dst.Port() == 80 && s.cfg.HostTricks:
		chunks = desyncHTTP(firstFlight(c))
	}
	for _, ch := range chunks {
		if _, err := out.Write(ch); err != nil {
			return
		}
	}
	io.Copy(out, c)
	if tc, ok := out.(interface{ CloseWrite() error }); ok {
		tc.CloseWrite()
	}
	<-done
}

// firstFlight reads the client's opening bytes, waiting for a whole TLS record
// when the stream starts with one so the SNI can be located.
func firstFlight(c net.Conn) []byte {
	buf := make([]byte, 0, 16*1024+5)
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	for {
		n, err := c.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if err != nil || len(buf) == cap(buf) || len(buf) > 0 && buf[0] != 0x16 || len(buf) >= 5 && recordLen(buf) <= len(buf) {
			return buf
		}
	}
}
