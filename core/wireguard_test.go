package core

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	awgconn "github.com/amnezia-vpn/amneziawg-go/v3/conn"
	awgdev "github.com/amnezia-vpn/amneziawg-go/v3/device"
	awgnet "github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
)

func keypair(t *testing.T) (priv, pub []byte) {
	priv = make([]byte, 32)
	rand.Read(priv)
	pub, err := curve25519.X25519(priv, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

var b64 = base64.StdEncoding.EncodeToString

func TestParseWG(t *testing.T) {
	_, pub := keypair(t)
	priv, _ := keypair(t)
	conf := fmt.Sprintf(`
[Interface]
Jc = 4
PrivateKey = %s   # comment
Address = 10.64.0.2/32, fd00::2/128
DNS = 10.64.0.1
MTU = 1380

[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, b64(priv), b64(pub), b64(pub))
	c, err := parseWG(conf, func(h string) (netip.Addr, error) {
		if h != "vpn.example" {
			t.Fatalf("resolved %q", h)
		}
		return netip.MustParseAddr("203.0.113.7"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.mtu != 1380 || len(c.addrs) != 2 || !c.routes(netip.MustParseAddr("1.2.3.4")) {
		t.Fatalf("parsed %+v", c)
	}
	for _, want := range []string{
		"private_key=" + hex.EncodeToString(priv), "public_key=" + hex.EncodeToString(pub),
		"endpoint=203.0.113.7:51820", "allowed_ip=::/0", "persistent_keepalive_interval=25",
	} {
		if !strings.Contains(c.uapi, want+"\n") {
			t.Errorf("uapi missing %q:\n%s", want, c.uapi)
		}
	}
	pk := strings.Index(c.uapi, "public_key=")
	for _, dev := range []string{"private_key=", "jc=4\n"} {
		if j := strings.Index(c.uapi, dev); j < 0 || j > pk {
			t.Errorf("%q must be a device line before the peer:\n%s", dev, c.uapi)
		}
	}

	split, _ := parseWG(strings.Replace(conf, "0.0.0.0/0, ::/0", "10.0.0.0/8", 1), func(string) (netip.Addr, error) { return netip.MustParseAddr("203.0.113.7"), nil })
	if split.routes(netip.MustParseAddr("1.2.3.4")) || !split.routes(netip.MustParseAddr("10.1.2.3")) {
		t.Error("split tunnel AllowedIPs not honoured")
	}

	for _, bad := range []string{"", "[Interface]\nPrivateKey = nope", "[Peer]\nPublicKey = " + b64(pub)} {
		if _, err := parseWG(bad, nil); err == nil {
			t.Errorf("want error for %q", bad)
		}
	}
}

// peerDev and peerNet are what upstream wireguard-go and amneziawg-go share.
type peerDev interface {
	IpcSet(string) error
	IpcGet() (string, error)
	Up() error
	Close()
}

type peerNet interface {
	ListenTCPAddrPort(netip.AddrPort) (*gonet.TCPListener, error)
	ListenUDPAddrPort(netip.AddrPort) (*gonet.UDPConn, error)
}

// echoPeer starts an in-process WireGuard server at 10.9.0.1 with TCP and UDP echo
// on :7, and returns its UDP port. awg is extra device UAPI; non-empty runs the
// server on amneziawg-go, empty on upstream wireguard-go (plain-WireGuard interop).
func echoPeer(t *testing.T, sPriv, cPub []byte, awg string) string {
	addrs := []netip.Addr{netip.MustParseAddr("10.9.0.1")}
	var (
		srv  peerDev
		snet peerNet
	)
	if awg == "" {
		stun, n, err := netstack.CreateNetTUN(addrs, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		srv, snet = device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, "")), n
	} else {
		stun, n, err := awgnet.CreateNetTUN(addrs, nil, 1420)
		if err != nil {
			t.Fatal(err)
		}
		srv, snet = awgdev.NewDevice(stun, awgconn.NewDefaultBind(), awgdev.NewLogger(awgdev.LogLevelSilent, "")), n
	}
	t.Cleanup(srv.Close)
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\n%spublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(sPriv), awg, hex.EncodeToString(cPub))); err != nil {
		t.Fatal(err)
	}
	if err := srv.Up(); err != nil {
		t.Fatal(err)
	}
	st, _ := srv.IpcGet()
	var port string
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port = v
		}
	}

	l, err := snet.ListenTCPAddrPort(netip.MustParseAddrPort("10.9.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	u, err := snet.ListenUDPAddrPort(netip.MustParseAddrPort("10.9.0.1:7"))
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		b := make([]byte, 1500)
		for {
			n, a, err := u.ReadFrom(b)
			if err != nil {
				return
			}
			u.WriteTo(b[:n], a)
		}
	}()
	return port
}

// TestWireGuardLoopback runs a real handshake against an in-process peer and
// pushes TCP and UDP through the tunnel: once against plain WireGuard, once with
// AmneziaWG obfuscation on both ends.
func TestWireGuardLoopback(t *testing.T) {
	for _, tc := range []struct{ name, iface string }{
		{"wireguard", ""},
		{"amneziawg", "Jc=4\nJmin=40\nJmax=70\nS1=15\nS2=18\nH1=123456\nH2=234567\nH3=345678\nH4=456789\n"},
	} {
		t.Run(tc.name, func(t *testing.T) { loopback(t, tc.iface) })
	}
}

func loopback(t *testing.T, iface string) {
	sPriv, sPub := keypair(t)
	cPriv, cPub := keypair(t)
	port := echoPeer(t, sPriv, cPub, strings.ToLower(iface))

	conf := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.9.0.2/32\n%s[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:%s\nAllowedIPs=10.9.0.0/24\n",
		b64(cPriv), iface, b64(sPub), port)
	if WgHandshakeAge() != -2 {
		t.Fatal("want -2 before start")
	}
	tun, err := wgFor(conf)
	if err != nil {
		t.Fatal(err)
	}
	defer wgFor("")
	// No traffic yet: the startup kick alone must complete a handshake.
	for i := 0; WgHandshakeAge() < 0; i++ {
		if i == 50 {
			t.Fatal("no handshake without traffic")
		}
		time.Sleep(100 * time.Millisecond)
	}
	if again, _ := wgFor(conf); again != tun {
		t.Fatal("same config must reuse the running tunnel")
	}

	s := &state{wg: tun, cfg: config{RouteAll: true}}
	dst := netip.MustParseAddrPort("10.9.0.1:7")
	if viaWG(s, 1, netip.MustParseAddrPort("1.1.1.1:443")) != nil {
		t.Fatal("dst outside AllowedIPs must go direct")
	}
	c, rt, err := upstreamDial(s, 1, dst)
	if err != nil || rt != "wireguard" {
		t.Fatal(rt, err)
	}
	defer c.Close()
	c.Write([]byte("over wireguard"))
	got := make([]byte, 14)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "over wireguard" {
		t.Fatalf("tcp echo: %q %v", got, err)
	}

	uc, err := tun.tnet.DialUDPAddrPort(netip.AddrPort{}, dst)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.Write([]byte("udp"))
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 16)
	if n, err := uc.Read(b); err != nil || string(b[:n]) != "udp" {
		t.Fatalf("udp echo: %q %v", b[:n], err)
	}

	if age := WgHandshakeAge(); age < 0 || age > 5 {
		t.Fatalf("handshake age %d", age)
	}
}
