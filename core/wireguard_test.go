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

	"golang.org/x/crypto/curve25519"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
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
	if !strings.HasPrefix(c.uapi, "private_key=") {
		t.Error("private_key must come first")
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

// TestWireGuardLoopback runs a real handshake against an in-process peer and
// pushes TCP and UDP through the tunnel.
func TestWireGuardLoopback(t *testing.T) {
	sPriv, sPub := keypair(t)
	cPriv, cPub := keypair(t)

	stun, snet, err := netstack.CreateNetTUN([]netip.Addr{netip.MustParseAddr("10.9.0.1")}, nil, 1420)
	if err != nil {
		t.Fatal(err)
	}
	srv := device.NewDevice(stun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer srv.Close()
	if err := srv.IpcSet(fmt.Sprintf("private_key=%s\nlisten_port=0\npublic_key=%s\nallowed_ip=10.9.0.2/32\n",
		hex.EncodeToString(sPriv), hex.EncodeToString(cPub))); err != nil {
		t.Fatal(err)
	}
	srv.Up()
	st, _ := srv.IpcGet()
	var port string
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "listen_port="); ok {
			port = v
		}
	}

	// TCP and UDP echo servers inside the "remote" network.
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

	conf := fmt.Sprintf("[Interface]\nPrivateKey=%s\nAddress=10.9.0.2/32\n[Peer]\nPublicKey=%s\nEndpoint=127.0.0.1:%s\nAllowedIPs=10.9.0.0/24\n",
		b64(cPriv), b64(sPub), port)
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

	s := &state{wg: tun, routed: map[int]bool{}}
	dst := netip.MustParseAddrPort("10.9.0.1:7")
	if viaWG(s, 1, netip.MustParseAddrPort("1.1.1.1:443")) != nil {
		t.Fatal("dst outside AllowedIPs must go direct")
	}
	c, err := upstreamDial(s, 1, dst)
	if err != nil {
		t.Fatal(err)
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
