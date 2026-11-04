package core

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type wgConfig struct {
	addrs   []netip.Addr
	mtu     int
	uapi    string // wireguard-go IPC "set" body
	allowed []netip.Prefix
	peers   []string // hex public keys
}

func wgKey(b64 string) (string, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(k) != 32 {
		return "", fmt.Errorf("bad key %q", b64)
	}
	return hex.EncodeToString(k), nil
}

// parseWG reads a wg-quick style config. DNS, Table and Pre/PostUp are ignored:
// DNS is ours, and there is no kernel interface to script.
func parseWG(s string, resolve func(host string) (netip.Addr, error)) (*wgConfig, error) {
	c := &wgConfig{mtu: 1420}
	var u strings.Builder
	section := ""
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[] "))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("bad line %q", line)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		list := func() []string {
			var out []string
			for _, x := range strings.Split(v, ",") {
				if x = strings.TrimSpace(x); x != "" {
					out = append(out, x)
				}
			}
			return out
		}
		switch section + "." + k {
		case "interface.privatekey":
			h, err := wgKey(v)
			if err != nil {
				return nil, fmt.Errorf("PrivateKey: %w", err)
			}
			fmt.Fprintf(&u, "private_key=%s\nreplace_peers=true\n", h)
		case "interface.address":
			for _, a := range list() {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					ip, err2 := netip.ParseAddr(a)
					if err2 != nil {
						return nil, fmt.Errorf("Address %q: %w", a, err)
					}
					p = netip.PrefixFrom(ip, ip.BitLen())
				}
				c.addrs = append(c.addrs, p.Addr())
			}
		case "interface.mtu":
			m, err := strconv.Atoi(v)
			if err != nil || m < 576 || m > 1500 {
				return nil, fmt.Errorf("bad MTU %q", v)
			}
			c.mtu = m
		case "peer.publickey":
			h, err := wgKey(v)
			if err != nil {
				return nil, fmt.Errorf("PublicKey: %w", err)
			}
			// public_key starts a new peer block in UAPI; later peer keys apply to it.
			fmt.Fprintf(&u, "public_key=%s\nreplace_allowed_ips=true\n", h)
			c.peers = append(c.peers, h)
		case "peer.presharedkey":
			h, err := wgKey(v)
			if err != nil {
				return nil, fmt.Errorf("PresharedKey: %w", err)
			}
			fmt.Fprintf(&u, "preshared_key=%s\n", h)
		case "peer.endpoint":
			host, port, err := net.SplitHostPort(v)
			if err != nil {
				return nil, fmt.Errorf("Endpoint %q: %w", v, err)
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				// shortcut: resolved once at connect, re-import the config if the endpoint's IP changes.
				if ip, err = resolve(host); err != nil {
					return nil, fmt.Errorf("Endpoint %q: %w", host, err)
				}
			}
			p, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("Endpoint port %q", port)
			}
			fmt.Fprintf(&u, "endpoint=%s\n", netip.AddrPortFrom(ip, uint16(p)))
		case "peer.allowedips":
			for _, a := range list() {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, fmt.Errorf("AllowedIPs %q: %w", a, err)
				}
				fmt.Fprintf(&u, "allowed_ip=%s\n", p.Masked())
				c.allowed = append(c.allowed, p.Masked())
			}
		case "peer.persistentkeepalive":
			if _, err := strconv.Atoi(v); err != nil {
				return nil, fmt.Errorf("bad PersistentKeepalive %q", v)
			}
			fmt.Fprintf(&u, "persistent_keepalive_interval=%s\n", v)
		}
	}
	c.uapi = u.String()
	if !strings.HasPrefix(c.uapi, "private_key=") || len(c.addrs) == 0 || len(c.peers) == 0 {
		return nil, fmt.Errorf("config needs [Interface] PrivateKey and Address, then a [Peer] with PublicKey")
	}
	return c, nil
}

func (c *wgConfig) routes(ip netip.Addr) bool {
	for _, p := range c.allowed {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

type wgTunnel struct {
	*wgConfig
	src  string
	dev  *device.Device
	tnet *netstack.Net
}

var (
	wgMu  sync.Mutex
	wgCur *wgTunnel
)

func systemResolve(host string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("resolve %s: %v", host, err)
	}
	return ips[0].Unmap(), nil
}

// wgFor returns a running tunnel for src, reusing the current one when src is
// unchanged so unrelated reconfigures don't drop VPN flows. Empty src stops it.
func wgFor(src string) (*wgTunnel, error) {
	wgMu.Lock()
	defer wgMu.Unlock()
	if wgCur != nil && wgCur.src == src {
		return wgCur, nil
	}
	if wgCur != nil {
		wgCur.dev.Close()
		wgCur = nil
	}
	if src == "" {
		return nil, nil
	}
	c, err := parseWG(src, systemResolve)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	t, err := startWG(c)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	t.src = src
	wgCur = t
	return t, nil
}

func startWG(c *wgConfig) (*wgTunnel, error) {
	tdev, tnet, err := netstack.CreateNetTUN(c.addrs, nil, c.mtu)
	if err != nil {
		return nil, err
	}
	logger := &device.Logger{Verbosef: device.DiscardLogf, Errorf: func(f string, a ...any) { logf("wg: "+f, a...) }}
	// Our app is excluded from the VPN, so the default bind's sockets go straight out.
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)
	if err := dev.IpcSet(c.uapi); err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, err
	}
	// WireGuard handshakes lazily, on first packet. Kick it now so the status is real
	// and the first app connection doesn't pay for the handshake.
	for _, h := range c.peers {
		var k device.NoisePublicKey
		if k.FromHex(h) == nil {
			if p := dev.LookupPeer(k); p != nil {
				p.SendKeepalive()
			}
		}
	}
	return &wgTunnel{wgConfig: c, dev: dev, tnet: tnet}, nil
}

// WgHandshakeAge is seconds since the newest peer handshake: -1 = none yet, -2 = WireGuard off.
func WgHandshakeAge() int64 {
	wgMu.Lock()
	t := wgCur
	wgMu.Unlock()
	if t == nil {
		return -2
	}
	st, err := t.dev.IpcGet()
	if err != nil {
		return -1
	}
	var newest int64
	for _, l := range strings.Split(st, "\n") {
		if v, ok := strings.CutPrefix(l, "last_handshake_time_sec="); ok {
			if n, _ := strconv.ParseInt(v, 10, 64); n > newest {
				newest = n
			}
		}
	}
	if newest == 0 {
		return -1
	}
	return time.Now().Unix() - newest
}
