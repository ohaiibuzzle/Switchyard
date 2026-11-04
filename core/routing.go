package core

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
)

type config struct {
	DNSUpstream  string   `json:"dnsUpstream"`  // https://, h3://, tls://, quic://
	DNSBootstrap []string `json:"dnsBootstrap"` // IPs of the upstream host; empty = resolve via 9.9.9.9
	BlockedUIDs  []int    `json:"blockedUids"`
	Blocklists   []string `json:"blocklists"` // file paths; empty = ad-block off
	BlockBypass  bool     `json:"blockBypass"`
	SNISplit     bool     `json:"sniSplit"`
	TLSFrag      bool     `json:"tlsFrag"`
	HostTricks   bool     `json:"hostTricks"`
	BlockQUIC    bool     `json:"blockQuic"`
	ProxyURL     string   `json:"proxyUrl"`  // socks5://[user:pass@]host:port or http://host:port
	WGConf       string   `json:"wgConf"`    // wg-quick config text; takes precedence over ProxyURL
	RouteUIDs    []int    `json:"routeUids"` // apps sent via WireGuard/proxy; empty = all apps
}

// state is an immutable snapshot swapped atomically on Reconfigure.
type state struct {
	cfg       config
	blocked   map[int]bool
	routed    map[int]bool
	blocklist domainSet
	up        upstream.Upstream
	dial      dialFunc
	wg        *wgTunnel
}

func set(xs []int) map[int]bool {
	m := map[int]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func routed(s *state, uid int) bool { return len(s.routed) == 0 || s.routed[uid] }

// viaWG returns the tunnel if this flow should use it: app selected and dst inside the peer's AllowedIPs.
func viaWG(s *state, uid int, dst netip.AddrPort) *wgTunnel {
	if s.wg != nil && routed(s, uid) && s.wg.routes(dst.Addr()) {
		return s.wg
	}
	return nil
}

func upstreamDial(s *state, uid int, dst netip.AddrPort) (net.Conn, error) {
	if wg := viaWG(s, uid, dst); wg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return wg.tnet.DialContextTCPAddrPort(ctx, dst)
	}
	if s.cfg.ProxyURL != "" && routed(s, uid) {
		return s.dial(dst.String())
	}
	return directDial(dst.String())
}
