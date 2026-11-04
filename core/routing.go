package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
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
	ProxyURL     string   `json:"proxyUrl"`     // socks5://[user:pass@]host:port or http://host:port
	WGConf       string   `json:"wgConf"`       // wg-quick config text; takes precedence over ProxyURL
	RouteAll     bool     `json:"routeAll"`     // every app goes via WireGuard/proxy/exit node; else only RouteUIDs
	RouteUIDs    []int    `json:"routeUids"`
	AllowDomains []string `json:"allowDomains"` // user rules, subdomains included
	BlockDomains []string `json:"blockDomains"`
	Log          bool     `json:"log"`
	TSDir        string   `json:"tsDir"`        // Tailscale state dir; empty = off. Tailnet IPs go here before WireGuard or proxy.
	TSHostname   string   `json:"tsHostname"`   // the device's name, as Tailscale's own app uses
	TSControlURL string   `json:"tsControlUrl"` // empty = Tailscale's own servers
	TSExit       bool     `json:"tsExit"`       // route mode "exit node": the routed apps' internet goes through Tailscale
	TSExitNode   string   `json:"tsExitNode"`   // its Tailscale IP; empty with TSExit fails closed
	TSAuthKey    string   `json:"tsAuthKey"`
	TSDNS        bool     `json:"tsDns"` // ask the tailnet first, DNSUpstream for what it can't answer
}

// cur is the live settings snapshot; nil while the engine is stopped.
var cur atomic.Pointer[state]

// state is an immutable snapshot swapped atomically on Reconfigure.
type state struct {
	cfg       config
	blocked   map[int]bool
	routed    map[int]bool
	blocklist domainSet
	allow     domainSet
	block     domainSet
	up        upstream.Upstream
	dial      dialFunc
	wg        *wgTunnel
	ts        *tsNode
}

func set(xs []int) map[int]bool {
	m := map[int]bool{}
	for _, x := range xs {
		m[x] = true
	}
	return m
}

func domains(xs []string) domainSet {
	d := domainSet{}
	for _, x := range xs {
		if x = normName(x); x != "" {
			d[x] = struct{}{}
		}
	}
	return d
}

func routed(s *state, uid int) bool { return s.cfg.RouteAll || s.routed[uid] }

// viaWG returns the tunnel if this flow should use it: app selected and dst inside the peer's AllowedIPs.
func viaWG(s *state, uid int, dst netip.AddrPort) *wgTunnel {
	if s.wg != nil && routed(s, uid) && s.wg.routes(dst.Addr()) {
		return s.wg
	}
	return nil
}

// viaTS returns the Tailscale node and the route's name if this flow goes through it: the
// tailnet for every app, or the routed apps' internet when an exit node is the route.
func viaTS(s *state, uid int, dst netip.AddrPort) (*tsNode, string) {
	switch {
	case s.ts == nil:
	case inTailnet(dst.Addr()):
		return s.ts, "tailscale"
	case s.cfg.TSExit && routed(s, uid):
		return s.ts, "exit node"
	}
	return nil, ""
}

// upstreamDial opens the app's TCP flow and names the path it took: tailscale, exit node, wireguard, proxy or direct.
func upstreamDial(s *state, uid int, dst netip.AddrPort) (net.Conn, string, error) {
	if ts, rt := viaTS(s, uid, dst); ts != nil {
		c, err := ts.dial("tcp", dst)
		return c, rt, err
	}
	if wg := viaWG(s, uid, dst); wg != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		c, err := wg.tnet.DialContextTCPAddrPort(ctx, dst)
		return c, "wireguard", err
	}
	if s.cfg.ProxyURL != "" && routed(s, uid) {
		c, err := s.dial(dst.String())
		return c, "proxy", err
	}
	c, err := directDial(dst.String())
	return c, "direct", err
}

// dnsDecision returns why a name is blocked, or "" to resolve it.
// The user's allow rules beat every list; their block rules join them.
func dnsDecision(s *state, name string) string {
	switch {
	case s.allow.has(name):
		return ""
	case s.block.has(name):
		return "rule"
	case s.blocklist.has(name):
		return "adblock"
	case s.cfg.BlockBypass && bypassDomains.has(name):
		return "bypass"
	}
	return ""
}

func newState(js string) (*state, error) {
	var c config
	dec := json.NewDecoder(strings.NewReader(js))
	dec.DisallowUnknownFields() // a key the app and engine disagree on is a bug, not a no-op
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	opts := &upstream.Options{Timeout: 5 * time.Second, Logger: slog.New(slog.DiscardHandler)}
	if len(c.DNSBootstrap) > 0 {
		var ips upstream.StaticResolver
		for _, s := range c.DNSBootstrap {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("bootstrap %q: %w", s, err)
			}
			ips = append(ips, ip)
		}
		opts.Bootstrap = ips
	} else {
		r, err := upstream.NewUpstreamResolver("9.9.9.9:53", opts)
		if err != nil {
			return nil, err
		}
		opts.Bootstrap = r
	}
	up, err := upstream.AddressToUpstream(c.DNSUpstream, opts)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", c.DNSUpstream, err)
	}
	d, err := newDialer(c.ProxyURL)
	if err != nil {
		up.Close()
		return nil, err
	}
	wg, err := wgFor(c.WGConf) // last, so a failure above doesn't tear down a working tunnel
	if err != nil {
		up.Close()
		return nil, err
	}
	ts, err := tsFor(c.TSDir, c.TSHostname, c.TSControlURL, c.TSAuthKey)
	if err != nil {
		up.Close()
		return nil, fmt.Errorf("tailscale: %w", err)
	}
	if ts != nil {
		if err := ts.useExit(c.TSExitNode); err != nil {
			up.Close()
			return nil, fmt.Errorf("tailscale: %w", err)
		}
	}
	if c.TSDNS && ts != nil {
		up = tsUpstream{ts.queryDNS, up}
	}
	return &state{
		cfg: c, blocked: set(c.BlockedUIDs), routed: set(c.RouteUIDs), blocklist: loadLists(c.Blocklists),
		allow: domains(c.AllowDomains), block: domains(c.BlockDomains), up: up, dial: d, wg: wg, ts: ts,
	}, nil
}
