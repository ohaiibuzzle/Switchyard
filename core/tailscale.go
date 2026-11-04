package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/miekg/dns"
	"tailscale.com/envknob"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/net/netmon"
	"tailscale.com/tsnet"
)

// Tailscale runs as a userspace node (tsnet). Its sockets go straight out because our app is
// excluded from the VPN, the same as WireGuard's.

var (
	tsMu  sync.Mutex             // serialises tsFor, which can block while a node starts
	tsCur atomic.Pointer[tsNode] // read lock-free so the status poll doesn't wait on a start
	// shortcut: only the CGNAT and ULA tailnet ranges, not subnet routes; read PrimaryRoutes from status if asked.
	tailnet4 = netip.MustParsePrefix("100.64.0.0/10")
	tailnet6 = netip.MustParsePrefix("fd7a:115c:a1e0::/48")
)

type tsNode struct {
	key string
	srv *tsnet.Server
	// The exit node last applied, valid once exitSet; only newState touches these, under the engine's mu.
	exit    string
	exitSet bool
}

func init() {
	envknob.SetNoLogsNoSupport() // never upload logs to Tailscale; we promise nothing leaves for a server we don't pick
	if runtime.GOOS == "android" {
		netmon.RegisterInterfaceGetter(androidInterfaces)
	}
}

func inTailnet(a netip.Addr) bool { return tailnet4.Contains(a) || tailnet6.Contains(a) }

// tsFor returns a running node for these settings, reusing the current one when they're
// unchanged. An empty dir stops it.
func tsFor(dir, hostname, controlURL, authKey string) (*tsNode, error) {
	key := dir + "\n" + hostname + "\n" + controlURL + "\n" + authKey
	tsMu.Lock()
	defer tsMu.Unlock()
	if t := tsCur.Load(); t != nil && t.key == key {
		return t, nil
	}
	// shortcut: the old node closes before the new one starts (they'd share a state dir), so a failed
	// start leaves Tailscale off until the next change or restart; Start rarely fails, as login is async.
	if t := tsCur.Swap(nil); t != nil {
		t.srv.Close()
	}
	if dir == "" {
		return nil, nil
	}
	// Android apps have no $HOME or $TMPDIR, so Tailscale panics looking for a logs dir unless told.
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	os.Setenv("TS_LOGS_DIR", dir)
	srv := &tsnet.Server{
		Dir: dir, Hostname: hostname, ControlURL: controlURL, AuthKey: authKey,
		// Silent: the user-facing log repeats the login URL every 5s, and TsStatus already shows it.
		Logf: func(string, ...any) {}, UserLogf: func(string, ...any) {},
	}
	// Returns once the backend runs; with no saved login it starts one, and the URL shows in TsStatus.
	if err := srv.Start(); err != nil {
		srv.Close()
		return nil, err
	}
	t := &tsNode{key: key, srv: srv}
	tsCur.Store(t)
	return t, nil
}

// dial connects through the tailnet. tsnet would quietly dial anything it has no route for
// straight out, so refuse those: an exit node that's offline, gone or unpicked fails closed.
func (t *tsNode) dial(network string, dst netip.AddrPort) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	d := t.srv.Sys().Dialer.Get()
	if _, via, err := d.UserDialPlan(ctx, network, dst.String()); err != nil {
		return nil, err
	} else if !via {
		return nil, errors.New("no Tailscale route (exit node offline or not picked?)")
	}
	return d.UserDial(ctx, network, dst.String())
}

// useExit sends the node's internet traffic through the exit node with this IP, or none for "".
// The node is kept, so changing it doesn't drop tailnet connections or need a new login.
func (t *tsNode) useExit(ip string) error {
	if t.exitSet && ip == t.exit {
		return nil
	}
	var a netip.Addr // zero clears it
	if ip != "" {
		var err error
		if a, err = netip.ParseAddr(ip); err != nil {
			return fmt.Errorf("exit node %q: %w", ip, err)
		}
	}
	lc, err := t.srv.LocalClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Clearing the ID too: Tailscale swaps a set IP for the node's ID, which is what's saved.
	if _, err := lc.EditPrefs(ctx, &ipn.MaskedPrefs{Prefs: ipn.Prefs{ExitNodeIP: a}, ExitNodeIPSet: true, ExitNodeIDSet: true}); err != nil {
		return err
	}
	t.exit, t.exitSet = ip, true
	return nil
}

// tsUpstream asks the tailnet's resolver (100.100.100.100: MagicDNS and the tailnet's DNS settings) and
// falls back to next for what it can't answer. tsnet can't read Android's DNS settings, so without
// global nameservers in the tailnet it fails every public name.
type tsUpstream struct {
	ask  func(context.Context, *dns.Msg) (*dns.Msg, error) // tsNode.queryDNS; swapped in tests
	next upstream.Upstream
}

func (u tsUpstream) Exchange(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	tctx, cancel := context.WithTimeout(ctx, 2*time.Second) // a starting or stuck node mustn't hang every lookup
	defer cancel()
	if r, err := u.ask(tctx, req); err == nil && r.Rcode != dns.RcodeServerFailure && r.Rcode != dns.RcodeRefused {
		return r, nil
	}
	return u.next.Exchange(ctx, req)
}

func (t *tsNode) queryDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	if len(req.Question) != 1 {
		return nil, errors.New("tailscale dns: one question per query")
	}
	lc, err := t.srv.LocalClient()
	if err != nil {
		return nil, err
	}
	q := req.Question[0]
	b, _, err := lc.QueryDNS(ctx, q.Name, dns.TypeToString[q.Qtype])
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	if err := r.Unpack(b); err != nil {
		return nil, err
	}
	r.Id = req.Id
	return r, nil
}

func (tsUpstream) Address() string { return "tailscale" }
func (u tsUpstream) Close() error  { return u.next.Close() } // the node itself outlives the snapshot

// TsStatus is JSON {state, authUrl, ip}; state is "Off" when Tailscale isn't running.
func TsStatus() string {
	out := map[string]string{"state": "Off"}
	if t := tsCur.Load(); t != nil {
		out["state"] = "Starting"
		if lc, err := t.srv.LocalClient(); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if st, err := lc.StatusWithoutPeers(ctx); err == nil {
				out["state"], out["authUrl"] = st.BackendState, st.AuthURL
				if len(st.TailscaleIPs) > 0 {
					out["ip"] = st.TailscaleIPs[0].String()
				}
			}
		}
	}
	b, _ := json.Marshal(out)
	return string(b)
}

type tsPeer struct {
	Name   string `json:"name"` // MagicDNS short name, what users type
	IP     string `json:"ip"`
	OS     string `json:"os"`
	Online bool   `json:"online"`
	Exit   bool   `json:"exit"`  // offers itself as an exit node
	InUse  bool   `json:"inUse"` // our current exit node
}

// TsPeers is a JSON array of the devices this node can see, online ones first; "[]" when off.
func TsPeers() string {
	var st *ipnstate.Status
	if t := tsCur.Load(); t != nil {
		if lc, err := t.srv.LocalClient(); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			st, _ = lc.Status(ctx)
		}
	}
	b, _ := json.Marshal(peerList(st))
	return string(b)
}

func peerList(st *ipnstate.Status) []tsPeer {
	out := []tsPeer{}
	if st == nil {
		return out
	}
	for _, p := range st.Peer {
		name, _, _ := strings.Cut(p.DNSName, ".")
		if name == "" {
			name = p.HostName
		}
		var ip string
		if len(p.TailscaleIPs) > 0 {
			ip = p.TailscaleIPs[0].String()
		}
		out = append(out, tsPeer{name, ip, p.OS, p.Online, p.ExitNodeOption, p.ExitNode})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Online != out[j].Online {
			return out[i].Online
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// TsLogin asks for a fresh login URL (after a sign-out); it shows up in TsStatus.
func TsLogin() error {
	return tsLocal(func(ctx context.Context, t *tsNode) error {
		lc, err := t.srv.LocalClient()
		if err != nil {
			return err
		}
		return lc.StartLoginInteractive(ctx)
	})
}

func TsLogout() error {
	return tsLocal(func(ctx context.Context, t *tsNode) error {
		lc, err := t.srv.LocalClient()
		if err != nil {
			return err
		}
		return lc.Logout(ctx)
	})
}

func tsLocal(f func(context.Context, *tsNode) error) error {
	t := tsCur.Load()
	if t == nil {
		return errors.New("tailscale is off")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return f(ctx, t)
}

// androidInterfaces stands in for net.Interfaces, which Android denies to apps. It reports one
// interface with the source addresses the kernel picks for outbound traffic (dialing UDP sends
// nothing). Adapted from tailscale.com/feature/androidbin, which skips cgo builds like ours.
func androidInterfaces() ([]netmon.Interface, error) {
	var addrs []net.Addr
	for _, p := range [][2]string{{"udp4", "8.8.8.8:53"}, {"udp6", "[2001:4860:4860::8888]:53"}} {
		c, err := net.DialTimeout(p[0], p[1], 2*time.Second)
		if err != nil {
			continue
		}
		ip := c.LocalAddr().(*net.UDPAddr).IP
		c.Close()
		bits := 8 * len(ip.To16())
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		addrs = append(addrs, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	if len(addrs) == 0 {
		return nil, errors.New("no outbound route")
	}
	return []netmon.Interface{{
		Interface: &net.Interface{Name: "android", MTU: 1500, Flags: net.FlagUp | net.FlagRunning},
		AltAddrs:  addrs,
	}}, nil
}
