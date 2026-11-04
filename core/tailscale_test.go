package core

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/types/key"
)

func TestInTailnet(t *testing.T) {
	for ip, want := range map[string]bool{
		"100.63.255.255": false, "100.64.0.0": true, "100.101.102.103": true, "100.127.255.255": true,
		"100.128.0.0": false, "8.8.8.8": false, "fd7a:115c:a1e0::1": true, "fd7a:115c:a1e1::1": false,
	} {
		if got := inTailnet(netip.MustParseAddr(ip)); got != want {
			t.Errorf("inTailnet(%s) = %v, want %v", ip, got, want)
		}
	}
	s := &state{} // Tailscale off: nothing goes to the tailnet
	if viaTS(s, netip.MustParseAddrPort("100.64.0.1:80")) != nil {
		t.Error("viaTS with Tailscale off")
	}
}

type fixedUpstream struct{ rcode int }

func (f fixedUpstream) Exchange(_ context.Context, req *dns.Msg) (*dns.Msg, error) {
	r := new(dns.Msg)
	r.SetRcode(req, f.rcode)
	return r, nil
}
func (fixedUpstream) Address() string { return "fixed" }
func (fixedUpstream) Close() error    { return nil }

func TestTailscaleDNSFallback(t *testing.T) {
	req := new(dns.Msg).SetQuestion("example.com.", dns.TypeA)
	for name, c := range map[string]struct {
		tsRcode int
		tsErr   error
		want    int
	}{
		"tailnet answers":       {dns.RcodeSuccess, nil, dns.RcodeSuccess},
		"tailnet says no such":  {dns.RcodeNameError, nil, dns.RcodeNameError},
		"tailnet can't forward": {dns.RcodeServerFailure, nil, dns.RcodeRefused},
		"tailnet refuses":       {dns.RcodeRefused, nil, dns.RcodeRefused},
		"tailnet down":          {0, errors.New("down"), dns.RcodeRefused},
	} {
		u := tsUpstream{
			ask: func(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
				if c.tsErr != nil {
					return nil, c.tsErr
				}
				return fixedUpstream{c.tsRcode}.Exchange(ctx, m)
			},
			next: fixedUpstream{dns.RcodeRefused}, // marks "came from the fallback"
		}
		r, err := u.Exchange(context.Background(), req)
		if err != nil || r.Rcode != c.want {
			t.Errorf("%s: rcode %d err %v, want %d", name, r.Rcode, err, c.want)
		}
	}
}

func TestPeerList(t *testing.T) {
	if got := peerList(nil); got == nil || len(got) != 0 {
		t.Fatalf("nil status: %v, want empty non-nil (JSON [])", got)
	}
	st := &ipnstate.Status{Peer: map[key.NodePublic]*ipnstate.PeerStatus{
		key.NewNode().Public(): {DNSName: "zed.tail1234.ts.net.", OS: "linux", Online: true, TailscaleIPs: []netip.Addr{netip.MustParseAddr("100.64.0.3")}},
		key.NewNode().Public(): {HostName: "offline-box", OS: "windows"},
		key.NewNode().Public(): {DNSName: "alpha.tail1234.ts.net.", Online: true},
	}}
	got := peerList(st)
	want := []string{"alpha", "zed", "offline-box"} // online first, then by name
	for i, p := range got {
		if p.Name != want[i] {
			t.Fatalf("order %d: %q, want %q (%+v)", i, p.Name, want[i], got)
		}
	}
	if got[1].IP != "100.64.0.3" || got[2].IP != "" {
		t.Fatalf("ips: %+v", got)
	}
}
