package core

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRoutesExcluding(t *testing.T) {
	got, err := RoutesExcluding("0.0.0.0/0", "192.168.1.0/24 224.0.0.0/4 fe80::/10 junk")
	if err != nil {
		t.Fatal(err)
	}
	routes := strings.Split(got, "\n")
	in := func(ip string) bool {
		a := netip.MustParseAddr(ip)
		for _, r := range routes {
			if netip.MustParsePrefix(r).Contains(a) {
				return true
			}
		}
		return false
	}
	for ip, want := range map[string]bool{
		"0.0.0.0": true, "8.8.8.8": true, "192.168.0.255": true, "192.168.1.0": false, "192.168.1.255": false,
		"192.168.2.0": true, "223.255.255.255": true, "224.0.0.251": false, "239.255.255.250": false, "240.0.0.1": true,
		"255.255.255.255": true, "10.111.0.2": true,
	} {
		if in(ip) != want {
			t.Errorf("%s routed = %v, want %v", ip, !want, want)
		}
	}
	if len(routes) > 64 { // one split per bit at most, per exclusion
		t.Errorf("%d routes", len(routes))
	}
	if got, _ := RoutesExcluding("0.0.0.0/0", "10.0.0.0/8"); got != "0.0.0.0/0" {
		t.Errorf("a LAN covering our DNS address must not be skipped: %q", got)
	}
	if got, _ := RoutesExcluding("0.0.0.0/0", "100.64.0.0/10 100.100.0.0/16"); got != "0.0.0.0/0" {
		t.Errorf("a CGNAT network overlapping the tailnet must not be skipped: %q", got)
	}
	if got, _ := RoutesExcluding("::/0", ""); got != "::/0" {
		t.Errorf("no exclusions: %q", got)
	}
	if got, _ := RoutesExcluding("::/0", "::/1"); got != "8000::/1" {
		t.Errorf("half excluded: %q", got)
	}
}
