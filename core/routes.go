package core

import (
	"fmt"
	"net/netip"
	"strings"
)

// RoutesExcluding returns root minus the excluded prefixes as newline-separated CIDRs, for
// VpnService routes. Builder.excludeRoute needs Android 13 and we support 10.
// Unparseable or out-of-family exclusions are ignored, and so is any that keepRouted rejects.
func RoutesExcluding(root, excl string) (string, error) {
	r, err := netip.ParsePrefix(root)
	if err != nil {
		return "", fmt.Errorf("route %q: %w", root, err)
	}
	var ex []netip.Prefix
	for _, s := range strings.Fields(excl) {
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Is4() == r.Addr().Is4() && keepRouted(p) {
			ex = append(ex, p.Masked())
		}
	}
	var out []string
	for _, p := range complement(r.Masked(), ex) {
		out = append(out, p.String())
	}
	return strings.Join(out, "\n"), nil
}

// The DNS addresses FilterVpnService announces on the tun; keep them in sync.
var tunDNS4, tunDNS6 = netip.MustParseAddr("10.111.0.2"), netip.MustParseAddr("fd00:111::2")

// keepRouted says an exclusion would swallow addresses that must stay in the tun: our DNS
// address, or the tailnet ranges (carrier-grade NAT networks also live in 100.64.0.0/10).
func keepRouted(p netip.Prefix) bool {
	return !p.Contains(tunDNS4) && !p.Contains(tunDNS6) && !p.Overlaps(tailnet4) && !p.Overlaps(tailnet6)
}

// complement splits p in halves until each piece is either clear of every exclusion or inside one.
func complement(p netip.Prefix, ex []netip.Prefix) []netip.Prefix {
	overlaps := false
	for _, e := range ex {
		if e.Bits() <= p.Bits() && e.Contains(p.Addr()) {
			return nil // p lies inside an exclusion
		}
		if p.Contains(e.Addr()) {
			overlaps = true
		}
	}
	if !overlaps {
		return []netip.Prefix{p}
	}
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	b := p.Addr().AsSlice()
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	a, _ := netip.AddrFromSlice(b)
	return append(complement(lo, ex), complement(netip.PrefixFrom(a, p.Bits()+1), ex)...)
}
