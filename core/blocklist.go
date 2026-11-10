package core

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

// shortcut: plain map costs ~100B/domain (~30MB for 300k), switch to a succinct trie if memory bites.
type domainSet map[string]struct{}

func normName(name string) string { return strings.TrimSuffix(strings.ToLower(name), ".") }

// has reports whether name or any parent domain is in the set.
func (s domainSet) has(name string) bool {
	name = normName(name)
	for name != "" {
		if _, ok := s[name]; ok {
			return true
		}
		i := strings.IndexByte(name, '.')
		if i < 0 {
			return false
		}
		name = name[i+1:]
	}
	return false
}

// parseList accepts hosts files, plain domain lists and adblock `||domain^` rules.
func (s domainSet) parseList(r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || line[0] == '[' {
			continue
		}
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		d := f[0]
		if len(f) >= 2 { // hosts format: "0.0.0.0 domain"
			d = f[1]
		}
		if strings.HasPrefix(d, "||") {
			if !strings.HasSuffix(d, "^") {
				continue // path/regex rules are not domain rules
			}
			d = d[2 : len(d)-1]
		}
		d = strings.TrimPrefix(strings.TrimPrefix(d, "*."), ".")
		d = normName(d)
		if d == "" || !strings.Contains(d, ".") || strings.ContainsAny(d, "/*$@|^:") {
			continue // also skips localhost, IPv6 and broadcast entries
		}
		s[d] = struct{}{}
	}
}

func loadLists(paths []string) domainSet {
	s := domainSet{}
	for _, p := range paths {
		f, err := os.Open(p)
		if err != nil {
			logf("blocklist %s: %v", p, err)
			continue
		}
		s.parseList(f)
		f.Close()
	}
	return s
}

// prefixSet holds the user's IP rules: single IPs and CIDR ranges.
type prefixSet []netip.Prefix

// parsePrefix reads a single IP or CIDR range; a single IP becomes a full-length prefix.
func parsePrefix(x string) (netip.Prefix, bool) {
	p, err := netip.ParsePrefix(x)
	if err != nil {
		a, err := netip.ParseAddr(x)
		if err != nil {
			return netip.Prefix{}, false
		}
		a = a.WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 { // flows arrive unmapped
		p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
	}
	return p.Masked(), true
}

// splitRules sorts the user's block rules into IPs/CIDR ranges and domains (anything else).
func splitRules(xs []string) (domainSet, prefixSet) {
	var ps prefixSet
	var ds []string
	for _, x := range xs {
		if p, ok := parsePrefix(x); ok {
			ps = append(ps, p)
		} else {
			ds = append(ds, x)
		}
	}
	return domains(ds), ps
}

// IPRule returns x as a canonical IP rule ("1.2.3.4", "10.0.0.0/8"), or "" if it isn't one.
// The app validates and stores rules through it, so stored rules are exactly what splitRules accepts.
func IPRule(x string) string {
	p, ok := parsePrefix(x)
	switch {
	case !ok:
		return ""
	case p.IsSingleIP():
		return p.Addr().String()
	}
	return p.String()
}

// has reports whether any rule covers a.
// shortcut: linear scan, fine for hand-written rules; use a prefix trie if rules ever come from imported lists.
func (ps prefixSet) has(a netip.Addr) bool {
	for _, p := range ps {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
