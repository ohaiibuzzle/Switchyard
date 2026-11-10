package core

import (
	"net/netip"
	"testing"
)

func TestSplitRules(t *testing.T) {
	ds, ps := splitRules([]string{"1.1.1.1", "10.0.0.0/8", "2606:4700::/32", "::ffff:9.9.9.9", "::ffff:8.8.0.0/112", "fe80::1%eth0", "example.com", "1.2.3.4/33", ""})
	if len(ps) != 6 {
		t.Fatalf("parsed %d IP rules, want 6: %v", len(ps), ps)
	}
	if len(ds) != 2 || !ds.has("www.example.com") { // "1.2.3.4/33" lands here too, where no name can match it
		t.Errorf("domains = %v, want example.com and 1.2.3.4/33", ds)
	}
	for ip, want := range map[string]bool{
		"1.1.1.1": true, "1.1.1.2": false, "10.200.3.4": true, "11.0.0.1": false,
		"2606:4700:4700::1111": true, "2607::1": false, "9.9.9.9": true, "8.8.4.4": true, "fe80::1": true,
	} {
		if got := ps.has(netip.MustParseAddr(ip)); got != want {
			t.Errorf("has(%s) = %v, want %v", ip, got, want)
		}
	}
	// A host address with a prefix length still means the whole range.
	if _, ps := splitRules([]string{"192.168.1.77/24"}); !ps.has(netip.MustParseAddr("192.168.1.1")) {
		t.Error("192.168.1.77/24 should cover 192.168.1.1")
	}
}

func TestIPRule(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4": "1.2.3.4", "1.2.3.4/32": "1.2.3.4", "192.168.1.77/24": "192.168.1.0/24",
		"0::1": "::1", "2606:4700:0::/32": "2606:4700::/32", "::ffff:9.9.9.9": "9.9.9.9", "::ffff:8.8.0.0/112": "8.8.0.0/16", "fe80::1%eth0": "fe80::1",
		"example.com": "", "1.2.3.4/33": "", "1.2.3": "", "": "",
	} {
		if got := IPRule(in); got != want {
			t.Errorf("IPRule(%q) = %q, want %q", in, got, want)
		}
	}
}
