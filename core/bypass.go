package core

import "net/netip"

// Well-known encrypted-DNS endpoints that apps use to dodge the system resolver.
var bypassDomains = domainSet{}

var bypassIPs = map[netip.Addr]bool{}

func init() {
	for _, d := range []string{
		"dns.google", "dns.google.com", "dns64.dns.google",
		"cloudflare-dns.com", "one.one.one.one", "1dot1dot1dot1.cloudflare-dns.com",
		"dns.quad9.net", "dns9.quad9.net", "dns10.quad9.net", "dns11.quad9.net",
		"dns.adguard.com", "dns.adguard-dns.com", "doh.opendns.com", "dns.opendns.com",
		"dns.nextdns.io", "doh.cleanbrowsing.org", "dns.mullvad.net", "doh.mullvad.net",
		"doh.dns.sb", "dns.alidns.com", "doh.pub", "dot.pub", "dns.twnic.tw",
		"doh.libredns.gr", "dns.controld.com", "freedns.controld.com",
		"use-application-dns.net", // Firefox canary: NXDOMAIN turns its built-in DoH off
	} {
		bypassDomains[d] = struct{}{}
	}
	for _, s := range []string{
		"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
		"94.140.14.14", "94.140.15.15", "208.67.222.222", "208.67.220.220",
		"185.228.168.168", "76.76.2.0", "76.76.10.0", "45.90.28.0", "45.90.30.0",
		"2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
		"2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9", "2a10:50c0::ad1:ff",
	} {
		bypassIPs[netip.MustParseAddr(s)] = true
	}
}
