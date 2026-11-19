package core

import (
	"testing"

	"github.com/ameshkov/dnsstamps"
)

func TestEncryptedUpstream(t *testing.T) {
	stamp := func(p dnsstamps.StampProtoType) string {
		return (&dnsstamps.ServerStamp{Proto: p, ServerAddrStr: "1.2.3.4", ProviderName: "dns.example", Path: "/dns-query"}).String()
	}
	for addr, ok := range map[string]bool{
		"https://dns.example/dns-query": true,
		"h3://dns.example/dns-query":    true,
		"tls://dns.example":             true,
		"quic://dns.example":            true,
		// AdGuard DNS's published DNSCrypt stamp.
		"sdns://AQMAAAAAAAAAETk0LjE0MC4xNC4xNDo1NDQzINErR_JS3PLCu_iZEIbq95zkSV2LFsigxDIuUso_OQhzIjIuZG5zY3J5cHQuZGVmYXVsdC5uczEuYWRndWFyZC5jb20": true,
		stamp(dnsstamps.StampProtoTypeDoH):   false,
		stamp(dnsstamps.StampProtoTypeTLS):   false,
		stamp(dnsstamps.StampProtoTypeDoQ):   false,
		stamp(dnsstamps.StampProtoTypePlain): false,
		"sdns://garbage":                     false,
		"udp://9.9.9.9":                      false,
		"tcp://9.9.9.9":                      false,
		"9.9.9.9":                            false,
	} {
		if err := encrypted(addr); (err == nil) != ok {
			t.Errorf("%s: err=%v, want ok=%v", addr, err, ok)
		}
	}
}
