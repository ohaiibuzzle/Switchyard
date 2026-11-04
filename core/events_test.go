package core

import (
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
)

func TestDNSDecision(t *testing.T) {
	s := &state{
		cfg:       config{BlockBypass: true},
		blocklist: domains([]string{"ads.example", "tracker.example"}),
		allow:     domains([]string{"cdn.ads.example", "dns.google"}),
		block:     domains([]string{"Social.Example."}),
	}
	for name, want := range map[string]string{
		"x.ads.example":      "adblock",
		"cdn.ads.example":    "", // allow beats the ad list
		"a.cdn.ads.example":  "",
		"dns.google":         "", // allow beats the bypass list
		"cloudflare-dns.com": "bypass",
		"m.social.example.":  "rule",
		"example.org":        "",
	} {
		if got := dnsDecision(s, name); got != want {
			t.Errorf("%s: got %q want %q", name, got, want)
		}
	}
}

func TestConfigRejectsUnknownKeys(t *testing.T) {
	if _, err := newState(`{"dnsUpstream":"tls://1.1.1.1","blockedUid":[1]}`); err == nil {
		t.Fatal("a misspelled key must fail instead of being ignored")
	}
}

func TestLogFlow(t *testing.T) {
	defer func() { cur.Store(nil); ClearEvents() }()
	cur.Store(&state{cfg: config{Log: true}})
	dst := netip.MustParseAddrPort("10.0.0.1:443")
	logFlow(7, "tcp", dst, "allow", "proxy", nil)
	logFlow(7, "tcp", dst, "allow", "proxy", errors.New("refused"))
	var got []event
	json.Unmarshal([]byte(Events(0)), &got)
	if len(got) != 2 || got[0].Action != "allow" || got[1].Action != "fail" || got[1].Reason != "proxy" || got[1].Err != "refused" {
		t.Fatalf("%+v", got)
	}
}

func TestEventLog(t *testing.T) {
	defer func() { cur.Store(nil); ClearEvents() }()
	ClearEvents()
	record(event{Action: "allow"})
	if Events(0) != "[]" {
		t.Fatal("must not record while logging is off")
	}
	cur.Store(&state{cfg: config{Log: true}})
	for i := 0; i < 2*maxEvents+5; i++ { // crosses the bulk trim
		record(event{UID: i, Action: "allow"})
	}
	var all []event
	json.Unmarshal([]byte(Events(0)), &all)
	if len(all) != maxEvents || all[0].UID != maxEvents+5 {
		t.Fatalf("ring: len %d first uid %d", len(all), all[0].UID)
	}
	var tail []event
	json.Unmarshal([]byte(Events(all[len(all)-3].Seq)), &tail)
	if len(tail) != 2 {
		t.Fatalf("Events(after) returned %d, want 2", len(tail))
	}

	m := new(dns.Msg)
	m.SetQuestion("Example.COM.", dns.TypeA)
	m.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA}, A: net.ParseIP("93.184.215.14")}}
	noteAnswer(m)
	if got := hostFor(netip.MustParseAddr("93.184.215.14")); got != "example.com" {
		t.Fatalf("hostFor: %q", got)
	}
	ClearEvents()
	if Events(0) != "[]" || hostFor(netip.MustParseAddr("93.184.215.14")) != "" {
		t.Fatal("ClearEvents must wipe both")
	}
}
