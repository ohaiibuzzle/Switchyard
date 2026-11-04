package core

import (
	"encoding/json"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// event is one line of the activity log, as sent to Kotlin.
type event struct {
	Seq    int64  `json:"seq"`
	T      int64  `json:"t"` // unix ms
	UID    int    `json:"uid"`
	Proto  string `json:"proto"` // tcp, udp, dns
	Dst    string `json:"dst,omitempty"`
	Host   string `json:"host,omitempty"`
	Action string `json:"action"`           // allow, block, fail
	Reason string `json:"reason,omitempty"` // code: route on allow/fail, rule on block
	Err    string `json:"err,omitempty"`    // why a fail failed
}

const maxEvents = 2000

var (
	evMu   sync.Mutex
	evs    []event
	evSeq  int64
	ipHost = map[netip.Addr]string{} // guarded by evMu; only filled while logging
)

func logging() bool { s := cur.Load(); return s != nil && s.cfg.Log }

func record(e event) {
	if !logging() {
		return
	}
	evMu.Lock()
	defer evMu.Unlock()
	evSeq++
	e.Seq, e.T = evSeq, time.Now().UnixMilli()
	evs = append(evs, e)
	if len(evs) >= 2*maxEvents { // trim in bulk so a full log isn't shifted on every event
		evs = append(evs[:0], evs[len(evs)-maxEvents:]...)
	}
}

// logFlow records a connection decision; a non-nil err turns it into a failed dial.
func logFlow(uid int, proto string, dst netip.AddrPort, action, reason string, err error) {
	if !logging() {
		return
	}
	e := event{UID: uid, Proto: proto, Dst: dst.String(), Host: hostFor(dst.Addr()), Action: action, Reason: reason}
	if err != nil {
		e.Action, e.Err = "fail", err.Error()
	}
	record(e)
}

// Events returns log entries newer than seq, oldest first, as a JSON array.
func Events(after int64) string {
	evMu.Lock()
	defer evMu.Unlock()
	i := sort.Search(len(evs), func(i int) bool { return evs[i].Seq > after })
	i = max(i, len(evs)-maxEvents)
	if i == len(evs) {
		return "[]" // a nil slice would marshal as null
	}
	b, _ := json.Marshal(evs[i:])
	return string(b)
}

// ClearEvents empties the log and the IP->domain memory.
func ClearEvents() {
	evMu.Lock()
	defer evMu.Unlock()
	evs, ipHost = nil, map[netip.Addr]string{}
}

// noteAnswer remembers which domain each answered IP belongs to, so connection
// entries can show a name instead of a bare IP.
func noteAnswer(m *dns.Msg) {
	if !logging() || len(m.Question) != 1 {
		return
	}
	name := normName(m.Question[0].Name)
	evMu.Lock()
	defer evMu.Unlock()
	if len(ipHost) > 20000 { // shortcut: crude cap instead of LRU, fine for a debugging aid
		ipHost = map[netip.Addr]string{}
	}
	for _, rr := range m.Answer {
		var ip netip.Addr
		switch r := rr.(type) {
		case *dns.A:
			ip, _ = netip.AddrFromSlice(r.A.To4())
		case *dns.AAAA:
			ip, _ = netip.AddrFromSlice(r.AAAA)
		}
		if ip.IsValid() {
			ipHost[ip] = name
		}
	}
}

func hostFor(ip netip.Addr) string {
	if !logging() {
		return ""
	}
	evMu.Lock()
	defer evMu.Unlock()
	return ipHost[ip]
}
