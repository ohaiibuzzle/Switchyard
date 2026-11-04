package core

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// shortcut: plain map costs ~100B/domain (~30MB for 300k), switch to a succinct trie if memory bites.
type domainSet map[string]struct{}

// has reports whether name or any parent domain is in the set.
func (s domainSet) has(name string) bool {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
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
		d = strings.TrimSuffix(strings.ToLower(d), ".")
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
