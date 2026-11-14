package bench

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
)

// Masker replaces the owner's private details in recorded text with stable
// placeholders (docs/research/agent-benchmark.md, "Privacy"): literal
// values the harness finds on the machine (user name, host name, search
// domains, interface names, Docker resources outside the lab), every MAC
// address, and every IP address outside the prefixes it is told to keep.
// The same value always gets the same placeholder.
type Masker struct {
	mu       sync.Mutex
	literals []literal
	keep     []netip.Prefix
	keepAddr []netip.Addr
	dns      []netip.Addr
	seen     map[string]string // value → placeholder
	counts   map[string]int    // placeholder kind → how many so far
}

type literal struct {
	value, placeholder string
}

// NewMasker keeps loopback, the unspecified addresses, TEST-NET-1 (WR020's
// dead resolver), multicast and broadcast, and a few public resolvers an
// agent may name.
func NewMasker() *Masker {
	m := &Masker{seen: map[string]string{}, counts: map[string]int{}}
	for _, p := range []string{"127.0.0.0/8", "::1/128", "0.0.0.0/32", "::/128", "192.0.2.0/24", "224.0.0.0/3"} {
		m.keep = append(m.keep, netip.MustParsePrefix(p))
	}
	for _, a := range []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"} {
		m.keepAddr = append(m.keepAddr, netip.MustParseAddr(a))
	}
	return m
}

// Literal masks a value wherever it appears as a whole token, ignoring
// case. Values shorter than 3 characters are ignored.
func (m *Masker) Literal(value, kind string) {
	value = strings.TrimSpace(value)
	if len(value) < 3 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.ContainsFunc(m.literals, func(l literal) bool { return strings.EqualFold(l.value, value) }) {
		return
	}
	m.literals = append(m.literals, literal{value, m.placeholder(strings.ToLower(value), kind)})
	// Longest first, so a host name that contains the user name goes whole.
	sort.SliceStable(m.literals, func(i, j int) bool { return len(m.literals[i].value) > len(m.literals[j].value) })
}

// Keep leaves addresses in a prefix as they are (the lab's Docker subnets).
func (m *Masker) Keep(p netip.Prefix) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.keep = append(m.keep, p.Masked())
}

// DNSServer marks an address as one of the host's resolvers: it is masked
// as such even where it would otherwise be kept, as 127.0.9.9 would be.
func (m *Masker) DNSServer(a netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dns = append(m.dns, a.Unmap())
}

func (m *Masker) placeholder(key, kind string) string {
	if p, ok := m.seen[key]; ok {
		return p
	}
	m.counts[kind]++
	p := fmt.Sprintf("<%s-%d>", kind, m.counts[kind])
	m.seen[key] = p
	return p
}

var (
	ipv4Re  = regexp.MustCompile(`\d{1,3}(?:\.\d{1,3}){3}`)
	ipv6Re  = regexp.MustCompile(`[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?:%[0-9A-Za-z_.-]+)?`)
	macRe   = regexp.MustCompile(`(?i)\b[0-9a-f]{2}(?:[:-][0-9a-f]{2}){5}\b`)
	emailRe = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)
)

// String masks a text.
func (m *Masker) String(s string) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	s = emailRe.ReplaceAllStringFunc(s, func(e string) string { return m.placeholder(strings.ToLower(e), "email") })
	for _, l := range m.literals {
		s = replaceToken(s, l.value, l.placeholder)
	}
	s = macRe.ReplaceAllStringFunc(s, func(mac string) string { return m.placeholder(strings.ToLower(mac), "mac") })
	s = replaceAddrs(s, ipv6Re, isHexOrColon, func(tok string) (string, bool) {
		addr, zone, _ := strings.Cut(tok, "%")
		a, err := netip.ParseAddr(addr)
		if err != nil || !a.Is6() || a.Is4In6() {
			return "", false
		}
		if m.kept(a) {
			return "", false
		}
		_ = zone
		return m.placeholder(a.String(), "ip6"), true
	})
	s = replaceAddrs(s, ipv4Re, isDigitByte, func(tok string) (string, bool) {
		a, err := netip.ParseAddr(tok)
		if err != nil {
			return "", false
		}
		if slices.Contains(m.dns, a) {
			return m.placeholder(a.String(), "dns"), true
		}
		if m.kept(a) {
			return "", false
		}
		return m.placeholder(a.String(), "ip"), true
	})
	return s
}

func (m *Masker) kept(a netip.Addr) bool {
	a = a.Unmap()
	if slices.Contains(m.dns, a) {
		return false
	}
	if slices.Contains(m.keepAddr, a) {
		return true
	}
	for _, p := range m.keep {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// replaceAddrs replaces the matches of re that f accepts, unless they
// continue a longer token: a byte of the address's own kind (in), or a dot
// followed by a digit, as in a version string. A full stop that ends a
// sentence doesn't continue it.
func replaceAddrs(s string, re *regexp.Regexp, in func(byte) bool, f func(string) (string, bool)) string {
	var b strings.Builder
	last := 0
	for _, loc := range re.FindAllStringIndex(s, -1) {
		start, end := loc[0], loc[1]
		if start > 0 && (in(s[start-1]) || (s[start-1] == '.' && start > 1 && isDigitByte(s[start-2]))) {
			continue
		}
		if end < len(s) && (in(s[end]) || (s[end] == '.' && end+1 < len(s) && isDigitByte(s[end+1]))) {
			continue
		}
		rep, ok := f(s[start:end])
		if !ok {
			continue
		}
		b.WriteString(s[last:start])
		b.WriteString(rep)
		last = end
	}
	b.WriteString(s[last:])
	return b.String()
}

func isDigitByte(c byte) bool { return c >= '0' && c <= '9' }

func isHexOrColon(c byte) bool {
	return c == ':' || isDigitByte(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// replaceToken replaces value, ignoring case, where it isn't part of a
// longer word.
func replaceToken(s, value, rep string) string {
	lower, lv := strings.ToLower(s), strings.ToLower(value)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(lower[i:], lv)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		start, end := i+j, i+j+len(lv)
		if (start > 0 && isWordByte(s[start-1])) || (end < len(s) && isWordByte(s[end])) {
			b.WriteString(s[i:end])
			i = end
			continue
		}
		b.WriteString(s[i:start])
		b.WriteString(rep)
		i = end
	}
}

func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// Leaks lists the literal values still present in s, ignoring case: a
// check run on everything before it is written.
func (m *Masker) Leaks(s string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	lower := strings.ToLower(s)
	var out []string
	for _, l := range m.literals {
		if strings.Contains(lower, strings.ToLower(l.value)) {
			out = append(out, l.placeholder)
		}
	}
	for _, d := range m.dns {
		if strings.Contains(s, d.String()) {
			out = append(out, "a DNS server address")
		}
	}
	// Any address left that masking would have replaced, whatever its
	// surroundings.
	for _, re := range []*regexp.Regexp{ipv4Re, ipv6Re} {
		for _, tok := range re.FindAllString(s, -1) {
			addr, _, _ := strings.Cut(tok, "%")
			if a, err := netip.ParseAddr(addr); err == nil && !m.kept(a) {
				out = append(out, "an address outside the kept prefixes")
				return out
			}
		}
	}
	return out
}

// JSON masks every string in a JSON document, keys included, and drops the
// keys named, wherever they are. Masking the decoded strings, not the
// encoded text, keeps the document valid and sees values next to escapes
// such as \n.
func (m *Masker) JSON(doc []byte, drop ...string) ([]byte, error) {
	dec := json.NewDecoder(bytes.NewReader(doc))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	var walk func(any) any
	walk = func(v any) any {
		switch t := v.(type) {
		case string:
			return m.String(t)
		case []any:
			for i := range t {
				t[i] = walk(t[i])
			}
			return t
		case map[string]any:
			out := make(map[string]any, len(t))
			for k, val := range t {
				if slices.Contains(drop, k) {
					continue
				}
				out[m.String(k)] = walk(val)
			}
			return out
		}
		return v
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(walk(v)); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}
