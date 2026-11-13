package report

import (
	"cmp"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
)

// Redactor replaces identifying values in a report with stable pseudonyms
// (INITIAL.md §4.12): public addresses become ip-…, host names host-…,
// container and network IDs ctr-…, and the user's home directory ~. A
// pseudonym is an HMAC of the value under a random per-report key, so the
// same value maps to the same pseudonym throughout one report, and reports
// can't be correlated with each other. Private addresses are kept unless
// RedactPrivate is set: they rarely identify anyone and the diagnosis needs
// them.
type Redactor struct {
	RedactPrivate bool
	Home          string // the user's home directory, replaced by ~

	key    []byte
	tokens []token
	counts map[string]int
}

type token struct {
	value, repl, class string
}

// Classes of redacted values, as counted in the summary.
const (
	ClassIP        = "ips"
	ClassHost      = "hostnames"
	ClassContainer = "container_ids"
)

var (
	cgnat        = netip.MustParsePrefix("100.64.0.0/10")
	ipInText     = regexp.MustCompile(`[0-9A-Fa-f:.]*[0-9A-Fa-f]`)
	searchMarker = regexp.MustCompile(`\.<search [0-9]+>`)
)

// NewRedactor returns a redactor with a fresh random key.
func NewRedactor(redactPrivate bool, home string) *Redactor {
	key := make([]byte, 32)
	_, _ = rand.Read(key) // crypto/rand.Read never fails on supported platforms
	return &Redactor{RedactPrivate: redactPrivate, Home: home, key: key, counts: map[string]int{}}
}

// Learn collects the identifying values in a diagnosis from its structured
// fields, and every address in any of its strings (error messages and
// explanations included); Apply then replaces them wherever they appear.
func (r *Redactor) Learn(d *engine.Diagnosis) {
	r.scanAddresses(d)
	q := d.Question
	if q.To.Class == evidence.TargetName {
		r.host(q.To.Host)
	}
	r.ip(q.To.Addr)
	if q.From.ContainerID != "" {
		r.container(q.From.ContainerID)
	}
	for _, e := range d.Evidence {
		if e.Context.Container != "" {
			r.container(e.Context.Container)
		}
		switch v := e.Data.(type) {
		case evidence.Container:
			r.container(v.ID)
			if host, _, ok := strings.Cut(v.Image, "/"); ok && strings.ContainsAny(host, ".:") {
				r.host(strings.Split(host, ":")[0]) // a registry host
				r.ipText(host)
			}
			for _, a := range v.Networks {
				r.container(a.NetworkID)
				r.ip(a.IPv4)
				r.ip(a.IPv6)
				r.ip(a.Gateway)
				for _, n := range a.Names {
					r.host(n) // aliases can be DNS names
				}
			}
			for _, l := range v.Links {
				for _, part := range strings.FieldsFunc(l, func(c rune) bool { return c == ':' || c == '/' }) {
					r.host(part)
				}
			}
			for _, h := range v.ExtraHosts {
				name, value, ok := strings.Cut(h, "=")
				if !ok {
					name, value, _ = strings.Cut(h, ":")
				}
				r.host(name)
				r.ipText(value)
			}
			for _, s := range v.DNS {
				r.ipText(s)
			}
			if owner := v.NetnsOwner(); owner != "" {
				r.container(owner)
			}
			for _, p := range v.Ports {
				r.ipText(p.HostIP)
			}
		case evidence.DNSProbe:
			r.host(v.Name)
			r.host(searchMarker.ReplaceAllString(v.Answered, ""))
			r.ipText(v.Server)
			for _, u := range v.Upstream {
				r.ipText(u)
			}
			for _, a := range v.Answers {
				r.ip(a)
			}
		case evidence.TCPProbe:
			r.ip(v.Addr.Addr())
			if host, _, ok := strings.Cut(v.Target, ":"); ok {
				r.host(host)
			}
		case evidence.Listeners:
			for _, s := range v.Sockets {
				r.ip(s.Local.Addr())
			}
		case evidence.HostAddrs:
			for _, i := range v.Interfaces {
				for _, p := range i.Addrs {
					r.ip(p.Addr())
				}
				// A user-defined network's bridge is br-<its short ID>.
				if id, ok := strings.CutPrefix(i.Name, "br-"); ok && len(id) == 12 && strings.Trim(id, "0123456789abcdef") == "" {
					r.addRepl(i.Name, ClassContainer, "br-"+r.mac(id))
				}
			}
		}
	}
}

// scanAddresses learns every address that appears in any string of the
// diagnosis, so one that only an error message or an explanation mentions
// is redacted too.
func (r *Redactor) scanAddresses(d *engine.Diagnosis) {
	b, err := json.Marshal(d)
	if err != nil {
		return
	}
	var tree any
	if json.Unmarshal(b, &tree) != nil {
		return
	}
	walk(tree, func(s string) string {
		r.ipText(s)
		return s
	})
}

// host learns a DNS name. Names without a dot (container, service and
// network names) are kept: the report can't be read without them.
func (r *Redactor) host(name string) {
	name = strings.TrimSuffix(asciiLower(strings.TrimSpace(name)), ".") // fold as Apply does
	if !strings.Contains(name, ".") || strings.Contains(name, "<") {
		return
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return
	}
	if name == evidence.HostDockerInternal {
		return // Docker's own name for the host
	}
	r.add(name, ClassHost, "host-")
}

// ip learns an address and returns its pseudonym, "" when it is kept.
func (r *Redactor) ip(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	a = a.Unmap()
	if a.IsLoopback() || a.IsUnspecified() {
		return ""
	}
	private := a.IsPrivate() || a.IsLinkLocalUnicast() || cgnat.Contains(a)
	if private && !r.RedactPrivate {
		return ""
	}
	repl := "ip-" + r.mac(a.String())
	r.addRepl(a.String(), ClassIP, repl)
	return repl
}

// ipText learns the addresses inside a string such as "host(127.0.0.53)",
// and each as spelled there too: Docker keeps extra_hosts as written, so
// 2001:0db8::0001 must be replaced where it appears, not only as 2001:db8::1.
func (r *Redactor) ipText(s string) {
	for _, m := range ipInText.FindAllString(s, -1) {
		repl := ""
		if a, err := netip.ParseAddr(m); err == nil {
			repl = r.ip(a)
		} else if ap, err := netip.ParseAddrPort(m); err == nil {
			repl = r.ip(ap.Addr())
			m = ap.Addr().String()
		}
		if raw := asciiLower(m); repl != "" && strings.Contains(raw, ":") {
			r.addRepl(raw, ClassIP, repl)
		}
	}
}

// container learns a container or network ID, and its 12-character short
// form, which maps to the same pseudonym (a network's bridge, br-<short
// ID>, gets the same suffix).
func (r *Redactor) container(id string) {
	full := asciiLower(id)
	if len(full) < 12 || strings.Trim(full, "0123456789abcdef") != "" {
		return // a name, not an ID
	}
	repl := "ctr-" + r.mac(full[:12])
	r.addRepl(full, ClassContainer, repl)
	r.addRepl(full[:12], ClassContainer, repl)
}

func (r *Redactor) add(value, class, prefix string) {
	r.addRepl(value, class, prefix+r.mac(value))
}

func (r *Redactor) addRepl(value, class, repl string) {
	for _, t := range r.tokens {
		if t.value == value {
			return
		}
	}
	r.tokens = append(r.tokens, token{value: value, repl: repl, class: class})
}

func (r *Redactor) mac(v string) string {
	m := hmac.New(sha256.New, r.key)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

// Apply replaces every learned value in s, longest first, matching whole
// tokens only (so 10.0.0.1 never matches inside 110.0.0.12).
func (r *Redactor) Apply(s string) string {
	slices.SortFunc(r.tokens, func(a, b token) int {
		return cmp.Or(cmp.Compare(len(b.value), len(a.value)), strings.Compare(a.value, b.value))
	})
	for _, t := range r.tokens {
		s = replaceWhole(s, t.value, t.repl, func(n int) { r.counts[t.class] += n })
	}
	if r.Home != "" && len(r.Home) > 1 {
		s = strings.ReplaceAll(s, r.Home, "~")
	}
	return s
}

// Counts reports how many replacements of each class Apply made.
func (r *Redactor) Counts() map[string]int {
	out := map[string]int{}
	for k, v := range r.counts {
		out[k] = v
	}
	return out
}

// replaceWhole replaces occurrences of tok that are not part of a longer
// name, address or ID, matching ASCII letters case-insensitively. Learned
// tokens are lowercase ASCII; folding only ASCII keeps every byte offset of
// s, which a full Unicode lowercase would not (İ grows by a byte).
func replaceWhole(s, tok, repl string, count func(int)) string {
	lower := asciiLower(s)
	colon := strings.Contains(tok, ":") // an IPv6 address: a colon continues it
	var b strings.Builder
	n, i := 0, 0
	for {
		j := strings.Index(lower[i:], tok)
		if j < 0 {
			break
		}
		start, end := i+j, i+j+len(tok)
		if continues(s, start-1, -1, colon) || continues(s, end, +1, colon) {
			b.WriteString(s[i:end])
			i = end
			continue
		}
		b.WriteString(s[i:start])
		b.WriteString(repl)
		i = end
		n++
	}
	if n == 0 {
		return s
	}
	b.WriteString(s[i:])
	count(n)
	return b.String()
}

// continues reports whether the byte at s[at] (looking in direction dir)
// extends the token into a longer name, address or ID. A dot does only when
// more of a name follows it: a full stop ends a sentence.
func continues(s string, at, dir int, colon bool) bool {
	if at < 0 || at >= len(s) {
		return false
	}
	c := s[at]
	switch {
	case alnum(c), c == '-', c == '_':
		return true
	case c == ':':
		return colon
	case c == '.':
		next := at + dir
		return next >= 0 && next < len(s) && alnum(s[next])
	default:
		return false
	}
}

func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func alnum(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z'
}
