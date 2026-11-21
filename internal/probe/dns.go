package probe

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"net"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/target"
)

// DNS timeouts (INITIAL.md §4.4): 2 s per query with 1 retry. A whole lookup,
// search domains included, gets LookupBudget.
const (
	QueryTimeout = 2 * time.Second
	QueryRetries = 1
	LookupBudget = 4 * time.Second
)

// Exchanger sends one DNS query to server ("127.0.0.11:53") over network
// ("udp" or "tcp").
type Exchanger func(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error)

// Resolver looks names up the way the source's libc would: /etc/hosts first,
// then the nameservers, search list and ndots from resolv.conf. It uses
// miekg/dns rather than net.Resolver so that the real rcode (NXDOMAIN,
// SERVFAIL, REFUSED) and timeouts stay distinguishable.
type Resolver struct {
	HostsPath  string        // "/etc/hosts"
	ResolvPath string        // "/etc/resolv.conf"
	Exchange   Exchanger     // nil means a real UDP/TCP client
	Timeout    time.Duration // per query; 0 means QueryTimeout
	Budget     time.Duration // per lookup; 0 means LookupBudget
	// Open opens HostsPath and ResolvPath; nil means os.Open. The netns
	// executor reads a container's own files with it, since entering a
	// network namespace leaves whyreach's file system as it is.
	Open func(ctx context.Context, path string) (io.ReadCloser, error)
}

func (r *Resolver) timeout() time.Duration { return cmp.Or(r.Timeout, QueryTimeout) }
func (r *Resolver) budget() time.Duration  { return cmp.Or(r.Budget, LookupBudget) }

func (r *Resolver) open(ctx context.Context, path string) (io.ReadCloser, error) {
	if r.Open != nil {
		return r.Open(ctx, path)
	}
	return os.Open(path) //nolint:gosec // G304: the resolver file paths are fixed by Env, never user input
}

// lookupWithin resolves name and records how. It never returns an error: a
// failed lookup is an observation. lim may hold back an outside name
// (Limits.CheckName); the nameservers pass the block list either way. Each
// query runs through enter (the batch's Env.Enter; nil means the caller's
// namespace), so that its socket lives in the namespace being probed. The
// hosts file answers first, as it does for the app; a name it doesn't
// answer and lim refuses is never sent.
func (r *Resolver) lookupWithin(ctx context.Context, enter Enter, name string, lim Limits) evidence.Evidence {
	start := time.Now()
	ev := evidence.Evidence{
		Kind:    evidence.KindDNS,
		Subject: name,
		Source:  "/etc/hosts, then the resolver in /etc/resolv.conf (miekg/dns)",
		Limitations: []string{
			"the app's libc (glibc or musl) may order IPv4 and IPv6 answers differently",
		},
	}
	p, notes, err := r.lookup(ctx, enter, name, lim)
	ev.Limitations = append(ev.Limitations, notes...)
	ev.Duration = time.Since(start)
	ev.ObservedAt = time.Now()
	ev.Data = p
	switch {
	case err != nil:
		ev.Status, ev.Err = Classify(err)
	case ctx.Err() != nil && len(p.Answers) == 0:
		ev.Status = evidence.StatusTimeout
		ev.Err = &evidence.Error{Code: evidence.CodeTimeout, Message: "the diagnosis deadline passed during the lookup"}
	default:
		ev.Status = evidence.StatusOK
	}
	return ev
}

// lookup resolves name: the hosts file first, then, if lim lets the name
// out, the nameservers that pass the block list. notes are limitations of
// the lookup, such as a nameserver it skipped.
func (r *Resolver) lookup(ctx context.Context, enter Enter, name string, lim Limits) (p evidence.DNSProbe, notes []string, err error) {
	p = evidence.DNSProbe{Name: name}
	addrs, err := r.hostsLookup(ctx, name)
	switch {
	case err == nil && len(addrs) > 0:
		p.Via, p.Answered, p.Answers = evidence.ViaHosts, name, addrs
		return p, nil, nil
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		// The app reads this file before any DNS: without it, an answer
		// from DNS would describe a lookup the app doesn't make.
		return p, nil, fmt.Errorf("read the hosts file: %w", err)
	}
	conf, err := r.readResolvConf(ctx)
	if err != nil {
		return p, nil, fmt.Errorf("read resolver config: %w", err)
	}
	p.Upstream = conf.extServers
	if len(conf.servers) == 0 {
		return p, nil, fmt.Errorf("%s lists no nameserver", r.ResolvPath)
	}
	// The container controls its resolv.conf: a nameserver on the block list
	// (link-local, cloud metadata) gets no query unless it is one of the
	// host's own resolvers (INITIAL.md §10 Q11, Q13). The nameservers come
	// before the name: a lookup that can't be made isn't worth asking the
	// user about.
	servers, next, notes, refusal := allowedServers(conf.servers, r.ResolvPath, lim)
	if refusal != "" {
		return p, notes, &Refused{Reason: refusal}
	}
	if reason, ok := lim.CheckName(name); !ok {
		return p, notes, &Refused{Reason: reason}
	}
	p.Server = servers[0].String()
	ctx, cancel := context.WithTimeout(ctx, r.budget())
	defer cancel()
	// Without an answer, Rcode describes the name as given (when it was
	// tried), not a search-domain variant: "api" did not resolve, rather
	// than "api.<search 1>".
	asGiven := strings.TrimSuffix(strings.ToLower(name), ".")
	givenRcode := ""
	var rcodeFrom, givenFrom netip.AddrPort // the nameserver whose reply set the rcode
	for i, cand := range conf.candidates(name) {
		res := r.resolveOne(ctx, enter, servers, cand.fqdn)
		if res.err != nil {
			// No query could be sent from the namespace: that is no answer
			// from the resolver, so it must not read as an rcode.
			return p, notes, res.err
		}
		for _, a := range res.attempts {
			a.Query = cand.label
			p.Attempts = append(p.Attempts, a)
		}
		if rc, ok := failover(res); ok && next != "" {
			// When the nameservers before it fail, the app asks the blocked
			// one, whose answer whyreach can't see (INITIAL.md §10 Q11).
			return p, notes, &Refused{Reason: fmt.Sprintf(
				"not looked up fully: the lookup of %s failed (%s), and when the nameservers before it fail, the app asks %s, which is on the probe block list (link-local and cloud-metadata addresses)",
				cand.label, rc, next)}
		}
		if i == 0 {
			p.Rcode, rcodeFrom = res.rcode, res.server
		}
		if cand.label == asGiven {
			givenRcode, givenFrom = res.rcode, res.server
		}
		if len(res.answers) > 0 {
			p.Via, p.Answered, p.Answers, p.Rcode = evidence.ViaDNS, cand.label, res.answers, res.rcode
			p.HostResolver = hostResolverOf(res.server, lim)
			return p, notes, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	if givenRcode != "" {
		p.Rcode, rcodeFrom = givenRcode, givenFrom
	}
	p.HostResolver = hostResolverOf(rcodeFrom, lim)
	return p, notes, nil
}

// hostResolverOf returns server when it is on the block list and was asked
// as one of the host's own resolvers, for the record (INITIAL.md §10 Q13);
// "" otherwise, and when no nameserver replied (an invalid server).
func hostResolverOf(server netip.AddrPort, lim Limits) string {
	if !server.IsValid() {
		return ""
	}
	if _, blocked := target.Blocked(server.Addr()); blocked && lim.HostResolver(server.Addr()) {
		return server.String()
	}
	return ""
}

// DockerResolvConf returns the resolv.conf Docker copies into containers on
// the default bridge, as Docker decides it: systemd-resolved's own
// (systemdPath) when hostPath lists only its stub, 127.0.0.53, which means
// nothing inside a container; otherwise hostPath.
func DockerResolvConf(hostPath, systemdPath string) string {
	f, err := os.Open(hostPath) //nolint:gosec // G304: the caller's fixed resolver file
	if err != nil {
		return hostPath
	}
	defer func() { _ = f.Close() }() // read-only
	if conf, err := parseResolvConf(f); err == nil && len(conf.servers) == 1 && conf.servers[0] == netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 53}), 53) {
		return systemdPath
	}
	return hostPath
}

// FirstNameserverBlocked reads a resolv.conf and reports its first
// nameserver when the probe block list keeps whyreach from querying it, so
// that no lookup through that file can be made (for whyreach doctor).
func FirstNameserverBlocked(path string) (string, bool, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the caller's fixed resolver file
	if err != nil {
		return "", false, err
	}
	defer func() { _ = f.Close() }() // read-only
	conf, err := parseResolvConf(f)
	if err != nil || len(conf.servers) == 0 {
		return "", false, err
	}
	first := conf.servers[0].Addr()
	_, blocked := target.Blocked(first)
	return first.String(), blocked, nil
}

// maxNameservers is how many nameservers the C libraries use: glibc's and
// musl's MAXNS. The app never asks a fourth.
const maxNameservers = 3

// allowedServers returns the nameservers (addr:53) a lookup may use, as
// the app's resolver would: of the first three, those before the first on
// the block list that isn't one of the host's own resolvers (lim). The C
// library asks them in order and moves on when one fails, so a blocked one
// is reached only after the ones before it fail: next names it, and a
// lookup whose servers fail stops there (failover). When the first is
// blocked, the app's own lookup would go there, so a lookup through the
// others would describe one the app doesn't make: refusal says so, and
// nothing is sent.
func allowedServers(servers []netip.AddrPort, path string, lim Limits) (ok []netip.AddrPort, next string, notes []string, refusal string) {
	if len(servers) > maxNameservers {
		servers = servers[:maxNameservers]
	}
	for i, ap := range servers {
		if reason, isBlocked := target.Blocked(ap.Addr()); isBlocked {
			if lim.HostResolver(ap.Addr()) {
				// The host's own resolver, which Docker copies into
				// default-bridge and host-network containers: DNS only, on
				// port 53 (INITIAL.md §10 Q13).
				notes = append(notes, fmt.Sprintf("nameserver %d of %s, %s, is on the probe block list (%s), but it is one of the host's own resolvers, so whyreach asks it for DNS only (INITIAL.md §10 Q13)", i+1, path, ap.Addr(), reason))
				ok = append(ok, ap)
				continue
			}
			if i == 0 {
				return nil, "", notes, fmt.Sprintf("not looked up: the first nameserver in %s, %s, which the app asks first, is on the probe block list (link-local and cloud-metadata addresses), which whyreach asks only when it is one of the host's own resolvers", path, ap.Addr())
			}
			notes = append(notes, fmt.Sprintf("nameserver %d of %s, %s, is on the probe block list (%s) and isn't one of the host's own resolvers: glibc asks it when the ones before it fail, and whyreach then makes no lookup; musl asks every nameserver at once, so a musl app may take its answer from there", i+1, path, ap.Addr(), reason))
			return ok, ap.Addr().String(), notes, ""
		}
		ok = append(ok, ap)
	}
	return ok, "", notes, ""
}

// maxResolverFile bounds a read of the host's resolver files.
const maxResolverFile = 1 << 20

// Nameservers reads the nameservers that resolver files list, as the C
// library reads them, without repeats; a file that can't be read is
// skipped. The policy reads the host's own with it (INITIAL.md §10 Q13).
func Nameservers(paths ...string) []netip.Addr {
	var out []netip.Addr
	for _, path := range paths {
		f, err := os.Open(path) //nolint:gosec // G304: the caller's fixed resolver files
		if err != nil {
			continue
		}
		conf, err := parseResolvConf(io.LimitReader(f, maxResolverFile))
		_ = f.Close() // read-only
		if err != nil {
			continue
		}
		for _, s := range conf.servers {
			if !slices.Contains(out, s.Addr()) {
				out = append(out, s.Addr())
			}
		}
	}
	return out
}

// failover reports a result after which glibc asks the next nameserver:
// neither query (A, AAAA) got a reply it accepts, only no reply, SERVFAIL,
// REFUSED or NOTIMP. One accepted reply, answered or not, ends the lookup
// at that server.
func failover(res resolveResult) (string, bool) {
	rc := ""
	for _, a := range res.attempts {
		switch a.Rcode {
		case evidence.RcodeTimeout, "ERROR", "SERVFAIL", "REFUSED", "NOTIMP":
			rc = cmp.Or(rc, a.Rcode)
		default:
			return "", false
		}
	}
	return rc, rc != ""
}

type candidate struct {
	fqdn  string // "api.corp.example."
	label string // "api" or "api.<search 1>": search domains are not recorded
}

// candidates lists the names a resolver tries, in order (resolv.conf(5)):
// the name as given first when it has at least ndots dots, the search
// domains otherwise; a trailing dot means the name is absolute.
func (c resolvConf) candidates(name string) []candidate {
	name = strings.ToLower(name)
	if strings.HasSuffix(name, ".") {
		return []candidate{{fqdn: name, label: strings.TrimSuffix(name, ".")}}
	}
	abs := candidate{fqdn: dns.Fqdn(name), label: name}
	var search []candidate
	for i, d := range c.search {
		search = append(search, candidate{
			fqdn:  dns.Fqdn(name + "." + d),
			label: name + ".<search " + strconv.Itoa(i+1) + ">",
		})
	}
	if strings.Count(name, ".") >= c.ndots {
		return append([]candidate{abs}, search...)
	}
	return append(search, abs)
}

type resolveResult struct {
	answers  []netip.Addr
	rcode    string
	server   netip.AddrPort // the nameserver whose reply was used; invalid when none came
	attempts []evidence.DNSAttempt
	err      error // the queries could not be sent at all (Env.Enter failed)
}

// resolveOne asks for A and AAAA in parallel, as getaddrinfo does.
func (r *Resolver) resolveOne(ctx context.Context, enter Enter, servers []netip.AddrPort, fqdn string) resolveResult {
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	results := make([]queryResult, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Go(func() { results[i] = r.query(ctx, enter, servers, fqdn, t) })
	}
	wg.Wait()
	var res resolveResult
	for i, q := range results {
		if q.err != nil {
			return resolveResult{err: q.err}
		}
		res.answers = append(res.answers, q.answers...)
		res.attempts = append(res.attempts, evidence.DNSAttempt{
			Type: dns.TypeToString[types[i]], Rcode: q.rcode, N: len(q.answers),
		})
	}
	res.rcode = combineRcodes(results[0], results[1])
	// The server of a reply with answers, else of any reply.
	for _, q := range results {
		if q.server.IsValid() && (len(q.answers) > 0 || !res.server.IsValid()) {
			res.server = q.server
		}
	}
	return res
}

type queryResult struct {
	answers []netip.Addr
	rcode   string
	server  netip.AddrPort // the nameserver that replied; invalid when none did
	err     error          // Env.Enter failed: nothing was sent
}

// query sends one question, retrying once on a timeout or an error (such as
// an ICMP refusal), on the next nameserver if there is one. A truncated UDP
// answer is retried over TCP. Each attempt runs through enter, so its
// sockets live in the namespace being probed.
func (r *Resolver) query(ctx context.Context, enter Enter, servers []netip.AddrPort, fqdn string, qtype uint16) queryResult {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, qtype)
	m.RecursionDesired = true
	exchange := r.Exchange
	if exchange == nil {
		exchange = exchangeNet
	}
	failure := evidence.RcodeTimeout
	for attempt := 0; attempt <= QueryRetries; attempt++ {
		if ctx.Err() != nil {
			break
		}
		server := servers[attempt%len(servers)]
		qctx, cancel := context.WithTimeout(ctx, r.timeout())
		var resp *dns.Msg
		var err error
		eerr := enter.run(func() {
			resp, err = exchange(qctx, m, server.String(), "udp")
			if err == nil && resp.Truncated {
				resp, err = exchange(qctx, m, server.String(), "tcp")
			}
		})
		cancel()
		if eerr != nil {
			return queryResult{err: eerr}
		}
		if err != nil {
			failure = evidence.RcodeTimeout
			if !isTimeout(err) {
				failure = "ERROR"
			}
			continue
		}
		return queryResult{answers: answers(resp), rcode: rcodeName(resp.Rcode), server: server}
	}
	return queryResult{rcode: failure}
}

func exchangeNet(ctx context.Context, m *dns.Msg, server, network string) (*dns.Msg, error) {
	c := &dns.Client{Net: network, Timeout: QueryTimeout}
	resp, _, err := c.ExchangeContext(ctx, m, server)
	return resp, err
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) ||
		(errors.As(err, &ne) && ne.Timeout())
}

func answers(m *dns.Msg) []netip.Addr {
	var out []netip.Addr
	for _, rr := range m.Answer {
		var ip net.IP
		switch v := rr.(type) {
		case *dns.A:
			ip = v.A
		case *dns.AAAA:
			ip = v.AAAA
		default:
			continue
		}
		if a, ok := netip.AddrFromSlice(ip); ok {
			out = append(out, a.Unmap())
		}
	}
	return out
}

func rcodeName(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return "RCODE" + strconv.Itoa(rc)
}

// combineRcodes summarises the A and AAAA results for one name: NOERROR when
// either has answers, otherwise the more telling failure.
func combineRcodes(a, b queryResult) string {
	if len(a.answers) > 0 || len(b.answers) > 0 {
		return dns.RcodeToString[dns.RcodeSuccess]
	}
	rank := func(rc string) int {
		switch rc {
		case evidence.RcodeTimeout:
			return 5
		case "SERVFAIL":
			return 4
		case "REFUSED":
			return 3
		case "ERROR":
			return 2
		case "NXDOMAIN":
			return 1
		default:
			return 0
		}
	}
	if rank(b.rcode) > rank(a.rcode) {
		return b.rcode
	}
	return a.rcode
}

// resolvConf is the part of resolv.conf(5) a lookup needs, plus Docker's
// "# ExtServers: [...]" comment, which names the upstream servers behind the
// embedded DNS at 127.0.0.11 (ADR 0001).
type resolvConf struct {
	servers    []netip.AddrPort // 127.0.0.11:53
	search     []string
	ndots      int
	extServers []string
}

func (r *Resolver) readResolvConf(ctx context.Context) (resolvConf, error) {
	f, err := r.open(ctx, r.ResolvPath)
	if err != nil {
		return resolvConf{}, err
	}
	defer func() { _ = f.Close() }() // read-only
	return parseResolvConf(f)
}

func parseResolvConf(r io.Reader) (resolvConf, error) {
	c := resolvConf{ndots: 1}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if rest, ok := strings.CutPrefix(line, "# ExtServers:"); ok {
			c.extServers = strings.Fields(strings.Trim(strings.TrimSpace(rest), "[]"))
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		f := strings.Fields(line)
		switch f[0] {
		case "nameserver":
			if len(f) > 1 {
				if a, ok := parseNameserver(f[1]); ok {
					c.servers = append(c.servers, netip.AddrPortFrom(a.Unmap(), 53))
				}
			}
		case "search", "domain":
			c.search = append([]string(nil), f[1:]...) // the last search/domain line wins
		case "options":
			for _, o := range f[1:] {
				if v, ok := strings.CutPrefix(o, "ndots:"); ok {
					if n, err := strconv.Atoi(v); err == nil && n >= 0 {
						c.ndots = min(n, 15)
					}
				}
			}
		}
	}
	return c, sc.Err()
}

// parseNameserver reads a nameserver line's address the way glibc and musl
// do, so that whyreach and the app agree on which server comes first: an
// IPv4 address in any inet_aton(3) form (0xa9fea9fe, 0251.0376.0251.0376
// and 169.254.43518 are all 169.254.169.254), or an IPv6 address, with an
// optional zone.
func parseNameserver(s string) (netip.Addr, bool) {
	if a, ok := inetAton(s); ok {
		return a, true
	}
	if a, err := netip.ParseAddr(s); err == nil && a.Is6() {
		return a, true
	}
	return netip.Addr{}, false
}

// inetAton parses IPv4 the way inet_aton(3) does: one to four parts, each
// decimal, octal (a leading 0) or hexadecimal (0x), the last filling the
// remaining bytes. Nothing may follow the address.
func inetAton(s string) (netip.Addr, bool) {
	parts := strings.Split(s, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		base, digits := 10, p
		switch {
		case len(p) > 1 && p[0] == '0' && (p[1] == 'x' || p[1] == 'X'):
			base, digits = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, digits = 8, p[1:]
		}
		if digits == "" {
			return netip.Addr{}, false
		}
		v, err := strconv.ParseUint(digits, base, 64)
		if err != nil {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	// The leading parts are a byte each; the last fills the rest.
	last := len(vals) - 1
	if vals[last] > uint64(1)<<(8*(4-last))-1 {
		return netip.Addr{}, false
	}
	var b [4]byte
	for i, v := range vals[:last] {
		if v > math.MaxUint8 {
			return netip.Addr{}, false
		}
		b[i] = uint8(v)
	}
	for i, v := 3, vals[last]; i >= last; i, v = i-1, v>>8 {
		b[i] = uint8(v & math.MaxUint8)
	}
	return netip.AddrFrom4(b), true
}

// hostsLookup returns the addresses /etc/hosts lists for name, in file order.
func (r *Resolver) hostsLookup(ctx context.Context, name string) ([]netip.Addr, error) {
	f, err := r.open(ctx, r.HostsPath)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }() // read-only
	return parseHosts(f, name)
}

func parseHosts(r io.Reader, name string) ([]netip.Addr, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	var out []netip.Addr
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line, _, _ := strings.Cut(sc.Text(), "#")
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		for _, h := range f[1:] {
			if strings.ToLower(h) == name {
				out = append(out, a.Unmap())
				break
			}
		}
	}
	return out, sc.Err()
}
