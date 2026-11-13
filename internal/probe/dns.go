package probe

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/SandstromPL/whyreach/internal/evidence"
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
}

func (r *Resolver) timeout() time.Duration { return cmp.Or(r.Timeout, QueryTimeout) }
func (r *Resolver) budget() time.Duration  { return cmp.Or(r.Budget, LookupBudget) }

// Lookup resolves name and records how. It never returns an error: a failed
// lookup is an observation.
func (r *Resolver) Lookup(ctx context.Context, name string) evidence.Evidence {
	start := time.Now()
	ev := evidence.Evidence{
		Kind:    evidence.KindDNS,
		Subject: name,
		Source:  "/etc/hosts, then the resolver in /etc/resolv.conf (miekg/dns)",
		Limitations: []string{
			"the app's libc (glibc or musl) may order IPv4 and IPv6 answers differently",
		},
	}
	p, err := r.lookup(ctx, name)
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

func (r *Resolver) lookup(ctx context.Context, name string) (evidence.DNSProbe, error) {
	p := evidence.DNSProbe{Name: name}
	if addrs, err := hostsLookup(r.HostsPath, name); err == nil && len(addrs) > 0 {
		p.Via, p.Answered, p.Answers = evidence.ViaHosts, name, addrs
		return p, nil
	}
	conf, err := readResolvConf(r.ResolvPath)
	if err != nil {
		return p, fmt.Errorf("read resolver config: %w", err)
	}
	p.Upstream = conf.extServers
	if len(conf.servers) == 0 {
		return p, fmt.Errorf("%s lists no nameserver", r.ResolvPath)
	}
	p.Server = conf.servers[0]
	ctx, cancel := context.WithTimeout(ctx, r.budget())
	defer cancel()
	// Without an answer, Rcode describes the name as given (when it was
	// tried), not a search-domain variant: "api" did not resolve, rather
	// than "api.<search 1>".
	asGiven := strings.TrimSuffix(strings.ToLower(name), ".")
	givenRcode := ""
	for i, cand := range conf.candidates(name) {
		res := r.resolveOne(ctx, conf.servers, cand.fqdn)
		for _, a := range res.attempts {
			a.Query = cand.label
			p.Attempts = append(p.Attempts, a)
		}
		if i == 0 {
			p.Rcode = res.rcode
		}
		if cand.label == asGiven {
			givenRcode = res.rcode
		}
		if len(res.answers) > 0 {
			p.Via, p.Answered, p.Answers, p.Rcode = evidence.ViaDNS, cand.label, res.answers, res.rcode
			return p, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	if givenRcode != "" {
		p.Rcode = givenRcode
	}
	return p, nil
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
	attempts []evidence.DNSAttempt
}

// resolveOne asks for A and AAAA in parallel, as getaddrinfo does.
func (r *Resolver) resolveOne(ctx context.Context, servers []string, fqdn string) resolveResult {
	types := []uint16{dns.TypeA, dns.TypeAAAA}
	results := make([]queryResult, len(types))
	var wg sync.WaitGroup
	for i, t := range types {
		wg.Go(func() { results[i] = r.query(ctx, servers, fqdn, t) })
	}
	wg.Wait()
	var res resolveResult
	for i, q := range results {
		res.answers = append(res.answers, q.answers...)
		res.attempts = append(res.attempts, evidence.DNSAttempt{
			Type: dns.TypeToString[types[i]], Rcode: q.rcode, N: len(q.answers),
		})
	}
	res.rcode = combineRcodes(results[0], results[1])
	return res
}

type queryResult struct {
	answers []netip.Addr
	rcode   string
}

// query sends one question, retrying once on a timeout or an error (such as
// an ICMP refusal), on the next nameserver if there is one. A truncated UDP
// answer is retried over TCP.
func (r *Resolver) query(ctx context.Context, servers []string, fqdn string, qtype uint16) queryResult {
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
		resp, err := exchange(qctx, m, server, "udp")
		if err == nil && resp.Truncated {
			resp, err = exchange(qctx, m, server, "tcp")
		}
		cancel()
		if err != nil {
			failure = evidence.RcodeTimeout
			if !isTimeout(err) {
				failure = "ERROR"
			}
			continue
		}
		return queryResult{answers: answers(resp), rcode: rcodeName(resp.Rcode)}
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
	servers    []string // "127.0.0.11:53"
	search     []string
	ndots      int
	extServers []string
}

func readResolvConf(path string) (resolvConf, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the resolver config path is fixed by Env, never user input

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
				if a, err := netip.ParseAddr(f[1]); err == nil {
					c.servers = append(c.servers, netip.AddrPortFrom(a.Unmap(), 53).String())
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

// hostsLookup returns the addresses /etc/hosts lists for name, in file order.
func hostsLookup(path, name string) ([]netip.Addr, error) {
	f, err := os.Open(path) //nolint:gosec // G304: the hosts path is fixed by Env, never user input

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
