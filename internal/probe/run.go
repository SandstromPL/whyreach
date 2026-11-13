package probe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Spec kinds.
const (
	SpecDNS       = "dns"       // look Host up
	SpecTCP       = "tcp"       // connect to Host:Port (resolving Host first if it is a name)
	SpecListeners = "listeners" // read this netns's listening sockets
)

// Limits on one batch, so a spec can't turn a probe into a scanner.
const (
	MaxSpecs        = 8
	MaxAddrsPerName = 4 // a name resolves to at most 4 addresses (INITIAL.md §4.9)
)

// Spec is one check. The probe container receives a batch of them as JSON.
type Spec struct {
	Kind string `json:"kind"`           // dns, tcp or listeners
	Host string `json:"host,omitempty"` // a name or an IP address
	Port uint16 `json:"port,omitempty"` // tcp only
	// Via marks an address that came from Docker metadata rather than from
	// the target itself ("metadata"); only for tcp specs with an IP Host.
	Via string `json:"via,omitempty"`
}

// Validate rejects anything but one well-formed check.
func (s Spec) Validate() error {
	switch s.Kind {
	case SpecListeners:
		if s.Host != "" || s.Port != 0 {
			return errors.New("a listeners spec takes no host or port")
		}
		return nil
	case SpecDNS:
		if s.Port != 0 {
			return errors.New("a dns spec takes no port")
		}
		_, err := target.ParseTo(s.Host + ":1")
		return err
	case SpecTCP:
		if s.Via != "" && s.Via != evidence.ViaMetadata {
			return fmt.Errorf("unknown via %q", s.Via)
		}
		if s.Via == evidence.ViaMetadata {
			if _, err := netip.ParseAddr(s.Host); err != nil {
				return errors.New("a metadata address must be an IP")
			}
		}
		_, err := target.ParseTo(s.subject())
		return err
	default:
		return fmt.Errorf("unknown spec kind %q", s.Kind)
	}
}

// subject is the spec's target as host:port.
func (s Spec) subject() string {
	host := s.Host
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() && !a.Is4In6() {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(s.Port))
}

// Env is where the probes find the netns's configuration. Inside a probe
// container the defaults are the target container's own files, which Docker
// shares with the probe (ADR 0001).
type Env struct {
	ProcDir  string // "/proc"
	Resolver *Resolver
}

// DefaultEnv reads the standard paths.
func DefaultEnv() Env {
	return Env{
		ProcDir:  "/proc",
		Resolver: &Resolver{HostsPath: "/etc/hosts", ResolvPath: "/etc/resolv.conf"},
	}
}

// Run executes a batch in the current network namespace and returns one or
// more evidence records per spec, in spec order. Independent checks run in
// parallel; a name that several specs need is looked up once. The records'
// Context is left for the caller to fill in.
func Run(ctx context.Context, env Env, specs []Spec) []evidence.Evidence {
	l := &lookups{env: env, done: map[string]*lookup{}}
	results := make([][]evidence.Evidence, len(specs))
	var wg sync.WaitGroup
	for i, s := range specs {
		wg.Go(func() { results[i] = runOne(ctx, env, l, s) })
	}
	wg.Wait()

	var out []evidence.Evidence
	emitted := map[string]bool{}
	for i, s := range specs {
		// Every lookup a spec triggered is reported once, before the
		// connects that used it.
		if s.Kind == SpecDNS || s.Kind == SpecTCP {
			if lk := l.get(s.Host); lk != nil && !emitted[s.Host] {
				emitted[s.Host] = true
				out = append(out, lk.ev)
			}
		}
		out = append(out, results[i]...)
	}
	return out
}

func runOne(ctx context.Context, env Env, l *lookups, s Spec) []evidence.Evidence {
	if err := s.Validate(); err != nil {
		return []evidence.Evidence{invalid(s, err)}
	}
	switch s.Kind {
	case SpecListeners:
		return []evidence.Evidence{listeners(env.ProcDir)}
	case SpecDNS:
		l.resolve(ctx, s.Host)
		return nil
	default:
		return connect(ctx, l, s)
	}
}

func listeners(procDir string) evidence.Evidence {
	start := time.Now()
	socks, err := ReadListeners(procDir)
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Subject: "listeners", Duration: time.Since(start), ObservedAt: time.Now(),
		Source: procDir + "/net/tcp{,6} inside the network namespace",
	}
	if err != nil {
		ev.Status, ev.Err = Classify(err)
		return ev
	}
	ev.Status = evidence.StatusOK
	ev.Data = evidence.Listeners{Sockets: socks}
	return ev
}

// connect dials every address the spec's host stands for, in parallel.
func connect(ctx context.Context, l *lookups, s Spec) []evidence.Evidence {
	subject := s.subject()
	if a, err := netip.ParseAddr(s.Host); err == nil {
		via := evidence.ViaLiteral
		if s.Via == evidence.ViaMetadata {
			via = evidence.ViaMetadata
		}
		return []evidence.Evidence{Dial(ctx, subject, netip.AddrPortFrom(a, s.Port), via)}
	}
	lk := l.resolve(ctx, s.Host)
	p, _ := lk.ev.Data.(evidence.DNSProbe)
	if len(p.Answers) == 0 {
		return []evidence.Evidence{{
			Kind: evidence.KindTCP, Subject: subject, Status: evidence.StatusSkipped, ObservedAt: time.Now(),
			Err:    &evidence.Error{Code: evidence.CodeNotFound, Message: s.Host + " did not resolve, so there was no address to connect to"},
			Source: "TCP connect, then close (no payload)",
		}}
	}
	addrs := p.Answers
	if len(addrs) > MaxAddrsPerName {
		addrs = addrs[:MaxAddrsPerName]
	}
	out := make([]evidence.Evidence, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() { out[i] = Dial(ctx, subject, netip.AddrPortFrom(a, s.Port), p.Via) })
	}
	wg.Wait()
	return out
}

func invalid(s Spec, err error) evidence.Evidence {
	kind := evidence.KindTCP
	switch s.Kind {
	case SpecDNS:
		kind = evidence.KindDNS
	case SpecListeners:
		kind = evidence.KindListeners
	}
	return evidence.Evidence{
		Kind: kind, Subject: s.subject(), Status: evidence.StatusError, ObservedAt: time.Now(),
		Err: &evidence.Error{Code: evidence.CodeInvalidArgument, Message: err.Error()},
	}
}

// lookups shares one DNS lookup per name across the specs of a batch.
type lookups struct {
	env  Env
	mu   sync.Mutex
	done map[string]*lookup
}

type lookup struct {
	once sync.Once
	ev   evidence.Evidence
}

func (l *lookups) entry(name string) *lookup {
	l.mu.Lock()
	defer l.mu.Unlock()
	lk, ok := l.done[name]
	if !ok {
		lk = &lookup{}
		l.done[name] = lk
	}
	return lk
}

func (l *lookups) resolve(ctx context.Context, name string) *lookup {
	lk := l.entry(name)
	lk.once.Do(func() { lk.ev = l.env.Resolver.Lookup(ctx, name) })
	return lk
}

// get returns the finished lookup for name, if one ran.
func (l *lookups) get(name string) *lookup {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.done[name]
}
