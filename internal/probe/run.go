package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
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
	// the target itself ("metadata"), or the host's own connect made for
	// comparison ("control", WR021); only for tcp specs with an IP Host.
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
		_, err := target.ParseTo(net.JoinHostPort(s.Host, "1")) // brackets an IPv6 literal
		return err
	case SpecTCP:
		switch s.Via {
		case "":
		case evidence.ViaMetadata, evidence.ViaControl:
			if _, err := netip.ParseAddr(s.Host); err != nil {
				return fmt.Errorf("a %s address must be an IP", s.Via)
			}
		default:
			return fmt.Errorf("unknown via %q", s.Via)
		}
		_, err := target.ParseTo(s.Subject())
		return err
	default:
		return fmt.Errorf("unknown spec kind %q", s.Kind)
	}
}

// Subject is what the spec's records are about: the name a dns spec looks
// up, "listeners", or a tcp spec's host:port, an IPv6 address in brackets.
func (s Spec) Subject() string {
	switch s.Kind {
	case SpecDNS:
		return s.Host
	case SpecListeners:
		return "listeners"
	}
	host := s.Host
	if a, err := netip.ParseAddr(host); err == nil && a.Is6() && !a.Is4In6() {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(int(s.Port))
}

// EvidenceKind is the kind of the records the spec produces.
func (s Spec) EvidenceKind() evidence.Kind {
	switch s.Kind {
	case SpecDNS:
		return evidence.KindDNS
	case SpecListeners:
		return evidence.KindListeners
	default:
		return evidence.KindTCP
	}
}

// Env is where the probes find the netns's configuration. Inside a probe
// container the defaults are the target container's own files, which Docker
// shares with the probe (ADR 0001).
type Env struct {
	ProcDir  string // "/proc/thread-self": the namespace of the thread that reads it
	Resolver *Resolver
	Limits   Limits // where connects may go, beyond the block list
	// Enter, when set, runs every socket the batch creates (its connects
	// and its DNS queries), and its listener read, inside another network
	// namespace (the netns executor). nil means the caller's own.
	Enter Enter
}

// Enter runs f on an OS thread inside the network namespace a batch is for:
// the netns executor's setns (INITIAL.md §4.7). A socket keeps the network
// namespace it was created in, so the probes create every socket, and read
// /proc/thread-self/net, inside f; using a socket afterwards needs no
// namespace. f must not start goroutines of its own that create sockets:
// they would run on other threads. Enter returns an error when the thread
// could not get there, and f has not run then.
type Enter func(f func()) error

// run runs f through e, or in place when e is nil.
func (e Enter) run(f func()) error {
	if e == nil {
		f()
		return nil
	}
	return e(f)
}

// DefaultEnv reads the standard paths. Listeners come from the calling
// thread's view of /proc (thread-self), which is where the probe runs;
// /proc/net would show the main thread's namespace.
func DefaultEnv() Env {
	return Env{
		ProcDir:  "/proc/thread-self",
		Resolver: &Resolver{HostsPath: "/etc/hosts", ResolvPath: "/etc/resolv.conf"},
	}
}

// Run executes a batch in the current network namespace and returns one or
// more evidence records per spec, in spec order. Independent checks run in
// parallel; a name that several specs need is looked up once. The records'
// Context is left for the caller to fill in.
func Run(ctx context.Context, env Env, specs []Spec) []evidence.Evidence {
	// Each connect to an approved private address uses one of the connects
	// the batch was given (INITIAL.md §10 Q15).
	env.Limits.allowance = newAllowance(env.Limits.Approved)
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
		return []evidence.Evidence{listeners(env)}
	case SpecDNS:
		l.resolve(ctx, s.Host)
		return nil
	default:
		return connect(ctx, env, l, s)
	}
}

func listeners(env Env) evidence.Evidence {
	start := time.Now()
	var socks []evidence.Socket
	var err error
	if eerr := env.Enter.run(func() { socks, err = ReadListeners(env.ProcDir) }); eerr != nil {
		err = eerr
	}
	ev := evidence.Evidence{
		Kind: evidence.KindListeners, Subject: "listeners", Duration: time.Since(start), ObservedAt: time.Now(),
		Source: env.ProcDir + "/net/tcp{,6} inside the network namespace",
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
func connect(ctx context.Context, env Env, l *lookups, s Spec) []evidence.Evidence {
	subject := s.Subject()
	if a, err := netip.ParseAddr(s.Host); err == nil {
		via := evidence.ViaLiteral
		if s.Via == evidence.ViaMetadata || s.Via == evidence.ViaControl {
			via = s.Via
		}
		return []evidence.Evidence{dial(ctx, env.Enter, subject, netip.AddrPortFrom(a, s.Port), via, env.Limits)}
	}
	lk := l.resolve(ctx, s.Host)
	p, _ := lk.ev.Data.(evidence.DNSProbe)
	if len(p.Answers) == 0 {
		// The lookup's own record says why; this one only says that no
		// connect was made, without claiming the name doesn't exist when
		// the lookup couldn't even run.
		why := &evidence.Error{Code: evidence.CodeNotFound, Message: s.Host + " did not resolve, so there was no address to connect to"}
		switch {
		case lk.ev.Status == evidence.StatusSkipped && lk.ev.Err != nil:
			// The policy held the lookup back: the connect shares its
			// reason, so the two make one gap.
			why = &evidence.Error{Code: lk.ev.Err.Code, Message: lk.ev.Err.Message}
		case !lk.ev.OK() && lk.ev.Err != nil:
			why = &evidence.Error{Code: lk.ev.Err.Code, Errno: lk.ev.Err.Errno,
				Message: "the lookup of " + s.Host + " could not be made (" + lk.ev.Err.Message + "), so there was no address to connect to"}
		}
		return []evidence.Evidence{{
			Kind: evidence.KindTCP, Subject: subject, Status: evidence.StatusSkipped, ObservedAt: time.Now(),
			Err: why, Source: "TCP connect, then close (no payload)",
		}}
	}
	addrs := p.Answers
	if len(addrs) > MaxAddrsPerName {
		addrs = addrs[:MaxAddrsPerName]
	}
	out := make([]evidence.Evidence, len(addrs))
	var wg sync.WaitGroup
	for i, a := range addrs {
		wg.Go(func() { out[i] = dial(ctx, env.Enter, subject, netip.AddrPortFrom(a, s.Port), p.Via, env.Limits) })
	}
	wg.Wait()
	return out
}

// invalid records a spec that was refused: a policy denial (a blocked
// address) is a skipped check, anything else an error.
func invalid(s Spec, err error) evidence.Evidence {
	status, code := evidence.StatusError, evidence.CodeInvalidArgument
	var te *target.Error
	if errors.As(err, &te) && te.Policy {
		status, code = evidence.StatusSkipped, evidence.CodePolicyDenied
	}
	return evidence.Evidence{
		Kind: s.EvidenceKind(), Subject: s.Subject(), Status: status, ObservedAt: time.Now(),
		Err: &evidence.Error{Code: code, Message: err.Error()},
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
	lk.once.Do(func() { lk.ev = l.env.Resolver.lookupWithin(ctx, l.env.Enter, name, l.env.Limits) })
	return lk
}

// get returns the finished lookup for name, if one ran.
func (l *lookups) get(name string) *lookup {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.done[name]
}
