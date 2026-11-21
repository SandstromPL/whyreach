// Package policy guards everything whyreach does for a caller (INITIAL.md
// §4.9). It parses and validates arguments, decides the permission tiers,
// keeps probes inside the target policy and the rate limit, and writes the
// audit log. The CLI and the MCP server both go through it, and nothing
// else drives the engine.
//
// Permissions come from the user's config file, or from the user's answer
// to an MCP elicitation (GrantProbeContainers). Tool arguments can only
// narrow what whyreach does: no argument turns a tier on.
package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Tool names, as the MCP server exposes them and the audit log records them.
const (
	ToolDiagnose = "diagnose_connection"
	ToolInspect  = "inspect_environment"
	ToolProbe    = "run_probe"
	ToolSave     = "save_report"
	ToolConsent  = "probe_containers_consent" // the user's answer to an elicitation
	// ToolNameConsent records the user's answer to a request to look up an
	// outside name (INITIAL.md §10 Q11).
	ToolNameConsent = "name_lookup_consent"
	// ToolAddrConsent records the user's answer to a request to connect to
	// a private address outside Docker's networks (INITIAL.md §10 Q15).
	ToolAddrConsent = "connect_consent"
)

// ApprovalBudget is how many lookups of a name, or connects to an address
// and port, one approval covers in a session (INITIAL.md §10 Q14, Q15):
// past them, whyreach asks again, within the session's question limit.
const ApprovalBudget = probe.ApprovalBudget

// Clients that go through the policy.
const (
	ClientCLI = "cli"
	ClientMCP = "mcp"
)

// Settings are the permissions and limits from the user's config file.
type Settings struct {
	Docker          bool     // tier 2a: read Docker metadata
	ProbeContainers bool     // tier 2b: ephemeral probe containers
	NetnsOff        bool     // [permissions] netns = false: tier 3 stays off, even as root
	Allow           []string // [probe] allow: classes and CIDRs; empty means no allowlist
	RatePerMinute   int      // [probe] rate_per_minute
	// Names are the domains whose names MCP clients may have looked up
	// without asking the user ([probe] names), each covering its subdomains.
	Names      []string
	ConfigPath string // named in advice
}

// SettingsFrom reads the settings out of a loaded config.
func SettingsFrom(c config.Config, path string) Settings {
	return Settings{
		Docker: c.Permissions.Docker, ProbeContainers: c.Permissions.ProbeContainers, NetnsOff: !c.Permissions.Netns,
		Allow: c.Probe.Allow, RatePerMinute: c.Probe.RatePerMinute, Names: c.Probe.Names, ConfigPath: path,
	}
}

// Docker is the metadata client: the engine's, plus nothing more.
type Docker = engine.Docker

// Deps are what the policy needs to build its engine.
type Deps struct {
	Settings   Settings
	Docker     Docker // nil when Docker access is off or unavailable (DockerErr says why)
	DockerErr  error
	Listeners  engine.Listeners
	Interfaces func() (evidence.HostAddrs, error)
	Routes     func(netip.Addr) (evidence.HostRoute, error) // how the host routes an address (WR013)
	Host       executor.Executor                            // runs probes in the host's network namespace
	Self       string                                       // the ID of the Docker container whyreach runs in, if any
	// Platform is where whyreach runs (platform.Detect): the engine
	// classifies the platform from it and the daemon's answer (INITIAL.md
	// §3.7). The zero value means natively, outside WSL and containers.
	Platform platform.Info
	// HostResolvers reads the host's own resolvers, which a probe may ask
	// even on the block list, for DNS only (INITIAL.md §10 Q13); nil when
	// whyreach can't see the host's resolver files.
	HostResolvers func() []netip.Addr
	// NewProbe builds the probe-container executor the first time tier 2b
	// is used; nil when it can't exist (no Docker API).
	NewProbe func() (executor.Executor, error)
	// Netns runs container checks by entering the containers' network
	// namespaces (tier 3). The caller sets it only when whyreach has the
	// privilege (root) and runs on the host itself; nil means it doesn't.
	Netns    executor.Executor
	Audit    *Audit // nil: no audit log
	Client   string // ClientCLI or ClientMCP
	Deadline time.Duration
	Logger   *slog.Logger
	Now      func() time.Time // the rate limiter's clock; nil means time.Now
}

// Policy is the only way into the engine.
type Policy struct {
	d       Deps
	static  []netip.Prefix // the allowlist's fixed part
	docker  bool           // the allowlist includes Docker's subnets
	limiter *limiter
	engine  *engine.Engine
	granted atomic.Bool // tier 2b approved for this session

	rfc1918  bool           // the allowlist has the rfc1918 class
	explicit []netip.Prefix // the allowlist's CIDRs and addresses

	namesMu  sync.Mutex
	approved budget[string]         // outside names the user approved: lookups left
	addrs    budget[netip.AddrPort] // private addresses and ports the user approved: connects left

	probeOnce sync.Once
	probeEx   executor.Executor
	probeErr  error
}

// New builds a policy and the engine behind it.
func New(d Deps) (*Policy, error) {
	if d.Logger == nil {
		d.Logger = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Settings.RatePerMinute <= 0 {
		d.Settings.RatePerMinute = config.DefaultRate
	}
	if d.Client == "" {
		d.Client = ClientCLI
	}
	if d.Platform.OS == "" {
		d.Platform.OS, d.Platform.Arch = runtime.GOOS, runtime.GOARCH
	}
	if !d.Settings.Docker {
		d.Docker, d.DockerErr = nil, nil
	}
	if d.Docker == nil || d.Settings.NetnsOff {
		d.Netns = nil // it finds containers through the Docker API; and the user can turn it off
	}
	p := &Policy{d: d, limiter: newLimiter(d.Settings.RatePerMinute, d.Now), approved: budget[string]{}, addrs: budget[netip.AddrPort]{}}
	for _, entry := range d.Settings.Allow {
		prefixes, err := config.AllowPrefixes(entry)
		if err != nil {
			return nil, &Error{Code: evidence.CodeInvalidArgument, Message: "probe allowlist: " + err.Error()}
		}
		switch strings.ToLower(strings.TrimSpace(entry)) {
		case config.AllowDocker:
			p.docker = true
		case config.AllowRFC1918:
			p.rfc1918 = true
		case config.AllowLoopback:
		default:
			p.explicit = append(p.explicit, prefixes...)
		}
		p.static = append(p.static, prefixes...)
	}
	host := d.Host
	if host == nil {
		host = executor.NewHost()
	}
	// The netns executor obeys the same allowlist, block list and rate
	// limit as the others; it needs no tier 2b, since it writes nothing to
	// Docker. When it can't enter a namespace, a probe container runs the
	// checks instead, if the user allows them.
	var netns executor.Executor
	if d.Netns != nil {
		netns = &guard{p: p, name: evidence.ExecutorNetns, inner: func() (executor.Executor, error) { return d.Netns, nil }, fallback: p.probeExecutor}
	}
	// A host executor that can't run anything (whyreach's image without
	// --network host) sends nothing: it takes no rate tokens, needs no name
	// checks, and the audit has nothing to count.
	var hostEx executor.Executor = &guard{p: p, name: evidence.ExecutorHost, inner: func() (executor.Executor, error) { return host, nil }}
	if u, ok := host.(executor.Unsupported); ok {
		hostEx = u
	}
	p.engine = engine.New(engine.Deps{
		Docker:     d.Docker,
		DockerErr:  d.DockerErr,
		Host:       hostEx,
		Probe:      &guard{p: p, name: evidence.ExecutorProbeContainer, tier2b: true, inner: p.probeExecutor},
		Netns:      netns,
		Listeners:  d.Listeners,
		Interfaces: d.Interfaces,
		Routes:     d.Routes,
		ConfigPath: d.Settings.ConfigPath,
		Self:       d.Self,
		Platform:   d.Platform,
		Deadline:   d.Deadline,
		Logger:     d.Logger,
	})
	return p, nil
}

// ProbeContainers reports whether tier 2b is in effect: on in the config,
// or approved by the user for this session.
func (p *Policy) ProbeContainers() bool {
	return p.d.Docker != nil && (p.d.Settings.ProbeContainers || p.granted.Load())
}

// ProbeContainersConfigured reports tier 2b turned on in the config file.
func (p *Policy) ProbeContainersConfigured() bool {
	return p.d.Docker != nil && p.d.Settings.ProbeContainers
}

// CanUseProbeContainers reports whether tier 2b could be turned on at all:
// the Docker API is there.
func (p *Policy) CanUseProbeContainers() bool { return p.d.Docker != nil && p.d.NewProbe != nil }

// RecordConsent records the user's answer to a request for probe
// containers; an approval turns tier 2b on for the rest of the session. Only
// the MCP server calls it, with what the user chose in the client's own
// dialog: never with anything the model sent.
func (p *Policy) RecordConsent(approved bool, how string) {
	if approved {
		p.granted.Store(true)
	}
	p.auditAnswer(ToolConsent, map[string]string{"answer": how}, approved)
}

// auditAnswer records the user's answer to a question in the audit log.
func (p *Policy) auditAnswer(tool string, args map[string]string, approved bool) {
	status := "declined"
	if approved {
		status = "approved"
	}
	p.audit(Entry{Tool: tool, Args: args, Status: status}, time.Now(), nil)
}

// budget holds the uses left of the user's approvals, by name or by address
// and port (INITIAL.md §10 Q14, Q15). Policy.namesMu guards it.
type budget[K comparable] map[K]int

// grant gives k a fresh approval: ApprovalBudget uses.
func (b budget[K]) grant(k K) { b[k] = ApprovalBudget }

// left is how many uses k's approval has left.
func (b budget[K]) left(k K) int { return b[k] }

// take uses one of k's, if any is left.
func (b budget[K]) take(k K) bool {
	if b[k] <= 0 {
		return false
	}
	b[k]--
	return true
}

// refund gives k back one use, never past ApprovalBudget.
func (b budget[K]) refund(k K) { b[k] = min(b[k]+1, ApprovalBudget) }

// NamesNeedApproval reports whether lookups of outside names are held back
// until the user approves them (INITIAL.md §10 Q11): for MCP clients. The
// CLI's user types the names, so it looks up any.
func (p *Policy) NamesNeedApproval() bool { return p.d.Client == ClientMCP }

// NameAllowed reports whether an outside name may be looked up without
// asking: [probe] names covers it, or the user approved it this session
// and the approval has lookups left (INITIAL.md §10 Q14).
func (p *Policy) NameAllowed(name string) bool {
	if target.CoveredBy(name, p.d.Settings.Names) {
		return true
	}
	p.namesMu.Lock()
	defer p.namesMu.Unlock()
	return p.approved.left(target.NormalizeName(name)) > 0
}

// RecordNameConsent records the user's answer to a request to look up one
// outside name; an approval lets that exact name, and no other, be looked
// up ApprovalBudget times in the session. Only the MCP server calls it,
// with what the user chose in the client's own dialog about the name the
// server asked about: never with anything the model sent.
func (p *Policy) RecordNameConsent(name string, approved bool, how string) {
	n := target.NormalizeName(name)
	if approved {
		p.namesMu.Lock()
		p.approved.grant(n)
		p.namesMu.Unlock()
	}
	p.auditAnswer(ToolNameConsent, map[string]string{"name": n, "answer": how}, approved)
}

// AddrsNeedApproval reports whether connects to private addresses outside
// Docker's networks and the host's own addresses wait for the user's
// approval (INITIAL.md §10 Q15): for MCP clients, when the allowlist admits
// them only through its rfc1918 class. The CLI's user types the targets.
func (p *Policy) AddrsNeedApproval() bool {
	return p.d.Client == ClientMCP && p.rfc1918
}

// AddrAllowed reports whether the user approved connects to ap this session
// and the approval has connects left.
func (p *Policy) AddrAllowed(ap netip.AddrPort) bool {
	p.namesMu.Lock()
	defer p.namesMu.Unlock()
	return p.addrs.left(unmapped(ap)) > 0
}

// RecordAddrConsent records the user's answer to a request to connect to one
// private address and port; an approval covers ApprovalBudget connects to
// exactly that address and port in the session. Only the MCP server calls
// it, with what the user chose about what the server asked.
func (p *Policy) RecordAddrConsent(ap netip.AddrPort, approved bool, how string) {
	ap = unmapped(ap)
	if approved {
		p.namesMu.Lock()
		p.addrs.grant(ap)
		p.namesMu.Unlock()
	}
	p.auditAnswer(ToolAddrConsent, map[string]string{"address": ap.String(), "answer": how}, approved)
}

func unmapped(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
}

// leaseName takes one lookup from an approval of name for a batch.
func (p *Policy) leaseName(n string) bool {
	p.namesMu.Lock()
	defer p.namesMu.Unlock()
	return p.approved.take(n)
}

// leaseAddrs sets aside, for one batch, connects to the approved addresses:
// as many as the batch has TCP checks to the address's port, and no more
// than the approval has left. The probe counts them down as it connects.
func (p *Policy) leaseAddrs(specs []probe.Spec) []netip.AddrPort {
	perPort := map[uint16]int{}
	for _, s := range specs {
		if s.Kind == probe.SpecTCP {
			perPort[s.Port]++
		}
	}
	p.namesMu.Lock()
	defer p.namesMu.Unlock()
	var out []netip.AddrPort
	for ap, left := range p.addrs {
		n := min(left, perPort[ap.Port()])
		p.addrs[ap] -= n
		for range n {
			out = append(out, ap)
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return out
}

// settle returns what a batch set aside and provably didn't use, and fails
// closed otherwise. Before the executor ran (ran false), nothing was sent,
// so everything returns. After a run that failed (runErr), nothing does: it
// may have sent before it lost its records. Otherwise a lookup of a leased
// name comes back only when its record shows no query sent (the hosts file
// answered, or the nameservers refused it), and connects to approved
// addresses when every connect record either kept its data, so the ones
// made can be counted, or was skipped, which sends nothing (a name that
// didn't resolve, a refusal). A return never takes an approval past
// ApprovalBudget.
func (p *Policy) settle(names []string, addrs []netip.AddrPort, evs []evidence.Evidence, ran bool, runErr error) {
	if len(names) == 0 && len(addrs) == 0 || ran && runErr != nil {
		return
	}
	if !ran {
		p.namesMu.Lock()
		defer p.namesMu.Unlock()
		for _, n := range names {
			p.approved.refund(n)
		}
		for _, ap := range addrs {
			p.addrs.refund(ap)
		}
		return
	}
	sent, unsent := map[string]bool{}, map[string]bool{}
	used := map[netip.AddrPort]int{}
	lost := false
	for _, e := range evs {
		switch d := e.Data.(type) {
		case evidence.DNSProbe:
			n := target.NormalizeName(e.Subject)
			if len(d.Attempts) > 0 {
				sent[n] = true
			} else if e.Status == evidence.StatusOK || e.Status == evidence.StatusSkipped {
				unsent[n] = true
			}
		case evidence.TCPProbe:
			if d.Outcome != evidence.OutcomeBlocked && d.Addr.IsValid() {
				used[unmapped(d.Addr)]++
			}
		default:
			lost = lost || e.Kind == evidence.KindTCP && e.Status != evidence.StatusSkipped
		}
	}
	p.namesMu.Lock()
	defer p.namesMu.Unlock()
	for _, n := range names {
		if unsent[n] && !sent[n] {
			p.approved.refund(n)
		}
	}
	if lost {
		return
	}
	for _, ap := range addrs {
		if used[ap] > 0 {
			used[ap]--
			continue
		}
		p.addrs.refund(ap)
	}
}

// Netns reports whether tier 3 is in effect: as root, container checks
// enter the containers' network namespaces (the netns executor).
func (p *Policy) Netns() bool { return p.d.Netns != nil }

// ConfigPath is the config file the settings came from.
func (p *Policy) ConfigPath() string { return p.d.Settings.ConfigPath }

// DiagnoseArgs are diagnose_connection's arguments, as given.
type DiagnoseArgs struct {
	From   string // host, container:<name>, service:<name>[@<project>]; empty means host
	To     string // host:port
	Expect string // "connect" or empty
}

// Diagnose answers "why can't From reach To?".
func (p *Policy) Diagnose(ctx context.Context, a DiagnoseArgs) (*engine.Diagnosis, error) {
	start := time.Now()
	ctx, n := withCounts(ctx)
	d, err := p.diagnose(ctx, a)
	e := Entry{Tool: ToolDiagnose, Args: map[string]string{"from": a.From, "to": a.To, "expect": a.Expect}}
	if d != nil {
		e.Verdict, e.DiagnosisID, e.SideEffects = d.Verdict, d.ID, d.SideEffects
		if f := d.Primary(); f != nil {
			e.Primary = f.RuleID
		}
	}
	n.fill(&e)
	p.audit(e, start, err)
	return d, err
}

func (p *Policy) diagnose(ctx context.Context, a DiagnoseArgs) (*engine.Diagnosis, error) {
	from, err := target.ParseFrom(a.From)
	if err != nil {
		return nil, err
	}
	to, err := target.ParseTo(a.To)
	if err != nil {
		return nil, err
	}
	if a.Expect != "" && a.Expect != "connect" {
		return nil, &Error{Code: evidence.CodeInvalidArgument, Message: fmt.Sprintf("expect %q: the only expectation is connect (the connection should succeed)", a.Expect)}
	}
	return p.engine.Diagnose(ctx, from, to)
}

// Inspect describes the host, a container or a network.
func (p *Policy) Inspect(ctx context.Context, scope string) (*engine.Inspection, error) {
	start := time.Now()
	in, err := p.inspect(ctx, scope)
	p.audit(Entry{Tool: ToolInspect, Args: map[string]string{"scope": scope}}, start, err)
	return in, err
}

func (p *Policy) inspect(ctx context.Context, scope string) (*engine.Inspection, error) {
	s, err := target.ParseScope(scope)
	if err != nil {
		return nil, err
	}
	in, err := p.engine.Inspect(ctx, s)
	if err != nil {
		return nil, err
	}
	if in.Host != nil {
		in.Host.Permissions = p.permissionFacts()
	}
	return in, nil
}

func (p *Policy) permissionFacts() *engine.PermissionFacts {
	f := &engine.PermissionFacts{
		Docker: p.d.Docker != nil, Root: os.Geteuid() == 0, Allow: p.d.Settings.Allow,
		RatePerMinute: p.d.Settings.RatePerMinute, ProbeContainers: "off", Netns: "off",
		OutsideNames: "any (CLI)",
	}
	if p.NamesNeedApproval() {
		f.OutsideNames = "ask the user"
		if len(p.d.Settings.Names) > 0 {
			f.OutsideNames += "; without asking under " + strings.Join(p.d.Settings.Names, ", ")
		}
	}
	if p.Netns() {
		f.Netns = "on (root)"
	}
	switch {
	case p.ProbeContainersConfigured():
		f.ProbeContainers = "on (config)"
	case p.ProbeContainers():
		f.ProbeContainers = "on (approved for this session)"
	}
	return f
}

// ProbeArgs are run_probe's arguments, as given.
type ProbeArgs struct {
	Kind   string // dns, tcp or listeners
	Target string // a name for dns, host:port for tcp, nothing for listeners
	From   string // as for DiagnoseArgs
}

// Probe runs one check.
func (p *Policy) Probe(ctx context.Context, a ProbeArgs) (*engine.ProbeResult, error) {
	start := time.Now()
	ctx, n := withCounts(ctx)
	res, err := p.probe(ctx, a)
	e := Entry{Tool: ToolProbe, Args: map[string]string{"kind": a.Kind, "target": a.Target, "from": a.From}}
	if res != nil {
		e.SideEffects = res.SideEffects
	}
	n.fill(&e)
	p.audit(e, start, err)
	return res, err
}

func (p *Policy) probe(ctx context.Context, a ProbeArgs) (*engine.ProbeResult, error) {
	from, err := target.ParseFrom(a.From)
	if err != nil {
		return nil, err
	}
	var spec probe.Spec
	switch a.Kind {
	case probe.SpecTCP:
		to, err := target.ParseTo(a.Target)
		if err != nil {
			return nil, err
		}
		spec = probe.Spec{Kind: probe.SpecTCP, Host: to.Host, Port: to.Port}
	case probe.SpecDNS:
		name, err := target.ParseName(a.Target)
		if err != nil {
			return nil, err
		}
		spec = probe.Spec{Kind: probe.SpecDNS, Host: name}
	case probe.SpecListeners:
		if strings.TrimSpace(a.Target) != "" {
			return nil, &Error{Code: evidence.CodeInvalidArgument, Message: "listeners takes no target: it reads the listening sockets of from's network namespace"}
		}
		spec = probe.Spec{Kind: probe.SpecListeners}
	default:
		return nil, &Error{Code: evidence.CodeInvalidArgument, Message: fmt.Sprintf("kind %q: want dns, tcp or listeners", a.Kind)}
	}
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	return p.engine.Probe(ctx, from, spec)
}

// NeedsProbeContainers reports evidence that a probe container would add:
// checks withheld because tier 2b is off, and checks the netns executor
// couldn't make because it couldn't enter the namespace (with tier 2b on, a
// probe container stands in).
func NeedsProbeContainers(evs []evidence.Evidence) bool {
	for _, e := range evs {
		if e.Status == evidence.StatusPermissionDenied && e.Err != nil && e.Err.Message == executor.ProbeContainersOff {
			return true
		}
		if e.Err != nil && e.Err.Message == executor.PIDsElsewhere {
			return true // Docker Desktop: listening sockets are read only in probe containers
		}
		if executor.CannotEnter(e.Err) {
			return true
		}
	}
	return false
}

// NeedsNameApproval lists the outside names whose lookups were held back
// because no one approved them, sorted and without repeats: the names the
// MCP server may ask the user about.
func NeedsNameApproval(evs []evidence.Evidence) []string {
	var out []string
	for _, e := range evs {
		if NameHeldBack(e) {
			if n := target.NormalizeName(e.Subject); !slices.Contains(out, n) {
				out = append(out, n)
			}
		}
	}
	slices.Sort(out)
	return out
}

// NeedsAddrApproval lists the private addresses and ports whose connects a
// batch held back because no one approved them (INITIAL.md §10 Q15), sorted
// and without repeats: what the MCP server may ask the user about.
func NeedsAddrApproval(evs []evidence.Evidence) []netip.AddrPort {
	var out []netip.AddrPort
	for _, e := range evs {
		if !AddrHeldBack(e) {
			continue
		}
		if t, ok := e.Data.(evidence.TCPProbe); ok && t.Addr.IsValid() && !slices.Contains(out, unmapped(t.Addr)) {
			out = append(out, unmapped(t.Addr))
		}
	}
	slices.SortFunc(out, func(a, b netip.AddrPort) int { return a.Compare(b) })
	return out
}

// AddrHeldBack reports a connect the probe didn't make because its private
// address and port weren't approved.
func AddrHeldBack(e evidence.Evidence) bool {
	return policyDenied(e, evidence.KindTCP) && e.Err.Message == probe.AddrNotApproved
}

// NameHeldBack reports a lookup the probe didn't send because its outside
// name wasn't approved.
func NameHeldBack(e evidence.Evidence) bool {
	return policyDenied(e, evidence.KindDNS) && e.Err.Message == probe.NameNotApproved
}

// policyDenied reports a check of kind k that the policy or the probe
// refused: skipped, with code policy_denied (and so an Err).
func policyDenied(e evidence.Evidence, k evidence.Kind) bool {
	return e.Kind == k && e.Status == evidence.StatusSkipped && e.Err != nil && e.Err.Code == evidence.CodePolicyDenied
}

// Error is a request the policy refused or could not serve.
type Error struct {
	Code    string // evidence.Code*
	Message string
}

func (e *Error) Error() string { return e.Message }

// Code classifies an error from the policy: invalid_argument,
// policy_denied, not_found, docker_unavailable, timeout or internal.
func Code(err error) string {
	var pe *Error
	var ee *engine.Error
	var te *target.Error
	switch {
	case err == nil:
		return ""
	case errors.As(err, &pe):
		return pe.Code
	case errors.As(err, &ee):
		return ee.Code
	case errors.As(err, &te):
		if te.Policy {
			return evidence.CodePolicyDenied
		}
		return evidence.CodeInvalidArgument
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return evidence.CodeTimeout
	default:
		return evidence.CodeInternal
	}
}

// IsUsage reports an error the caller can fix by changing the arguments.
func IsUsage(err error) bool {
	switch Code(err) {
	case evidence.CodeInvalidArgument, evidence.CodePolicyDenied, evidence.CodeNotFound:
		return true
	}
	return false
}

func (p *Policy) probeExecutor() (executor.Executor, error) {
	p.probeOnce.Do(func() {
		if p.d.NewProbe == nil {
			p.probeErr = errors.New("probe containers need the Docker API")
			return
		}
		p.probeEx, p.probeErr = p.d.NewProbe()
	})
	return p.probeEx, p.probeErr
}

// limits is the allowlist in effect now: the fixed ranges plus, when the
// config names "docker", the subnets of Docker's networks at this moment.
func (p *Policy) limits(ctx context.Context) probe.Limits {
	var l probe.Limits
	if p.d.HostResolvers != nil {
		l.HostResolvers = p.d.HostResolvers()
	}
	if len(p.d.Settings.Allow) == 0 {
		return l
	}
	l.Restricted, l.Allow = true, append([]netip.Prefix(nil), p.static...)
	// Through MCP, a private address the allowlist admits only through its
	// rfc1918 class needs the user's approval, except on Docker's networks,
	// at the host's own addresses or under an explicit entry (§10 Q15).
	addrs := p.AddrsNeedApproval()
	if (p.docker || addrs) && p.d.Docker != nil {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		nets, err := p.d.Docker.ListNetworks(lctx)
		cancel()
		if err != nil {
			p.d.Logger.Warn("could not list Docker networks for the probe allowlist", "err", err)
		}
		// A bridge network's subnet lives inside the host: every address
		// there is Docker's. Of any other (macvlan and ipvlan share the
		// physical network's subnet), only the containers' own addresses
		// are, for the allowlist's docker class as for Q15's free list.
		var shared []string
		for _, n := range nets {
			if n.Driver != "bridge" {
				shared = append(shared, n.Name)
				continue
			}
			if p.docker {
				l.Allow = append(l.Allow, n.Subnets...)
			}
			if addrs {
				l.Free = append(l.Free, n.Subnets...)
			}
		}
		if len(shared) > 0 {
			own := p.containerAddrs(ctx, shared)
			if p.docker {
				l.Allow = append(l.Allow, own...)
			}
			if addrs {
				l.Free = append(l.Free, own...)
			}
		}
	}
	if addrs {
		l.AddrsRestricted = true
		l.Private, _ = config.AllowPrefixes(config.AllowRFC1918)
		l.Free = append(l.Free, p.explicit...)
		l.Free = append(l.Free, p.hostAddrs()...)
	}
	return l
}

// containerAddrs lists the addresses Docker gave running containers on the
// named networks. A macvlan or ipvlan network's subnet is the physical
// network itself, so of it only the containers' own addresses are Docker's
// (§10 Q15): the router and the other hosts there still need approval.
func (p *Policy) containerAddrs(ctx context.Context, networks []string) []netip.Prefix {
	lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	list, err := p.d.Docker.ListContainers(lctx, false)
	cancel()
	if err != nil {
		p.d.Logger.Warn("could not list containers for the probe allowlist", "err", err)
		return nil
	}
	var out []netip.Prefix
	for _, c := range list {
		for name, ep := range c.NetworkSettings.Networks {
			if !slices.Contains(networks, name) {
				continue
			}
			for _, s := range []string{ep.IPAddress, ep.GlobalIPv6Address} {
				if a, err := netip.ParseAddr(s); err == nil {
					out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
				}
			}
		}
	}
	return out
}

// hostAddrs lists the host's own interface addresses, none when whyreach
// can't see the host's network (its image without --network host).
func (p *Policy) hostAddrs() []netip.Prefix {
	if p.d.Interfaces == nil {
		return nil
	}
	ha, err := p.d.Interfaces()
	if err != nil {
		return nil
	}
	var out []netip.Prefix
	for _, i := range ha.Interfaces {
		for _, a := range i.Addrs {
			out = append(out, netip.PrefixFrom(a.Addr().Unmap(), a.Addr().Unmap().BitLen()))
		}
	}
	return out
}

// audit writes an entry, if there is an audit log.
func (p *Policy) audit(e Entry, start time.Time, err error) {
	if p.d.Audit == nil {
		return
	}
	e.Time = start.UTC()
	e.Client = p.d.Client
	e.DurationMS = evidence.Millis(time.Since(start))
	e.ProbeContainers = p.ProbeContainers()
	e.Netns = p.Netns()
	if e.Status == "" {
		e.Status = "ok"
	}
	if err != nil {
		e.Status = Code(err)
		e.Error = err.Error()
	}
	if e.SideEffects == nil {
		e.SideEffects = []string{}
	}
	if werr := p.d.Audit.Write(e); werr != nil {
		p.d.Logger.Warn("could not write the audit log", "err", werr)
	}
}

// Audit records a tool call that does not run through the engine, such as
// save_report.
func (p *Policy) Audit(tool string, args map[string]string, start time.Time, err error) {
	p.audit(Entry{Tool: tool, Args: args}, start, err)
}
