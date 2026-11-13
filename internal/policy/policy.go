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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
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
)

// Clients that go through the policy.
const (
	ClientCLI = "cli"
	ClientMCP = "mcp"
)

// Settings are the permissions and limits from the user's config file.
type Settings struct {
	Docker          bool     // tier 2a: read Docker metadata
	ProbeContainers bool     // tier 2b: ephemeral probe containers
	Allow           []string // [probe] allow: classes and CIDRs; empty means no allowlist
	RatePerMinute   int      // [probe] rate_per_minute
	ConfigPath      string   // named in advice
}

// SettingsFrom reads the settings out of a loaded config.
func SettingsFrom(c config.Config, path string) Settings {
	return Settings{
		Docker: c.Permissions.Docker, ProbeContainers: c.Permissions.ProbeContainers,
		Allow: c.Probe.Allow, RatePerMinute: c.Probe.RatePerMinute, ConfigPath: path,
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
	Host       executor.Executor // runs probes in the host's network namespace
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
	if !d.Settings.Docker {
		d.Docker, d.DockerErr = nil, nil
	}
	if d.Docker == nil {
		d.Netns = nil // it finds containers through the Docker API
	}
	p := &Policy{d: d, limiter: newLimiter(d.Settings.RatePerMinute, d.Now)}
	for _, entry := range d.Settings.Allow {
		prefixes, err := config.AllowPrefixes(entry)
		if err != nil {
			return nil, &Error{Code: evidence.CodeInvalidArgument, Message: "probe allowlist: " + err.Error()}
		}
		if strings.EqualFold(strings.TrimSpace(entry), config.AllowDocker) {
			p.docker = true
		}
		p.static = append(p.static, prefixes...)
	}
	host := d.Host
	if host == nil {
		host = executor.NewHost()
	}
	// The netns executor obeys the same allowlist, block list and rate
	// limit as the others; it needs no tier 2b, since it writes nothing to
	// Docker.
	var netns executor.Executor
	if d.Netns != nil {
		netns = &guard{p: p, name: evidence.ExecutorNetns, inner: func() (executor.Executor, error) { return d.Netns, nil }}
	}
	p.engine = engine.New(engine.Deps{
		Docker:     d.Docker,
		DockerErr:  d.DockerErr,
		Host:       &guard{p: p, name: evidence.ExecutorHost, inner: func() (executor.Executor, error) { return host, nil }},
		Probe:      &guard{p: p, name: evidence.ExecutorProbeContainer, tier2b: true, inner: p.probeExecutor},
		Netns:      netns,
		Listeners:  d.Listeners,
		Interfaces: d.Interfaces,
		ConfigPath: d.Settings.ConfigPath,
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
	status := "declined"
	if approved {
		status = "approved"
	}
	p.audit(Entry{Tool: ToolConsent, Args: map[string]string{"answer": how}, Status: status, SideEffects: []string{}}, time.Now(), nil)
}

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
	p.audit(Entry{Tool: ToolInspect, Args: map[string]string{"scope": scope}, SideEffects: []string{}}, start, err)
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
	}
	if p.d.Netns != nil {
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

// NeedsProbeContainers reports evidence that could not be collected because
// tier 2b is off: a probe container would add something.
func NeedsProbeContainers(evs []evidence.Evidence) bool {
	for _, e := range evs {
		if e.Status == evidence.StatusPermissionDenied && e.Err != nil && e.Err.Message == executor.ProbeContainersOff {
			return true
		}
	}
	return false
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
	if len(p.d.Settings.Allow) == 0 {
		return probe.Limits{}
	}
	l := probe.Limits{Restricted: true, Allow: append([]netip.Prefix(nil), p.static...)}
	if p.docker && p.d.Docker != nil {
		lctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		nets, err := p.d.Docker.ListNetworks(lctx)
		cancel()
		if err != nil {
			p.d.Logger.Warn("could not list Docker networks for the probe allowlist", "err", err)
		}
		for _, n := range nets {
			l.Allow = append(l.Allow, n.Subnets...)
		}
	}
	return l
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
	p.audit(Entry{Tool: tool, Args: args, SideEffects: []string{}}, start, err)
}
