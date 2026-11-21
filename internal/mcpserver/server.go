// Package mcpserver is whyreach's MCP server: four tools over stdio
// (INITIAL.md §4.10). It is a thin adapter. Every call goes through package
// policy, which owns validation, permissions, probe limits and the audit
// log; this package only translates arguments and renders results.
//
// Structured content is what Claude Code shows the model (ADR 0001), so
// every tool returns a compact typed result that leads with the answer, plus
// a text summary of similar size for clients that ignore structured content.
// Tool failures are results with isError set, never protocol errors.
package mcpserver

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/netip"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/policy"
	"github.com/SandstromPL/whyreach/internal/report"
	"github.com/SandstromPL/whyreach/internal/rules"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Options configure the server.
type Options struct {
	Version       string
	Logger        *slog.Logger // stderr only: stdout carries the protocol
	ReportsDir    string       // where save_report writes bundles
	RedactPrivate bool         // [report] redact_private
	// ConsentTimeout bounds how long a probe-container request waits for
	// the user; 0 means two minutes.
	ConsentTimeout time.Duration
}

// Server serves whyreach's tools to one MCP client.
type Server struct {
	p   *policy.Policy
	o   Options
	srv *mcp.Server

	logOnce   sync.Once
	mu        sync.Mutex
	recent    []*engine.Diagnosis // the last few, for save_report
	asked     bool                // the user was asked for probe containers this session
	questions int                 // questions about names and addresses asked this session
	answers   map[string]string   // per name or address question: pending, approved or declined
	pending   map[string]question // request states of questions sent as input requests
}

// question is what an input request asked the user: to allow probe
// containers, to look up one outside name, or to connect to one private
// address and port.
type question struct {
	key  string         // consentKey, nameKey or addrKey
	name string         // for nameKey: the name the server asked about
	addr netip.AddrPort // for addrKey: the address and port
}

// keep is how many diagnoses save_report can find.
const keep = 32

// Keys of the questions in input requests: probe containers, the lookup of
// an outside name (INITIAL.md §10 Q11), and a connect to a private address
// (§10 Q15).
const (
	consentKey = "probe_containers"
	nameKey    = "name_lookup"
	addrKey    = "private_connect"
)

// maxQuestions bounds the questions about names and addresses in a session,
// together: an agent can pick any name or address, and a stream of dialogs
// invites a careless yes. Past it, a held-back check is a gap that names
// the setting.
const maxQuestions = 3

// States of a name or address question (Server.answers).
const (
	answerPending  = "pending"
	answerApproved = "approved"
	answerDeclined = "declined"
)

// New builds the server and registers its tools.
func New(p *policy.Policy, o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.ConsentTimeout <= 0 {
		o.ConsentTimeout = 2 * time.Minute
	}
	s := &Server{p: p, o: o, pending: map[string]question{}, answers: map[string]string{}}
	s.srv = mcp.NewServer(&mcp.Implementation{Name: "whyreach", Title: "whyreach: Docker network diagnosis", Version: o.Version}, &mcp.ServerOptions{
		Logger:             o.Logger,
		Instructions:       instructions,
		InitializedHandler: s.initialized,
	})
	s.srv.AddReceivingMiddleware(s.auditRejected)
	s.register()
	return s
}

// tools are the four tool names.
var tools = []string{policy.ToolDiagnose, policy.ToolInspect, policy.ToolProbe, policy.ToolSave}

type reachedKey struct{}

// reached marks that a tool handler ran: the call's audit is the handler's.
func reached(ctx context.Context) {
	if b, ok := ctx.Value(reachedKey{}).(*atomic.Bool); ok {
		b.Store(true)
	}
}

// auditRejected audits the tool calls the SDK refuses before any handler
// runs (an unknown tool, arguments that fail the input schema), so the
// audit log has every call, refused ones included (INITIAL.md §4.9).
func (s *Server) auditRejected(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		if method != "tools/call" {
			return next(ctx, method, req)
		}
		ran := &atomic.Bool{}
		start := time.Now()
		res, err := next(context.WithValue(ctx, reachedKey{}, ran), method, req)
		if ran.Load() {
			return res, err
		}
		tool, args := "unknown_tool", map[string]string{}
		if r, ok := req.(*mcp.CallToolRequest); ok && r.Params != nil {
			rejectedArgs(r.Params.Arguments, args)
			// After the arguments: one named "name" must not hide the tool.
			if slices.Contains(tools, r.Params.Name) {
				tool = r.Params.Name
			} else {
				args["name"] = cutRunes(target.MaskCredentials(r.Params.Name), 64)
			}
		}
		msg := "refused before the tool ran"
		if err != nil {
			msg = err.Error()
		} else if r, ok := res.(*mcp.CallToolResult); ok && r.IsError {
			for _, c := range r.Content {
				if tc, ok := c.(*mcp.TextContent); ok {
					msg = tc.Text
					break
				}
			}
		}
		s.p.Audit(tool, args, start, &policy.Error{Code: evidence.CodeInvalidArgument, Message: msg})
		return res, err
	}
}

// rejectedArgs describes a refused call's arguments by name, type and
// length only: they failed validation, so they can hold anything under any
// name, a password included, and their values are of no use to the audit.
func rejectedArgs(raw json.RawMessage, args map[string]string) {
	if len(raw) == 0 {
		return
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		args["arguments"] = fmt.Sprintf("<not an object, %d bytes>", len(raw))
		return
	}
	keys := slices.Sorted(maps.Keys(m))
	for _, k := range keys[:min(len(keys), 8)] {
		var kind string
		switch v := m[k].(type) {
		case string:
			kind = fmt.Sprintf("<string, %d chars>", len([]rune(v)))
		case float64:
			kind = "<number>"
		case bool:
			kind = "<boolean>"
		case nil:
			kind = "<null>"
		case []any:
			kind = "<array>"
		default:
			kind = "<object>"
		}
		args[cutRunes(k, 64)] = kind
	}
	if len(keys) > 8 { // after the names: one named "arguments" must not hide the count
		args["arguments"] = fmt.Sprintf("<%d names>", len(keys))
	}
}

func cutRunes(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

const instructions = `whyreach diagnoses network connections between Docker containers and between containers and the host, read-only. ` +
	`When a service can't connect to another (connection refused, timeout, name not resolving), call diagnose_connection first ` +
	`with to=<host:port the app uses> and from=<the client: host, container:<name> or service:<compose service>[@<project>]>. ` +
	`Follow its next_checks; use inspect_environment to see containers and networks, and run_probe to test one thing.`

// Run serves until the client disconnects or ctx ends.
func (s *Server) Run(ctx context.Context, t mcp.Transport) error {
	return s.srv.Run(ctx, t)
}

func (s *Server) initialized(_ context.Context, req *mcp.InitializedRequest) {
	ip := req.Session.InitializeParams()
	if ip == nil {
		return
	}
	client, elicitation := "", ip.Capabilities != nil && ip.Capabilities.Elicitation != nil
	if ip.ClientInfo != nil {
		client = ip.ClientInfo.Name + " " + ip.ClientInfo.Version
	}
	s.o.Logger.Info("MCP client connected", "client", client, "protocol", ip.ProtocolVersion, "elicitation", elicitation)
}

// logClient logs who calls, once per session. From protocol 2026-07-28 on
// there is no initialize handshake: client info and capabilities travel with
// each request.
func (s *Server) logClient(req *mcp.CallToolRequest) {
	s.logOnce.Do(func() {
		client := ""
		if ci := req.ClientInfo(); ci != nil {
			client = ci.Name + " " + ci.Version
		}
		caps := req.ClientCapabilities()
		s.o.Logger.Info("MCP client calls", "client", client, "protocol", req.ProtocolVersion(),
			"elicitation", caps != nil && caps.Elicitation != nil)
	})
}

// register adds the four tools, with annotations that match the permissions
// in effect: readOnlyHint is false whenever probe containers may run.
func (s *Server) register() {
	readOnly := !s.p.ProbeContainers()
	no, yes := false, true
	probing := &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &yes}
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  policy.ToolDiagnose,
		Title: "Diagnose a failing network connection (Docker)",
		Description: "Diagnose why a network connection fails between Docker containers, or between a container and the host: " +
			"connection refused, timeouts, names that don't resolve. Use this first when one service can't connect to another. " +
			"to is the destination as the app uses it (host:port: a Compose service, container name, IP, localhost or host.docker.internal); " +
			"from is where the connection starts: host (default), container:<name> or service:<compose service>[@<project>]. " +
			"whyreach checks Docker metadata, listening sockets, DNS and TCP from the source's own network namespace, and returns " +
			"the cause with evidence and a fix. It never changes containers, networks or config.",
		Annotations: probing,
	}, s.diagnose)
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  policy.ToolInspect,
		Title: "Inspect Docker networking facts",
		Description: "Inspect Docker networking: scope host (Docker version, interfaces, listening ports, containers and published ports), " +
			"container:<name> or service:<name>[@<project>] (state, networks, IPs, DNS names, published ports, listening sockets), " +
			"or network:<name> (driver, subnet, members). Use it to see what exists. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &no},
	}, s.inspect)
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  policy.ToolProbe,
		Title: "Run one network check (DNS, TCP connect, listeners)",
		Description: "Run one network check from the host or from inside a container's network namespace: kind dns (target: a name), " +
			"kind tcp (target: host:port; connects and closes, sends nothing) or kind listeners (no target: the listening TCP sockets). " +
			"from is host (default), container:<name> or service:<name>[@<project>]. Use it to confirm a fix or test one thing; " +
			"use diagnose_connection to find a cause.",
		Annotations: probing,
	}, s.probe)
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  policy.ToolSave,
		Title: "Save a diagnosis as a report bundle",
		Description: "Save a diagnosis (its id from diagnose_connection) with all its evidence as a report bundle on disk, to attach to an issue. " +
			"The bundle is redacted: public IP addresses, host names and container IDs are replaced by pseudonyms.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: false, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &no},
	}, s.save)
}

// DiagnoseIn is diagnose_connection's input.
type DiagnoseIn struct {
	To     string `json:"to" jsonschema:"the destination as host:port, e.g. api:8080, localhost:5432, 172.22.0.3:8080 or host.docker.internal:5432"`
	From   string `json:"from,omitempty" jsonschema:"where the connection starts: host (default), container:<name or id>, or service:<compose service>[@<project>]"`
	Expect string `json:"expect,omitempty" jsonschema:"connect (the default): the connection should succeed"`
}

func (s *Server) diagnose(ctx context.Context, req *mcp.CallToolRequest, in DiagnoseIn) (*mcp.CallToolResult, report.Diagnosis, error) {
	reached(ctx)
	s.logClient(req)
	args := policy.DiagnoseArgs{From: in.From, To: in.To, Expect: in.Expect}
	s.answered(req)
	d, err := s.p.Diagnose(ctx, args)
	if err != nil {
		return nil, report.Diagnosis{}, err
	}
	for _, ask := range s.askers() {
		if settled(d) {
			break // a cause that metadata and listeners settle needs no more permission
		}
		res, approved := ask(ctx, req, d.Evidence, d.Question.From.Ref)
		if res != nil {
			return res, report.Diagnosis{}, nil // the client asks the user and calls again
		}
		if approved {
			if again, err := s.p.Diagnose(ctx, args); err == nil {
				d = again
			}
		}
	}
	s.remember(d)
	var text bytes.Buffer
	report.RenderText(&text, d)
	return textResult(text.String()), report.Compact(d), nil
}

// asker puts the question a call's records lead to, if any and if it may:
// res is an input request to return, which the client puts to the user and
// answers by calling again; approved says the user, asked directly, said yes.
type asker func(ctx context.Context, req *mcp.CallToolRequest, evs []evidence.Evidence, source string) (res *mcp.CallToolResult, approved bool)

// askers are the questions a call may lead to, in the order they are put:
// probe containers, then an outside name, then a private address (ADR 0003).
// After an approval the call runs again, and the next asker reads the new
// records.
func (s *Server) askers() []asker {
	return []asker{s.askForProbeContainers, s.askForName, s.askForAddr}
}

// settled reports a cause found at high confidence: no further check would
// change the answer, so whyreach asks the user for nothing more.
func settled(d *engine.Diagnosis) bool {
	return d.Verdict == engine.VerdictCause && d.Primary() != nil && d.Primary().Confidence == rules.High
}

// InspectIn is inspect_environment's input.
type InspectIn struct {
	Scope string `json:"scope" jsonschema:"host, container:<name or id>, service:<compose service>[@<project>] or network:<name>"`
}

func (s *Server) inspect(ctx context.Context, req *mcp.CallToolRequest, in InspectIn) (*mcp.CallToolResult, *engine.Inspection, error) {
	reached(ctx)
	s.logClient(req)
	got, err := s.p.Inspect(ctx, in.Scope)
	if err != nil {
		return nil, nil, err
	}
	var text bytes.Buffer
	report.RenderInspection(&text, got)
	return textResult(text.String()), got, nil
}

// ProbeIn is run_probe's input.
type ProbeIn struct {
	Kind   string `json:"kind" jsonschema:"dns, tcp or listeners"`
	Target string `json:"target,omitempty" jsonschema:"for tcp host:port; for dns a name; for listeners leave it empty"`
	From   string `json:"from,omitempty" jsonschema:"where the check runs: host (default), container:<name or id>, or service:<compose service>[@<project>]"`
}

func (s *Server) probe(ctx context.Context, req *mcp.CallToolRequest, in ProbeIn) (*mcp.CallToolResult, report.ProbeResult, error) {
	reached(ctx)
	s.logClient(req)
	args := policy.ProbeArgs{Kind: in.Kind, Target: in.Target, From: in.From}
	s.answered(req)
	res, err := s.p.Probe(ctx, args)
	if err != nil {
		return nil, report.ProbeResult{}, err
	}
	for _, ask := range s.askers() {
		q, approved := ask(ctx, req, res.Evidence, res.From)
		if q != nil {
			return q, report.ProbeResult{}, nil // the client asks the user and calls again
		}
		if approved {
			if again, err := s.p.Probe(ctx, args); err == nil {
				res = again
			}
		}
	}
	out := report.CompactProbe(res, s.adviceFor(req))
	var text bytes.Buffer
	report.RenderProbe(&text, out)
	return textResult(text.String()), out, nil
}

// adviceFor returns advice for this call's client: whether whyreach can
// still ask about a name depends on the client and on the session.
func (s *Server) adviceFor(req *mcp.CallToolRequest) func(evidence.Evidence) string {
	caps := req.ClientCapabilities()
	canAsk := caps != nil && caps.Elicitation != nil
	return func(e evidence.Evidence) string { return s.advice(e, canAsk) }
}

// advice says how to allow a check that couldn't run, addressed to the
// user: turning a tier on or approving a name is their decision, never an
// agent's (an agent that can write files must not change the config to
// widen its own permissions).
func (s *Server) advice(e evidence.Evidence, canAsk bool) string {
	if e.Err != nil {
		if a := executor.Advice(e.Err.Message); a != "" {
			return a
		}
	}
	switch {
	case e.Err != nil && e.Err.Message == executor.PIDsElsewhere:
		return "On Docker Desktop whyreach reads containers' listening sockets only inside probe containers, which are off. Turning them on is the user's decision: " +
			"approve probe containers when whyreach asks, or set probe_containers = true under [permissions] in " + s.p.ConfigPath() + "."
	case e.Status == evidence.StatusPermissionDenied && e.Err != nil && (e.Err.Message == executor.ProbeContainersOff || executor.CannotEnter(e.Err)):
		// Not any denial: a read of a container's listeners that /proc
		// refused (hidepid) is no matter for probe containers.
		return "This check runs inside the container through a probe container, which is off. Turning them on is the user's decision: " +
			"approve probe containers when whyreach asks, or set probe_containers = true under [permissions] in " + s.p.ConfigPath() + "."
	case policy.AddrHeldBack(e):
		t, _ := e.Data.(evidence.TCPProbe)
		how := "add the address or its CIDR to allow under [probe] in " + s.p.ConfigPath() + "."
		if canAsk && t.Addr.IsValid() && s.mayAskAbout(question{key: addrKey, addr: t.Addr}.answerKey()) {
			how = "approve the address and port when whyreach asks, or " + how
		}
		return "A connect's address, port and timing can carry data to whoever runs a private address, so whyreach connects to one outside Docker's networks " +
			"and this machine's own addresses only with the user's approval of that address and port. That is the user's decision: " + how
	case policy.NameHeldBack(e):
		how := "list its domain under names in [probe] in " + s.p.ConfigPath() + "."
		if canAsk && s.mayAskAbout(question{key: nameKey, name: target.NormalizeName(e.Subject)}.answerKey()) {
			how = "approve the name when whyreach asks, or " + how
		}
		msg := "A lookup sends its name to the DNS servers of the name's domain, so whyreach looks up a name with a dot that Docker doesn't know " +
			"only with the user's approval. That is the user's decision: " + how
		if slices.Contains(e.Limitations, engine.NameSearchBounded) {
			msg += " Note: " + engine.NameSearchBounded + "."
		}
		return msg
	default:
		return ""
	}
}

// mayAskAbout reports whether whyreach would still ask the user about a
// name or an address in this session (its answer key).
func (s *Server) mayAskAbout(k string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mayAsk(k)
}

// mayAsk reports whether a question may be put: not declined, not waiting
// for an answer, and within maxQuestions. An approval whose uses ran out
// may be asked about again. s.mu is held.
func (s *Server) mayAsk(k string) bool {
	st := s.answers[k]
	return st != answerPending && st != answerDeclined && s.questions < maxQuestions
}

// answerKey identifies a question about a name or an address.
func (q question) answerKey() string {
	if q.key == addrKey {
		return "addr:" + q.addr.String()
	}
	return "name:" + q.name
}

// SaveIn is save_report's input. It has no way to turn redaction off:
// bundles saved through MCP are always redacted, and an unredacted one is
// the user's to make with the CLI (INITIAL.md §10 Q12).
type SaveIn struct {
	DiagnosisID string `json:"diagnosis_id" jsonschema:"the id of a diagnosis from diagnose_connection in this session"`
}

func (s *Server) save(ctx context.Context, req *mcp.CallToolRequest, in SaveIn) (*mcp.CallToolResult, report.Saved, error) {
	reached(ctx)
	s.logClient(req)
	start := time.Now()
	saved, err := s.saveReport(in.DiagnosisID)
	s.p.Audit(policy.ToolSave, map[string]string{"diagnosis_id": in.DiagnosisID}, start, err)
	if err != nil {
		return nil, report.Saved{}, err
	}
	text := fmt.Sprintf("Saved diagnosis %s to %s (%s).", in.DiagnosisID, saved.Path, redactionText(saved))
	return textResult(text), saved, nil
}

func (s *Server) saveReport(id string) (report.Saved, error) {
	d := s.lookup(id)
	if d == nil {
		return report.Saved{}, &policy.Error{Code: evidence.CodeNotFound, Message: fmt.Sprintf(
			"no diagnosis %q in this session; whyreach keeps the last %d diagnoses: run diagnose_connection and pass its id", id, keep)}
	}
	if s.o.ReportsDir == "" {
		return report.Saved{}, errors.New("no reports directory")
	}
	home, _ := os.UserHomeDir()
	return report.Save(d, report.SaveOptions{
		Dir: s.o.ReportsDir, Redact: true, RedactPrivate: s.o.RedactPrivate, Home: home, Version: s.o.Version,
	})
}

func redactionText(s report.Saved) string {
	if !s.Redacted {
		return "not redacted"
	}
	return fmt.Sprintf("redacted: %d addresses, %d host names, %d container IDs replaced",
		s.Replaced[report.ClassIP], s.Replaced[report.ClassHost], s.Replaced[report.ClassContainer])
}

func (s *Server) remember(d *engine.Diagnosis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recent = append(s.recent, d)
	if len(s.recent) > keep {
		s.recent = s.recent[len(s.recent)-keep:]
	}
}

func (s *Server) lookup(id string) *engine.Diagnosis {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.recent {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// askForProbeContainers asks the user, once per session, to allow probe
// containers, when the records have checks they would run. Clients on
// protocol 2026-07-28 or later get an input request in the result and call
// again with the answer (SEP-2322): res is that result. Older clients are
// asked directly, and approved says what the user chose. The question goes
// to the user through the client's own dialog: the model can't answer it,
// and no tool argument can.
func (s *Server) askForProbeContainers(ctx context.Context, req *mcp.CallToolRequest, evs []evidence.Evidence, source string) (res *mcp.CallToolResult, approved bool) {
	if !policy.NeedsProbeContainers(evs) {
		return nil, false
	}
	caps := req.ClientCapabilities()
	if caps == nil || caps.Elicitation == nil || !s.p.CanUseProbeContainers() || s.p.ProbeContainers() {
		return nil, false
	}
	s.mu.Lock()
	if s.asked {
		s.mu.Unlock()
		return nil, false
	}
	s.asked = true
	params := consentParams(source)
	if req.ProtocolVersion() >= "2026-07-28" {
		state := randomState()
		s.pending[state] = question{key: consentKey}
		s.mu.Unlock()
		return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{consentKey: params}, RequestState: state}, false
	}
	s.mu.Unlock()
	ectx, cancel := context.WithTimeout(ctx, s.o.ConsentTimeout)
	defer cancel()
	answer, err := req.Session.Elicit(ectx, params)
	if err != nil {
		s.o.Logger.Warn("could not ask for probe containers", "err", err)
		s.p.RecordConsent(false, "no answer: "+err.Error())
		return nil, false
	}
	return nil, s.consent(answer)
}

// answered applies the answer to a question that this server sent as an
// input request, when the client calls again with it. The request state
// says which question it was, and for a name which name: an answer applies
// only to what the server asked, once. An answer without a matching pending
// request is ignored.
func (s *Server) answered(req *mcp.CallToolRequest) {
	if req.Params == nil || req.Params.InputResponses == nil {
		return
	}
	s.mu.Lock()
	q, known := s.pending[req.Params.RequestState]
	delete(s.pending, req.Params.RequestState)
	s.mu.Unlock()
	if !known {
		s.o.Logger.Warn("ignored an answer to a request whyreach did not send")
		return
	}
	answer, _ := req.Params.InputResponses[q.key].(*mcp.ElicitResult) // nil: not answered, which declines
	switch q.key {
	case consentKey:
		s.consent(answer)
	case nameKey, addrKey:
		s.record(q, answer, "")
	}
}

// consent records the user's answer and, on approval, re-registers the
// probing tools so their annotations stop claiming read-only.
func (s *Server) consent(answer *mcp.ElicitResult) bool {
	approved := answer != nil && answer.Action == "accept" && answer.Content["allow"] == true
	how := "cancel"
	if answer != nil {
		how = answer.Action
	}
	s.p.RecordConsent(approved, how)
	if approved {
		s.register()
	}
	return approved
}

// askForName asks the user about one outside name whose lookup the records
// held back (INITIAL.md §10 Q11, Q14), the first that may be asked about. An
// approval covers that exact name only, for ApprovalBudget lookups: one yes
// must not let other names out. A declined name isn't asked about again; one
// whose lookups ran out may be.
func (s *Server) askForName(ctx context.Context, req *mcp.CallToolRequest, evs []evidence.Evidence, source string) (*mcp.CallToolResult, bool) {
	for _, n := range policy.NeedsNameApproval(evs) {
		if s.p.NameAllowed(n) {
			continue
		}
		if res, approved, asked := s.ask(ctx, req, question{key: nameKey, name: n}, nameParams(n, source, s.p.ConfigPath())); asked {
			return res, approved
		}
	}
	return nil, false
}

// askForAddr asks the user about one private address and port whose connect
// the records held back (INITIAL.md §10 Q15), like askForName: an approval
// covers exactly that address and port, for ApprovalBudget connects.
func (s *Server) askForAddr(ctx context.Context, req *mcp.CallToolRequest, evs []evidence.Evidence, source string) (*mcp.CallToolResult, bool) {
	for _, a := range policy.NeedsAddrApproval(evs) {
		if s.p.AddrAllowed(a) {
			continue
		}
		if res, approved, asked := s.ask(ctx, req, question{key: addrKey, addr: a}, addrParams(a, source, s.p.ConfigPath())); asked {
			return res, approved
		}
	}
	return nil, false
}

// ask puts one question about a name or an address to the user through the
// same two paths as askForProbeContainers, unless mayAsk says no; asked
// says whether it was put. On the 2026-07-28 path the answer comes with the
// client's next call (answered).
func (s *Server) ask(ctx context.Context, req *mcp.CallToolRequest, q question, params *mcp.ElicitParams) (res *mcp.CallToolResult, approved, asked bool) {
	caps := req.ClientCapabilities()
	if caps == nil || caps.Elicitation == nil {
		return nil, false, false
	}
	k := q.answerKey()
	s.mu.Lock()
	if !s.mayAsk(k) {
		s.mu.Unlock()
		return nil, false, false
	}
	s.answers[k] = answerPending
	s.questions++
	if req.ProtocolVersion() >= "2026-07-28" {
		state := randomState()
		s.pending[state] = q
		s.mu.Unlock()
		return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{q.key: params}, RequestState: state}, false, true
	}
	s.mu.Unlock()
	ectx, cancel := context.WithTimeout(ctx, s.o.ConsentTimeout)
	defer cancel()
	answer, err := req.Session.Elicit(ectx, params)
	if err != nil {
		s.o.Logger.Warn("could not ask the user", "question", q.key, "err", err)
		s.record(q, nil, "no answer: "+err.Error())
		return nil, false, true
	}
	return nil, s.record(q, answer, ""), true
}

// record stores the user's answer to a question about a name or an
// address; how, when set, says why there was none.
func (s *Server) record(q question, answer *mcp.ElicitResult, how string) bool {
	approved := answer != nil && answer.Action == "accept" && answer.Content["allow"] == true
	if how == "" {
		how = "cancel"
		if answer != nil {
			how = answer.Action
		}
	}
	switch q.key {
	case nameKey:
		s.p.RecordNameConsent(q.name, approved, how)
	case addrKey:
		s.p.RecordAddrConsent(q.addr, approved, how)
	}
	s.mu.Lock()
	s.answers[q.answerKey()] = answerDeclined
	if approved {
		s.answers[q.answerKey()] = answerApproved
	}
	s.mu.Unlock()
	return approved
}

func nameParams(name, source, configPath string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: fmt.Sprintf("whyreach was asked to look up the name %s from %s. A lookup sends the name to the DNS servers of its domain, "+
			"outside this machine, so whyreach asks you first: otherwise an agent could pass data out through the names it asks for. "+
			"Allow it only if you expect a lookup of this name. If you allow it, whyreach may look up exactly %s, and no other name, "+
			"up to %d times in this session. (To allow a whole domain without being asked, list it under names in [probe] in %s.) Allow looking up %s?",
			name, source, name, policy.ApprovalBudget, configPath, name),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"allow": map[string]any{
					"type": "boolean", "title": "Look up " + name + " for this session", "default": false,
				},
			},
			"required": []string{"allow"},
		},
	}
}

func addrParams(a netip.AddrPort, source, configPath string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: fmt.Sprintf("whyreach was asked to connect to %s from %s. It is a private address outside Docker's networks and this machine's own addresses: "+
			"a connection's address, port and timing can carry data to whoever runs it, so whyreach asks you first. whyreach sends nothing over the connection; it connects and closes. "+
			"Allow it only if you expect a check of this address. If you allow it, whyreach may connect to exactly %s, and no other address or port, "+
			"up to %d times in this session. (To allow an address or a range without being asked, add it to allow under [probe] in %s.) Allow connecting to %s?",
			a, source, a, policy.ApprovalBudget, configPath, a),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"allow": map[string]any{
					"type": "boolean", "title": "Connect to " + a.String() + " for this session", "default": false,
				},
			},
			"required": []string{"allow"},
		},
	}
}

func consentParams(source string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: fmt.Sprintf("whyreach wants to test DNS and TCP from inside containers' network namespaces with probe containers, "+
			"starting with %s's. If you allow it, for the rest of this session whyreach may: import its own binary as the local image "+
			"whyreach-probe (no registry pull; whyreach never deletes images, so it stays until you remove it); run short-lived, "+
			"locked-down containers (no capabilities, read-only, labeled io.whyreach.probe=1) joined to the network namespace of any "+
			"container it checks; and remove them, along with leftovers of earlier runs that carry that label. "+
			"Nothing else changes. Allow probe containers for this session?", source),
		RequestedSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"allow": map[string]any{
					"type": "boolean", "title": "Allow probe containers for this session", "default": true,
				},
			},
			"required": []string{"allow"},
		},
	}
}

func randomState() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never fails on supported platforms
	return hex.EncodeToString(b)
}

func textResult(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}
}
