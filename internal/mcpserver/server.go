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
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/policy"
	"github.com/SandstromPL/whyreach/internal/report"
	"github.com/SandstromPL/whyreach/internal/rules"
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

	logOnce  sync.Once
	mu       sync.Mutex
	recent   []*engine.Diagnosis // the last few, for save_report
	asked    bool                // the user was asked for probe containers this session
	pending  map[string]bool     // request states of consent requests sent as input requests
	readOnly bool                // the annotations currently registered
}

// keep is how many diagnoses save_report can find.
const keep = 32

// consentKey names the probe-container question in input requests.
const consentKey = "probe_containers"

// New builds the server and registers its tools.
func New(p *policy.Policy, o Options) *Server {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.ConsentTimeout <= 0 {
		o.ConsentTimeout = 2 * time.Minute
	}
	s := &Server{p: p, o: o, pending: map[string]bool{}}
	s.srv = mcp.NewServer(&mcp.Implementation{Name: "whyreach", Title: "whyreach: Docker network diagnosis", Version: o.Version}, &mcp.ServerOptions{
		Logger:             o.Logger,
		Instructions:       instructions,
		InitializedHandler: s.initialized,
	})
	s.register()
	return s
}

const instructions = `whyreach diagnoses network connections between Docker containers and between containers and the host, read-only. ` +
	`When a service can't connect to another (connection refused, timeout, name not resolving), call diagnose_connection first ` +
	`with to=<host:port the app uses> and from=<the client: host, container:<name> or service:<compose service>[@<project>]>. ` +
	`Follow its next_checks; use inspect_environment to see containers and networks, and run_probe to test one thing.`

// MCP returns the underlying SDK server, for transports and tests.
func (s *Server) MCP() *mcp.Server { return s.srv }

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
	s.mu.Lock()
	s.readOnly = readOnly
	s.mu.Unlock()
	no, yes := false, true
	probing := &mcp.ToolAnnotations{ReadOnlyHint: readOnly, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &yes}
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  "diagnose_connection",
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
		Name:  "inspect_environment",
		Title: "Inspect Docker networking facts",
		Description: "Inspect Docker networking: scope host (Docker version, interfaces, listening ports, containers and published ports), " +
			"container:<name> or service:<name>[@<project>] (state, networks, IPs, DNS names, published ports, listening sockets), " +
			"or network:<name> (driver, subnet, members). Use it to see what exists. Read-only.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, DestructiveHint: &no, IdempotentHint: true, OpenWorldHint: &no},
	}, s.inspect)
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  "run_probe",
		Title: "Run one network check (DNS, TCP connect, listeners)",
		Description: "Run one network check from the host or from inside a container's network namespace: kind dns (target: a name), " +
			"kind tcp (target: host:port; connects and closes, sends nothing) or kind listeners (no target: the listening TCP sockets). " +
			"from is host (default), container:<name> or service:<name>[@<project>]. Use it to confirm a fix or test one thing; " +
			"use diagnose_connection to find a cause.",
		Annotations: probing,
	}, s.probe)
	mcp.AddTool(s.srv, &mcp.Tool{
		Name:  "save_report",
		Title: "Save a diagnosis as a report bundle",
		Description: "Save a diagnosis (its id from diagnose_connection) with all its evidence as a report bundle on disk, to attach to an issue. " +
			"Public IP addresses, host names and container IDs are replaced by pseudonyms unless redact is false.",
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
	s.logClient(req)
	args := policy.DiagnoseArgs{From: in.From, To: in.To, Expect: in.Expect}
	s.answered(req)
	d, err := s.p.Diagnose(ctx, args)
	if err != nil {
		return nil, report.Diagnosis{}, err
	}
	settled := d.Verdict == engine.VerdictCause && d.Primary() != nil && d.Primary().Confidence == rules.High
	if !settled && policy.NeedsProbeContainers(d.Evidence) {
		res, approved := s.askForProbeContainers(ctx, req, d.Question.From.Ref)
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

// InspectIn is inspect_environment's input.
type InspectIn struct {
	Scope string `json:"scope" jsonschema:"host, container:<name or id>, service:<compose service>[@<project>] or network:<name>"`
}

func (s *Server) inspect(ctx context.Context, req *mcp.CallToolRequest, in InspectIn) (*mcp.CallToolResult, *engine.Inspection, error) {
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
	s.logClient(req)
	args := policy.ProbeArgs{Kind: in.Kind, Target: in.Target, From: in.From}
	s.answered(req)
	res, err := s.p.Probe(ctx, args)
	if err != nil {
		return nil, report.ProbeResult{}, err
	}
	if policy.NeedsProbeContainers(res.Evidence) {
		ask, approved := s.askForProbeContainers(ctx, req, res.From)
		if ask != nil {
			return ask, report.ProbeResult{}, nil
		}
		if approved {
			if again, err := s.p.Probe(ctx, args); err == nil {
				res = again
			}
		}
	}
	out := report.CompactProbe(res, s.howToEnable())
	var text bytes.Buffer
	report.RenderProbe(&text, out)
	return textResult(text.String()), out, nil
}

func (s *Server) howToEnable() string {
	return "This check runs inside the container through a probe container, which is off. Approve probe containers when whyreach asks, " +
		"or set probe_containers = true under [permissions] in " + s.p.ConfigPath() + "."
}

// SaveIn is save_report's input.
type SaveIn struct {
	DiagnosisID string `json:"diagnosis_id" jsonschema:"the id of a diagnosis from diagnose_connection in this session"`
	Redact      *bool  `json:"redact,omitempty" jsonschema:"replace public IPs, host names and container IDs with pseudonyms (default true)"`
}

func (s *Server) save(_ context.Context, req *mcp.CallToolRequest, in SaveIn) (*mcp.CallToolResult, report.Saved, error) {
	s.logClient(req)
	start := time.Now()
	redact := in.Redact == nil || *in.Redact
	saved, err := s.saveReport(in.DiagnosisID, redact)
	s.p.Audit(policy.ToolSave, map[string]string{"diagnosis_id": in.DiagnosisID, "redact": fmt.Sprint(redact)}, start, err)
	if err != nil {
		return nil, report.Saved{}, err
	}
	text := fmt.Sprintf("Saved diagnosis %s to %s (%s).", in.DiagnosisID, saved.Path, redactionText(saved))
	return textResult(text), saved, nil
}

func (s *Server) saveReport(id string, redact bool) (report.Saved, error) {
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
		Dir: s.o.ReportsDir, Redact: redact, RedactPrivate: s.o.RedactPrivate, Home: home, Version: s.o.Version,
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
// containers. Clients on protocol 2026-07-28 or later get an input request
// in the result and call again with the answer (SEP-2322): res is that
// result. Older clients are asked directly, and approved says what the user
// chose. The question goes to the user through the client's own dialog: the
// model can't answer it, and no tool argument can.
func (s *Server) askForProbeContainers(ctx context.Context, req *mcp.CallToolRequest, source string) (res *mcp.CallToolResult, approved bool) {
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
		s.pending[state] = true
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

// answered applies the answer to a consent request that this server sent
// as an input request, when the client calls again with it. An answer
// without a matching pending request is ignored.
func (s *Server) answered(req *mcp.CallToolRequest) {
	if req.Params == nil || req.Params.InputResponses == nil {
		return
	}
	answer, ok := req.Params.InputResponses[consentKey].(*mcp.ElicitResult)
	if !ok {
		return
	}
	s.mu.Lock()
	known := s.pending[req.Params.RequestState]
	delete(s.pending, req.Params.RequestState)
	s.mu.Unlock()
	if !known {
		s.o.Logger.Warn("ignored an answer to a probe-container request whyreach did not send")
		return
	}
	s.consent(answer)
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

func consentParams(source string) *mcp.ElicitParams {
	return &mcp.ElicitParams{
		Message: fmt.Sprintf("whyreach wants to test DNS and TCP from inside %s's network namespace with a probe container. "+
			"It imports whyreach's own binary as the local image whyreach-probe (no registry pull), runs one short-lived, locked-down "+
			"container (no capabilities, read-only, labeled io.whyreach.probe=1) joined to that network namespace, and removes it. "+
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
