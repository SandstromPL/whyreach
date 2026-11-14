//go:build lab

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// simulatedDesktop is the platform name the -lab.desktop proxy reports.
const simulatedDesktop = "Docker Desktop 4.50.0 (lab simulation)"

// desktopProxy serves the real Docker socket at sock, except that GET
// /version says Docker Desktop: whyreach then treats Docker's PIDs as
// another machine's and reads containers' listening sockets only inside
// probe containers (ADR 0004). Everything else passes through, probe
// containers' lifecycle calls included; whyreach's own allowlist still
// decides what it sends.
func desktopProxy(sock string) error {
	real, err := docker.Endpoint(os.Getenv)
	if err != nil {
		return err
	}
	path := strings.TrimPrefix(real, "unix://")
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host = "http", "docker"
		},
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			if resp.Request.Method != http.MethodGet || !strings.HasSuffix(resp.Request.URL.Path, "/version") || resp.StatusCode != http.StatusOK {
				return nil
			}
			b, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
			var v map[string]any
			if err := json.Unmarshal(b, &v); err != nil {
				return err
			}
			v["Platform"] = map[string]any{"Name": simulatedDesktop}
			if b, err = json.Marshal(v); err != nil {
				return err
			}
			resp.Body = io.NopCloser(bytes.NewReader(b))
			resp.ContentLength = int64(len(b))
			resp.Header.Set("Content-Length", strconv.Itoa(len(b)))
			return nil
		},
	}
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", sock)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: rp, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			panic(err)
		}
	}()
	return nil
}

// TestDegradedProblems checks the harness's own judgement of a diagnosis
// made without probe containers on Docker Desktop, on made-up diagnoses.
func TestDegradedProblems(t *testing.T) {
	wr002 := expect{Verdict: engine.VerdictCause, TopRule: "WR002", Confidence: "high", MustNotFire: []string{"WR004"}}
	healthy := expect{Verdict: engine.VerdictNoProblem}
	probeGap := []engine.Gap{{What: "listening sockets in api", Why: "unsupported", HowToEnable: "Allow probe containers (…): set probe_containers = true under [permissions] in …"}}
	finding := func(id, conf string) []rules.Finding {
		return []rules.Finding{{RuleID: id, Confidence: rules.Confidence(conf), Title: id}}
	}
	tests := []struct {
		name string
		d    engine.Diagnosis
		e    expect
		ok   bool
	}{
		{"the same cause", engine.Diagnosis{Verdict: engine.VerdictCause, Findings: finding("WR002", "high")}, wr002, true},
		{"the same cause, less sure", engine.Diagnosis{Verdict: engine.VerdictLikelyCause, Findings: finding("WR002", "medium"), Gaps: probeGap}, wr002, true},
		{"inconclusive with the gap", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Gaps: probeGap}, wr002, true},
		{"inconclusive without saying why", engine.Diagnosis{Verdict: engine.VerdictInconclusive}, wr002, false},
		{"another cause", engine.Diagnosis{Verdict: engine.VerdictCause, Findings: finding("WR001", "high"), Gaps: probeGap}, wr002, false},
		{"a forbidden finding", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Findings: finding("WR004", "low"), Gaps: probeGap}, wr002, false},
		{"surer than with probes", engine.Diagnosis{Verdict: engine.VerdictCause, Findings: finding("WR002", "high")},
			expect{Verdict: engine.VerdictLikelyCause, TopRule: "WR002", Confidence: "medium"}, false},
		{"inconclusive, with another rule as the weak lead", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Findings: finding("WR001", "low"), Gaps: probeGap}, wr002, false},
		{"inconclusive, with the expected rule as the weak lead", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Findings: finding("WR002", "low"), Gaps: probeGap}, wr002, true},
		{"healthy, unconfirmed", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Gaps: probeGap}, healthy, true},
		{"healthy, unconfirmed with a weak lead", engine.Diagnosis{Verdict: engine.VerdictInconclusive, Findings: finding("WR001", "low"), Gaps: probeGap}, healthy, true},
		{"healthy, a cause", engine.Diagnosis{Verdict: engine.VerdictCause, Findings: finding("WR002", "high"), Gaps: probeGap}, healthy, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if p := degradedProblems(&tt.d, tt.e); (len(p) == 0) != tt.ok {
				t.Errorf("problems %q, want ok: %v", p, tt.ok)
			}
		})
	}
	on := expectOn{VerdictIn: []string{engine.VerdictNoProblem, engine.VerdictInconclusive}, MustNotFire: []string{"WR011"}}
	if p := onProblems(&engine.Diagnosis{Verdict: engine.VerdictInconclusive}, on); len(p) != 0 {
		t.Errorf("onProblems: %q", p)
	}
	if p := onProblems(&engine.Diagnosis{Verdict: engine.VerdictCause, Findings: finding("WR011", "high")}, on); len(p) != 2 {
		t.Errorf("onProblems: %q, want the verdict and WR011", p)
	}
}
