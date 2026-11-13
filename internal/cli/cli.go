// Package cli is whyreach's command line: argument parsing, wiring and
// rendering. It holds no diagnostic logic (CLAUDE.md).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/target"
)

// Exit codes (INITIAL.md §4.11).
const (
	ExitNoProblem    = 0 // no problem reproduced
	ExitCause        = 1 // cause or likely cause found
	ExitInconclusive = 2 // inconclusive
	ExitUsage        = 3 // usage or policy error
	ExitInternal     = 4 // internal error
)

// Options are the process's environment, injected for tests.
type Options struct {
	Version string
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	// NewEngine builds the engine; nil means the real one.
	NewEngine func(o Options, logger *slog.Logger) (*engine.Engine, error)
}

// exitError carries an exit code out of a command.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

func usageErr(err error) error    { return &exitError{code: ExitUsage, err: err} }
func internalErr(err error) error { return &exitError{code: ExitInternal, err: err} }

// Execute runs whyreach with args and returns the exit code.
func Execute(ctx context.Context, args []string, o Options) int {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	code := ExitNoProblem
	root := newRoot(o, &code)
	if args == nil {
		args = []string{} // cobra reads os.Args when given nil
	}
	root.SetArgs(args)
	root.SetOut(o.Stdout)
	root.SetErr(o.Stderr)
	if err := root.ExecuteContext(ctx); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			code = ee.code
		} else {
			code = ExitUsage // cobra's own errors: unknown flags, wrong argument counts
		}
		fmt.Fprintln(o.Stderr, "whyreach:", err)
	}
	return code
}

type diagnoseFlags struct {
	from string
	json bool
}

func newRoot(o Options, code *int) *cobra.Command {
	var f diagnoseFlags
	root := &cobra.Command{
		Use:   "whyreach [--from container:NAME] HOST:PORT",
		Short: "Explain why one container can't reach another (read-only network diagnosis for Docker)",
		Long: `whyreach diagnoses network connections between Docker containers and the host.
It collects evidence (Docker metadata, listening sockets, DNS and TCP probes
from the right network namespace) and reports the cause from a catalog of
rules, without changing anything.

"whyreach [--from SOURCE] HOST:PORT" is short for "whyreach diagnose".`,
		Example: `  whyreach --from container:worker api:8080
  whyreach diagnose --from service:worker@shop localhost:5432 --json`,
		Args:          cobra.MaximumNArgs(1),
		Version:       o.Version,
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				_ = cmd.Usage()
				return usageErr(errors.New("missing HOST:PORT"))
			}
			return runDiagnose(cmd, o, f, args[0], code)
		},
	}
	root.SetVersionTemplate("whyreach {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr(err) })
	addDiagnoseFlags(root, &f)

	var df diagnoseFlags
	diagnose := &cobra.Command{
		Use:   "diagnose [--from SOURCE] HOST:PORT",
		Short: "Diagnose a connection from SOURCE (default: host) to HOST:PORT",
		Long: `Diagnose a TCP connection and explain why it fails.

SOURCE is host, container:<name|id> or service:<name>[@<project>].
HOST:PORT (or tcp://HOST:PORT) names exactly one destination: a container
name, Compose service, alias, DNS name, IP address or localhost.

Exit codes: 0 no problem reproduced, 1 cause or likely cause found,
2 inconclusive, 3 usage or policy error, 4 internal error.`,
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(fmt.Errorf("diagnose takes exactly one HOST:PORT, got %d arguments", len(args)))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiagnose(cmd, o, df, args[0], code)
		},
	}
	addDiagnoseFlags(diagnose, &df)
	root.AddCommand(diagnose)

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print whyreach's version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "whyreach %s\n", o.Version)
		},
	})

	var spec string
	probeCmd := &cobra.Command{
		Use:    "__probe",
		Short:  "Run probe specs in this network namespace (inside a probe container)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if c := probe.Main(cmd.Context(), spec, cmd.OutOrStdout(), cmd.ErrOrStderr()); c != probe.ExitOK {
				return internalErr(errors.New("probe failed"))
			}
			return nil
		},
	}
	probeCmd.Flags().StringVar(&spec, "spec", "", "JSON list of probe specs")
	root.AddCommand(probeCmd)
	return root
}

func addDiagnoseFlags(cmd *cobra.Command, f *diagnoseFlags) {
	cmd.Flags().StringVar(&f.from, "from", "host", "where the connection starts: host, container:<name|id> or service:<name>[@<project>]")
	cmd.Flags().BoolVar(&f.json, "json", false, "print the diagnosis as JSON")
}

func runDiagnose(cmd *cobra.Command, o Options, f diagnoseFlags, to string, code *int) error {
	from, err := target.ParseFrom(f.from)
	if err != nil {
		return usageErr(err)
	}
	dest, err := target.ParseTo(to)
	if err != nil {
		return usageErr(err)
	}
	logger := newLogger(o)
	newEngine := o.NewEngine
	if newEngine == nil {
		newEngine = buildEngine
	}
	eng, err := newEngine(o, logger)
	if err != nil {
		return usageErr(err)
	}
	d, err := eng.Diagnose(cmd.Context(), from, dest)
	if err != nil {
		if engine.IsUsage(err) {
			return usageErr(err)
		}
		return internalErr(err)
	}
	out := cmd.OutOrStdout()
	if f.json {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			return internalErr(err)
		}
	} else {
		RenderText(out, d)
	}
	*code = d.ExitCode()
	return nil
}

// newLogger writes JSON logs to stderr only; stdout carries results (and,
// from M2, the MCP protocol). WHYREACH_LOG=debug|info|warn sets the level.
func newLogger(o Options) *slog.Logger {
	level := slog.LevelWarn
	switch strings.ToLower(o.Getenv("WHYREACH_LOG")) {
	case "debug":
		level = slog.LevelDebug
	case "info":
		level = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(o.Stderr, &slog.HandlerOptions{Level: level}))
}

// buildEngine wires the real collaborators from the config file.
func buildEngine(o Options, logger *slog.Logger) (*engine.Engine, error) {
	path, err := config.Path()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	deps := engine.Deps{
		Host:       executor.NewHost(),
		Listeners:  procListeners{},
		ConfigPath: path,
		Deadline:   cfg.Timeouts.Diagnosis.Duration,
		Logger:     logger,
	}
	if !cfg.Permissions.Docker {
		return engine.New(deps), nil
	}
	endpoint, err := docker.Endpoint(o.Getenv)
	if err != nil {
		deps.DockerErr = err
		return engine.New(deps), nil
	}
	client, err := docker.New(endpoint, docker.ReadRoutes())
	if err != nil {
		deps.DockerErr = err
		return engine.New(deps), nil
	}
	deps.Docker = client
	if cfg.Permissions.ProbeContainers {
		pc, err := docker.NewProbeClient(endpoint)
		if err != nil {
			return nil, err
		}
		exe, err := os.Executable()
		if err != nil {
			return nil, fmt.Errorf("find whyreach's own binary for the probe image: %w", err)
		}
		deps.Probe = executor.NewProbeContainer(pc, exe, o.Version, logger)
	}
	return engine.New(deps), nil
}

// procListeners reads listeners from /proc on the host.
type procListeners struct{}

func (procListeners) Host() ([]evidence.Socket, error) { return probe.ReadListeners("/proc") }

func (procListeners) Container(pid int, id string) ([]evidence.Socket, error) {
	return probe.ContainerListeners(pid, id)
}
