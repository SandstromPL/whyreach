// Package cli is whyreach's command line: argument parsing, wiring and
// rendering. It holds no diagnostic logic, and reaches the engine only
// through package policy (CLAUDE.md).
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/SandstromPL/whyreach/internal/collect/docker"
	"github.com/SandstromPL/whyreach/internal/collect/host"
	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/evidence"
	"github.com/SandstromPL/whyreach/internal/executor"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/policy"
	"github.com/SandstromPL/whyreach/internal/probe"
	"github.com/SandstromPL/whyreach/internal/report"
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
	Stdin   io.Reader // mcp serve reads the protocol here; nil means os.Stdin
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	// NewPolicy builds the policy (and the engine behind it) for a client;
	// nil means the real one, from the config file.
	NewPolicy func(o Options, logger *slog.Logger, client string) (*policy.Policy, error)
	// ServeMCP runs the MCP server until the client disconnects; main wires
	// it in, so that nothing else imports the mcpserver package.
	ServeMCP func(ctx context.Context, p *policy.Policy, mo MCPOptions) error
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

// policyErr maps an error from the policy to an exit code.
func policyErr(err error) error {
	if policy.IsUsage(err) {
		return usageErr(err)
	}
	return internalErr(err)
}

// Execute runs whyreach with args and returns the exit code.
func Execute(ctx context.Context, args []string, o Options) int {
	if o.Getenv == nil {
		o.Getenv = os.Getenv
	}
	if o.NewPolicy == nil {
		o.NewPolicy = buildPolicy
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
		fmt.Fprintln(o.Stderr, "whyreach:", report.Sanitize(err.Error()))
	}
	return code
}

type diagnoseFlags struct {
	from   string
	json   bool
	report bool
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
  whyreach diagnose --from service:worker@shop localhost:5432 --json
  whyreach --from host localhost:8080`,
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
	root.AddCommand(diagnose, newInspect(o), newProbe(o), newDoctor(o, code), newMCP(o), newReport(o), newRules())

	root.AddCommand(&cobra.Command{
		Use:   "version",
		Short: "Print whyreach's version",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "whyreach %s\n", o.Version)
		},
	})
	root.AddCommand(newProbeEntry())
	return root
}

// newProbeEntry is the hidden subcommand the probe container runs.
func newProbeEntry() *cobra.Command {
	var spec, allow, names, hostResolvers, private, free, approved string
	var budget time.Duration
	cmd := &cobra.Command{
		Use:    "__probe",
		Short:  "Run probe specs in this network namespace (inside a probe container)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var lim probe.Limits
			if cmd.Flags().Changed("allow") {
				var err error
				if lim, err = probe.ParseLimits(allow); err != nil {
					return internalErr(err)
				}
			}
			if cmd.Flags().Changed("names") {
				var err error
				lim.NamesRestricted = true
				if lim.Names, err = probe.ParseNames(names); err != nil {
					return internalErr(err)
				}
			}
			var err error
			if lim.HostResolvers, err = probe.ParseAddrs(hostResolvers); err != nil {
				return internalErr(err)
			}
			if cmd.Flags().Changed("private") {
				lim.AddrsRestricted = true
				if lim.Private, err = probe.ParsePrefixes(private); err != nil {
					return internalErr(err)
				}
				if lim.Free, err = probe.ParsePrefixes(free); err != nil {
					return internalErr(err)
				}
				if lim.Approved, err = probe.ParseAddrPorts(approved); err != nil {
					return internalErr(err)
				}
			}
			if c := probe.Main(cmd.Context(), spec, budget, lim, cmd.OutOrStdout(), cmd.ErrOrStderr()); c != probe.ExitOK {
				return internalErr(errors.New("probe failed"))
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&spec, "spec", "", "JSON list of probe specs")
	cmd.Flags().DurationVar(&budget, "budget", probe.Budget, "time the whole batch may take")
	cmd.Flags().StringVar(&allow, "allow", "", "comma-separated prefixes connects are restricted to (absent: no allowlist)")
	cmd.Flags().StringVar(&names, "names", "", "comma-separated outside names that may be sent to a nameserver (absent: any name)")
	cmd.Flags().StringVar(&hostResolvers, "host-resolvers", "", "comma-separated addresses of the host's own resolvers, asked for DNS even on the block list")
	cmd.Flags().StringVar(&private, "private", "", "comma-separated prefixes whose addresses need free or approved (absent: no such limit)")
	cmd.Flags().StringVar(&free, "free", "", "comma-separated prefixes of private addresses that need no approval")
	cmd.Flags().StringVar(&approved, "approved", "", "comma-separated address:port pairs the user approved")
	return cmd
}

func addDiagnoseFlags(cmd *cobra.Command, f *diagnoseFlags) {
	cmd.Flags().StringVar(&f.from, "from", "host", "where the connection starts: host, container:<name|id> or service:<name>[@<project>]")
	cmd.Flags().BoolVar(&f.json, "json", false, "print the diagnosis as JSON")
	cmd.Flags().BoolVar(&f.report, "report", false, "also save the diagnosis, with all its evidence, as a report bundle (not redacted; share it with whyreach report export)")
}

func runDiagnose(cmd *cobra.Command, o Options, f diagnoseFlags, to string, code *int) error {
	p, err := o.NewPolicy(o, newLogger(o), policy.ClientCLI)
	if err != nil {
		return usageErr(err)
	}
	d, err := p.Diagnose(cmd.Context(), policy.DiagnoseArgs{From: f.from, To: to})
	if err != nil {
		return policyErr(err)
	}
	out := cmd.OutOrStdout()
	if f.json {
		if err := writeJSON(out, d); err != nil {
			return internalErr(err)
		}
	} else {
		report.RenderText(out, d)
	}
	if f.report {
		// stderr: with --json, stdout holds the JSON alone.
		if err := saveBundle(cmd.ErrOrStderr(), o, d); err != nil {
			return internalErr(err)
		}
	}
	*code = d.ExitCode()
	return nil
}

func newInspect(o Options) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "inspect host | container NAME | service NAME[@PROJECT] | network NAME",
		Short: "Show the networking facts of the host, a container or a Docker network",
		Args: func(_ *cobra.Command, args []string) error {
			switch {
			case len(args) == 1 && args[0] == "host":
			case len(args) == 2 && (args[0] == "container" || args[0] == "service" || args[0] == "network"):
			default:
				return usageErr(errors.New("want: inspect host | container NAME | service NAME[@PROJECT] | network NAME"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := o.NewPolicy(o, newLogger(o), policy.ClientCLI)
			if err != nil {
				return usageErr(err)
			}
			in, err := p.Inspect(cmd.Context(), strings.Join(args, ":"))
			if err != nil {
				return policyErr(err)
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), in)
			}
			report.RenderInspection(cmd.OutOrStdout(), in)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the facts as JSON")
	return cmd
}

func newProbe(o Options) *cobra.Command {
	var from string
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "probe tcp HOST:PORT | dns NAME | listeners  [--from SOURCE]",
		Short: "Run one check: a TCP connect, a DNS lookup or a listener read, from SOURCE's network namespace",
		Args: func(_ *cobra.Command, args []string) error {
			switch {
			case len(args) == 2 && (args[0] == probe.SpecTCP || args[0] == probe.SpecDNS):
			case len(args) == 1 && args[0] == probe.SpecListeners:
			default:
				return usageErr(errors.New("want: probe tcp HOST:PORT | dns NAME | listeners"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := o.NewPolicy(o, newLogger(o), policy.ClientCLI)
			if err != nil {
				return usageErr(err)
			}
			a := policy.ProbeArgs{Kind: args[0], From: from}
			if len(args) == 2 {
				a.Target = args[1]
			}
			res, err := p.Probe(cmd.Context(), a)
			if err != nil {
				return policyErr(err)
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), res)
			}
			report.RenderProbe(cmd.OutOrStdout(), report.CompactProbe(res, probeHowTo(p)))
			return nil
		},
	}
	cmd.Flags().StringVar(&from, "from", "host", "where the check runs: host, container:<name|id> or service:<name>[@<project>]")
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the evidence as JSON")
	return cmd
}

// probeHowTo is the advice for a check that needs probe containers.
func probeHowTo(p *policy.Policy) func(evidence.Evidence) string {
	return func(e evidence.Evidence) string {
		if e.Err != nil && e.Err.Message == executor.HostHidden {
			return executor.HostHiddenAdvice + "."
		}
		if e.Err != nil && e.Err.Message == executor.PIDsHidden {
			return executor.PIDsHiddenAdvice + "."
		}
		if e.Status != evidence.StatusPermissionDenied {
			return ""
		}
		return "Checks from inside a container need probe containers: set probe_containers = true under [permissions] in " +
			p.ConfigPath() + ", or approve them when an MCP client asks."
	}
}

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// newLogger writes JSON logs to stderr only; stdout carries results and,
// in mcp serve, the MCP protocol. WHYREACH_LOG=debug|info|warn sets the level.
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

// buildPolicy wires the real collaborators from the config file.
func buildPolicy(o Options, logger *slog.Logger, client string) (*policy.Policy, error) {
	path, err := config.Path()
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	deps := policy.Deps{
		Settings:   policy.SettingsFrom(cfg, path),
		Listeners:  procListeners{},
		Interfaces: host.Addrs,
		Host:       executor.NewHost(),
		// The host's own resolvers, read for each batch, since they change
		// (DHCP, VPNs): a probe may ask them even on the block list, for DNS
		// only (INITIAL.md §10 Q13).
		HostResolvers: func() []netip.Addr { return probe.Nameservers(hostResolvConf, systemdResolvConf) },
		Client:        client,
		Deadline:      cfg.Timeouts.Diagnosis.Duration,
		Logger:        logger,
	}
	if auditPath, err := config.AuditPath(); err == nil {
		deps.Audit = policy.NewAudit(auditPath)
	} else {
		logger.Warn("no audit log", "err", err)
	}
	warnForeignDirs(logger)
	if cfg.Permissions.Docker {
		endpoint, err := docker.Endpoint(o.Getenv)
		if err == nil {
			deps.Docker, err = docker.New(endpoint, docker.ReadRoutes())
		}
		if err != nil {
			deps.Docker, deps.DockerErr = nil, err
		} else {
			deps.NewProbe = func() (executor.Executor, error) {
				pc, err := docker.NewProbeClient(endpoint)
				if err != nil {
					return nil, err
				}
				exe, err := os.Executable()
				if err != nil {
					return nil, fmt.Errorf("find whyreach's own binary for the probe image: %w", err)
				}
				return executor.NewProbeContainer(pc, exe, o.Version, logger), nil
			}
			// As root on the host itself, container checks enter the
			// containers' network namespaces: no Docker write (tier 3),
			// unless the config turns it off.
			if ok, _ := platform.Detect().NetnsExecutor(); ok && cfg.Permissions.Netns {
				deps.Netns = executor.NewNetns(deps.Docker, logger)
			}
		}
	}
	// In a container without --network host, whyreach's own network
	// namespace would pass for the host's: host-side checks become
	// unsupported records, which the diagnosis reports as gaps. Without
	// --pid host, containers' PIDs aren't its own to read.
	if platform.Detect().InContainer {
		deps.Self = platform.OwnContainerID()
		v := viewFromContainer(context.Background(), deps.Docker, deps.Self, host.DockerBridgeVisible, "/proc", logger)
		if !v.network {
			hideHost(&deps)
			deps.HostResolvers = nil // its own resolv.conf isn't the host's
		}
		if !v.pids {
			deps.Listeners = hiddenPIDs{deps.Listeners}
		}
	}
	return policy.New(deps)
}

// view is what whyreach, in a container, can see of the host: its network
// namespace (--network host) and its PIDs (--pid host).
type view struct{ network, pids bool }

// viewFromContainer asks Docker about the container whyreach runs in (the
// one whose files are mounted over /etc). Its network is the host's with
// --network host, or when it joins a container that has it; the host's
// PIDs are in sight when Docker's PID for it, a host PID, is in procDir.
// Without Docker's answer, a Docker bridge in sight decides the network
// (the host's namespace has one, a container's own doesn't), and a read
// of a container's PID says for itself whether it worked.
func viewFromContainer(ctx context.Context, dk engine.Docker, ownID string, bridgeVisible func() bool, procDir string, logger *slog.Logger) view {
	if dk != nil && ownID != "" {
		ctx, cancel := context.WithTimeout(ctx, selfInspectTimeout)
		defer cancel()
		self, err := dk.InspectContainer(ctx, ownID)
		netns := self
		if err == nil && self.NetnsOwner() != "" {
			netns, err = dk.InspectContainer(ctx, self.NetnsOwner())
		}
		if err == nil {
			_, perr := os.Stat(filepath.Join(procDir, strconv.Itoa(self.Pid)))
			v := view{network: netns.HostNetwork(), pids: self.Pid > 0 && perr == nil}
			logger.Debug("whyreach's container", "id", evidence.ShortID(ownID), "network_mode", self.NetworkMode, "host_network", v.network, "host_pids", v.pids)
			return v
		}
		logger.Debug("Docker couldn't say what whyreach's container sees of the host", "err", err)
	}
	return view{network: bridgeVisible(), pids: true}
}

// The host's resolver files: its own, and systemd-resolved's list of the
// upstream servers behind its stub, which Docker gives default-bridge
// containers when the first lists only the stub.
const (
	hostResolvConf    = "/etc/resolv.conf"
	systemdResolvConf = "/run/systemd/resolve/resolv.conf"
)

// selfInspectTimeout bounds asking Docker about whyreach's own container.
const selfInspectTimeout = 3 * time.Second

// warnForeignDirs warns when whyreach runs as root but its state and data
// directories belong to another user, as after sudo -E: the root-owned
// files it would write there (the audit log, reports) would lock that user
// out of them.
func warnForeignDirs(logger *slog.Logger) {
	if !platform.Detect().Root {
		return
	}
	for _, dir := range []func() (string, error){config.StateDir, config.DataDir} {
		if d, err := dir(); err == nil && platform.OwnedByOther(d) {
			logger.Warn("running as root with another user's directories (sudo -E?): root-owned files would be written there; use sudo without -E", "dir", d)
		}
	}
}

// hideHost makes the host's side unsupported: its interfaces, its
// listening sockets and checks run from it. Containers' listeners, read
// through /proc/<pid> (with --pid host), stay.
func hideHost(d *policy.Deps) {
	d.Interfaces = func() (evidence.HostAddrs, error) { return evidence.HostAddrs{}, hostHidden{} }
	d.Listeners = hiddenHostListeners{d.Listeners}
	d.Host = executor.Unsupported{Executor: evidence.ExecutorHost, Reason: executor.HostHidden}
}

// hostHidden is the error of a host-side read that can't describe the host.
type hostHidden struct{}

func (hostHidden) Error() string        { return executor.HostHidden }
func (hostHidden) Is(target error) bool { return target == probe.ErrUnsupported }

type hiddenHostListeners struct{ engine.Listeners }

func (hiddenHostListeners) Host() ([]evidence.Socket, error) { return nil, hostHidden{} }

// hiddenPIDs reads no container's listeners: whyreach runs in a container
// without the host's PIDs, so Docker's PIDs aren't ones it can see.
type hiddenPIDs struct{ engine.Listeners }

func (hiddenPIDs) Container(int, string) ([]evidence.Socket, error) { return nil, pidsHidden{} }

// pidsHidden is the error of such a read.
type pidsHidden struct{}

func (pidsHidden) Error() string        { return executor.PIDsHidden }
func (pidsHidden) Is(target error) bool { return target == probe.ErrUnsupported }

// procListeners reads listeners from /proc on the host. The host's own come
// from the reading thread's view (/proc/thread-self): /proc/net shows the
// main thread's namespace, whatever thread reads it.
type procListeners struct{}

func (procListeners) Host() ([]evidence.Socket, error) {
	return probe.ReadListeners("/proc/thread-self")
}

func (procListeners) Container(pid int, id string) ([]evidence.Socket, error) {
	return probe.ContainerListeners(pid, id)
}
