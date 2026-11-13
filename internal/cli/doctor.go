package cli

import (
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/policy"
	"github.com/SandstromPL/whyreach/internal/report"
)

// doctorReport is doctor's JSON output.
type doctorReport struct {
	Version string         `json:"version"`
	OK      bool           `json:"ok"` // nothing failed
	Checks  []engine.Check `json:"checks"`
}

func newDoctor(o Options, code *int) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check what whyreach can do here: config, Docker, listeners, probe containers, audit log",
		Long: `Check whyreach's own setup: the config file, the Docker API, reading host and
container listeners, probe containers (tier 2b), the probe policy, privileges
and the audit log. It changes nothing.

Exit codes: 0 nothing failed, 1 something failed, 3 usage error, 4 internal error.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			r := doctorReport{Version: o.Version, OK: true}
			cfg := engine.Check{Name: "config", Status: engine.CheckOK}
			path, err := config.Path()
			if err == nil {
				cfg.Detail = path
				if _, serr := os.Stat(path); serr != nil {
					cfg.Detail += " (none: the defaults apply, with probe containers off)"
				}
				_, err = config.Load(path)
			}
			if err != nil {
				cfg.Status, cfg.Detail = engine.CheckFail, err.Error()
				cfg.Fix = "Fix the file: an unknown key or a bad value is an error, so that a typo can't leave a permission at its default."
			}
			r.Checks = append(r.Checks, engine.Check{Name: "whyreach", Status: engine.CheckInfo,
				Detail: fmt.Sprintf("%s (%s/%s, %s)", o.Version, runtime.GOOS, runtime.GOARCH, runtime.Version())}, cfg)
			if cfg.Status != engine.CheckFail {
				p, err := o.NewPolicy(o, newLogger(o), policy.ClientCLI)
				if err != nil {
					return usageErr(err)
				}
				r.Checks = append(r.Checks, p.Doctor(cmd.Context())...)
			}
			switch exe, err := os.Executable(); {
			case platform.Detect().InContainer:
				r.Checks = append(r.Checks, engine.Check{Name: "mcp", Status: engine.CheckInfo,
					Detail: "add the image to Claude Code: claude mcp add whyreach -- docker run --rm -i --network host --pid host -v /var/run/docker.sock:/var/run/docker.sock IMAGE mcp serve"})
			case err == nil:
				r.Checks = append(r.Checks, engine.Check{Name: "mcp", Status: engine.CheckInfo,
					Detail: "add it to Claude Code: claude mcp add whyreach -- " + exe + " mcp serve"})
			}
			for _, c := range r.Checks {
				if c.Status == engine.CheckFail {
					r.OK = false
					*code = 1
				}
			}
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), r)
			}
			renderDoctor(cmd.OutOrStdout(), r)
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the checks as JSON")
	return cmd
}

func renderDoctor(w io.Writer, r doctorReport) {
	var b strings.Builder
	marks := map[string]string{engine.CheckOK: "✓", engine.CheckWarn: "!", engine.CheckFail: "✗", engine.CheckInfo: "·"}
	for _, c := range r.Checks {
		fmt.Fprintf(&b, "%s %-20s %s\n", marks[c.Status], c.Name, c.Detail)
		if c.Fix != "" {
			fmt.Fprintf(&b, "  %-20s → %s\n", "", c.Fix)
		}
	}
	if r.OK {
		b.WriteString("\nwhyreach is ready.\n")
	} else {
		b.WriteString("\nSome checks failed; see above.\n")
	}
	_, _ = io.WriteString(w, report.Sanitize(b.String()))
}
