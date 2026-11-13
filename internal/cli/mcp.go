package cli

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"

	"github.com/spf13/cobra"

	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/platform"
	"github.com/SandstromPL/whyreach/internal/policy"
)

// MCPOptions are what `mcp serve` hands the MCP server, which main wires
// in (Options.ServeMCP): nothing imports the mcpserver package but main.
type MCPOptions struct {
	Version       string
	Logger        *slog.Logger
	In            io.Reader // the protocol arrives here
	Out           io.Writer // and leaves here: nothing else may write to it
	ReportsDir    string
	RedactPrivate bool
}

func newMCP(o Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "mcp",
		Short: "Serve whyreach's tools to MCP clients",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "Serve diagnose_connection, inspect_environment, run_probe and save_report over stdio",
		Long: `Serve whyreach's four MCP tools over stdio. stdout carries the protocol;
logs go to stderr (WHYREACH_LOG=debug|info|warn).

Add it to Claude Code with:
  claude mcp add whyreach -- /absolute/path/to/whyreach mcp serve`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if o.ServeMCP == nil {
				return internalErr(errors.New("this build has no MCP server"))
			}
			logger := newLogger(o)
			if platform.Detect().Root {
				logger.Warn("the MCP server runs as root: prefer a regular user, and keep root for the CLI (an agent's tool calls then run with root's privileges, within the probe policy)")
			}
			p, err := o.NewPolicy(o, logger, policy.ClientMCP)
			if err != nil {
				return usageErr(err)
			}
			mo := MCPOptions{Version: o.Version, Logger: logger, In: o.Stdin, Out: o.Stdout}
			if mo.In == nil {
				mo.In = os.Stdin
			}
			if dir, err := config.ReportsDir(); err == nil {
				mo.ReportsDir = dir
			}
			if path, err := config.Path(); err == nil {
				if cfg, err := config.Load(path); err == nil {
					mo.RedactPrivate = cfg.Report.RedactPrivate
				}
			}
			if err := o.ServeMCP(cmd.Context(), p, mo); err != nil && !errors.Is(err, context.Canceled) && cmd.Context().Err() == nil {
				return internalErr(err)
			}
			return nil
		},
	})
	return cmd
}
