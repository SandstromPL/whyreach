// Command whyreach diagnoses container and host network connectivity,
// read-only. See INITIAL.md for the design and CLAUDE.md for the rules.
// main wires the two front ends, the CLI and the MCP server; nothing else
// imports either (INITIAL.md §4.1).
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/SandstromPL/whyreach/internal/cli"
	"github.com/SandstromPL/whyreach/internal/mcpserver"
	"github.com/SandstromPL/whyreach/internal/policy"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], cli.Options{
		Version: version, Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv,
		ServeMCP: serveMCP,
	})
	stop()
	os.Exit(code)
}

// serveMCP runs whyreach's MCP server over the given streams.
func serveMCP(ctx context.Context, p *policy.Policy, o cli.MCPOptions) error {
	s := mcpserver.New(p, mcpserver.Options{
		Version: o.Version, Logger: o.Logger, ReportsDir: o.ReportsDir, RedactPrivate: o.RedactPrivate,
	})
	return s.Run(ctx, &mcp.IOTransport{Reader: io.NopCloser(o.In), Writer: nopCloser{o.Out}})
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
