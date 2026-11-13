// Command whyreach diagnoses container and host network connectivity,
// read-only. See INITIAL.md for the design and CLAUDE.md for the rules.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/SandstromPL/whyreach/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := cli.Execute(ctx, os.Args[1:], cli.Options{Version: version, Stdout: os.Stdout, Stderr: os.Stderr, Getenv: os.Getenv})
	stop()
	os.Exit(code)
}
