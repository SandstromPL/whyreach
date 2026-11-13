// Command whyreach diagnoses container and host network connectivity.
//
// Milestone M0: only `whyreach version` exists. The real CLI and the MCP
// server arrive in M1 and M2 (see INITIAL.md §7).
package main

import (
	"fmt"
	"io"
	"os"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

// Exit codes from INITIAL.md §4.11.
const (
	exitOK    = 0
	exitUsage = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "version" || args[0] == "--version") {
		fmt.Fprintf(stdout, "whyreach %s\n", version)
		return exitOK
	}
	fmt.Fprintln(stderr, "whyreach: nothing here yet (milestone M0). Try `whyreach version`.")
	return exitUsage
}
