//go:build !linux

package main

import (
	"fmt"
	"os"
)

// The sandbox needs bwrap and seccomp: Linux only, like the benchmark.
func shell([]string) int {
	fmt.Fprintln(os.Stderr, "benchguard shell: the sandbox runs on Linux only")
	return 126
}
