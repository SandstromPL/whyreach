// Package config loads whyreach's config file,
// $XDG_CONFIG_HOME/whyreach/config.toml (INITIAL.md §4.13), and names
// whyreach's own directories (§4.15). Permission tiers come from here (or
// from the user's answer to an MCP elicitation), never from arguments an
// agent supplies.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the file's content. [report] is accepted so that a complete
// config file loads; report bundles use it from M4.
type Config struct {
	Permissions Permissions `toml:"permissions"`
	Probe       Probe       `toml:"probe"`
	Timeouts    Timeouts    `toml:"timeouts"`
	Report      Report      `toml:"report"`
}

// Permissions are the permission tiers the user enables (INITIAL.md §4.9).
type Permissions struct {
	Docker          bool `toml:"docker"`           // tier 2a: read Docker metadata
	ProbeContainers bool `toml:"probe_containers"` // tier 2b: ephemeral probe containers
	// Netns lets whyreach, when it runs as root, enter containers' network
	// namespaces itself (tier 3, the netns executor). Root's privilege is
	// what turns tier 3 on; false keeps it off even then.
	Netns bool `toml:"netns"`
}

// Probe narrows probe targets (INITIAL.md §4.9). Allow lists the address
// classes ("loopback", "rfc1918", "docker") and CIDRs that TCP probes may
// connect to; an empty list means any address the block list allows.
type Probe struct {
	Allow         []string `toml:"allow"`
	RatePerMinute int      `toml:"rate_per_minute"`
}

// Probe allowlist classes.
const (
	AllowLoopback = "loopback" // 127.0.0.0/8 and ::1
	AllowRFC1918  = "rfc1918"  // 10/8, 172.16/12, 192.168/16
	AllowDocker   = "docker"   // the subnets of Docker's networks, read when a probe runs
)

// Rate limit bounds.
const (
	DefaultRate = 30
	maxRate     = 600
)

// Timeouts bound the work.
type Timeouts struct {
	Diagnosis Duration `toml:"diagnosis"`
}

// Report controls report bundles (from M4).
type Report struct {
	RedactPrivate bool `toml:"redact_private"`
}

// Duration is a time.Duration written as "15s" in TOML.
type Duration struct{ time.Duration }

// UnmarshalText parses a Go duration string.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// Diagnosis deadline bounds (INITIAL.md §3.6: 15 s by default).
const (
	DefaultDiagnosis = 15 * time.Second
	minDiagnosis     = 3 * time.Second
	maxDiagnosis     = 60 * time.Second
)

// Default is the configuration without a file: Docker metadata on, probe
// containers off, and the netns executor allowed when whyreach runs as root.
func Default() Config {
	return Config{
		Permissions: Permissions{Docker: true, ProbeContainers: false, Netns: true},
		Probe:       Probe{Allow: []string{AllowLoopback, AllowRFC1918, AllowDocker}, RatePerMinute: DefaultRate},
		Timeouts:    Timeouts{Diagnosis: Duration{DefaultDiagnosis}},
	}
}

// Path is the config file's location: $XDG_CONFIG_HOME/whyreach/config.toml
// on Linux (~/.config when unset), and the platform's user config directory
// elsewhere.
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("find the config directory: %w", err)
	}
	return filepath.Join(dir, "whyreach", "config.toml"), nil
}

// Load reads a config file. A missing file gives Default. Unknown keys are
// an error, so a typo can't silently leave a setting at its default.
func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path) //nolint:gosec // G304: the path is the user's own config file
	if errors.Is(err, fs.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	md, err := toml.Decode(string(b), &c)
	if err != nil {
		return c, fmt.Errorf("parse %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		var keys []string
		for _, k := range undecoded {
			keys = append(keys, k.String())
		}
		slices.Sort(keys)
		return c, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	if d := c.Timeouts.Diagnosis.Duration; d < minDiagnosis || d > maxDiagnosis {
		return c, fmt.Errorf("%s: timeouts.diagnosis must be between %s and %s, got %s", path, minDiagnosis, maxDiagnosis, d)
	}
	for _, a := range c.Probe.Allow {
		if _, err := AllowPrefixes(a); err != nil {
			return c, fmt.Errorf("%s: probe.allow: %w", path, err)
		}
	}
	if r := c.Probe.RatePerMinute; r < 1 || r > maxRate {
		return c, fmt.Errorf("%s: probe.rate_per_minute must be between 1 and %d, got %d", path, maxRate, r)
	}
	return c, nil
}

// AllowPrefixes returns the addresses an allowlist entry stands for: a
// class's fixed ranges, a CIDR, or a single address. "docker" stands for
// subnets only known at run time, so it returns none.
func AllowPrefixes(entry string) ([]netip.Prefix, error) {
	switch strings.ToLower(strings.TrimSpace(entry)) {
	case AllowLoopback:
		return []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("::1/128")}, nil
	case AllowRFC1918:
		return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("192.168.0.0/16")}, nil
	case AllowDocker:
		return nil, nil
	}
	if p, err := netip.ParsePrefix(entry); err == nil {
		return []netip.Prefix{p.Masked()}, nil
	}
	if a, err := netip.ParseAddr(entry); err == nil {
		a = a.Unmap()
		return []netip.Prefix{netip.PrefixFrom(a, a.BitLen())}, nil
	}
	return nil, fmt.Errorf("%q is not loopback, rfc1918, docker, a CIDR or an address", entry)
}

// StateDir is whyreach's state directory, which holds the audit log:
// $XDG_STATE_HOME/whyreach (~/.local/state/whyreach) on Linux, and the user's
// application data directory elsewhere (INITIAL.md §4.15).
func StateDir() (string, error) { return xdgDir("XDG_STATE_HOME", ".local/state") }

// DataDir is whyreach's data directory, which holds report bundles:
// $XDG_DATA_HOME/whyreach (~/.local/share/whyreach) on Linux.
func DataDir() (string, error) { return xdgDir("XDG_DATA_HOME", ".local/share") }

// AuditPath is the audit log's location (INITIAL.md §4.9).
func AuditPath() (string, error) {
	dir, err := StateDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "audit.jsonl"), nil
}

// ReportsDir is where report bundles go (INITIAL.md §4.12).
func ReportsDir() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "reports"), nil
}

func xdgDir(env, fallback string) (string, error) {
	if runtime.GOOS != "linux" {
		// macOS: ~/Library/Application Support; Windows: %AppData%. There is
		// no separate state directory on either.
		dir, err := os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("find the user data directory: %w", err)
		}
		return filepath.Join(dir, "whyreach"), nil
	}
	if dir := os.Getenv(env); filepath.IsAbs(dir) { // the XDG spec ignores relative paths
		return filepath.Join(dir, "whyreach"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("find the home directory: %w", err)
	}
	return filepath.Join(home, fallback, "whyreach"), nil
}
