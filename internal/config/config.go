// Package config loads whyreach's config file,
// $XDG_CONFIG_HOME/whyreach/config.toml (INITIAL.md §4.13). Permission tiers
// come from here (or, from M2, from MCP elicitation), never from arguments an
// agent supplies.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Config is the file's content. Only [permissions] and [timeouts] are used
// in v0.1 M1; the other documented sections are accepted so that a complete
// config file doesn't fail to load.
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
}

// Probe narrows probe targets (from M2).
type Probe struct {
	Allow         []string `toml:"allow"`
	RatePerMinute int      `toml:"rate_per_minute"`
}

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
// containers off.
func Default() Config {
	return Config{
		Permissions: Permissions{Docker: true, ProbeContainers: false},
		Probe:       Probe{Allow: []string{"loopback", "rfc1918", "docker"}, RatePerMinute: 30},
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
	return c, nil
}
