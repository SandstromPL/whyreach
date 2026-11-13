package config

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	c, err := Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Permissions.Docker || c.Permissions.ProbeContainers || !c.Permissions.Netns || c.Timeouts.Diagnosis.Duration != 15*time.Second {
		t.Errorf("defaults = %+v", c)
	}

	full := `
[permissions]
docker = true
probe_containers = true        # tier 2b

[probe]
allow = ["loopback", "rfc1918", "docker"]
rate_per_minute = 30
names = ["Example.COM.", "corp.example"]

[timeouts]
diagnosis = "10s"

[report]
redact_private = false
`
	c, err = Load(write(t, full))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Permissions.ProbeContainers || c.Timeouts.Diagnosis.Duration != 10*time.Second {
		t.Errorf("loaded = %+v", c)
	}
	if want := []string{"example.com", "corp.example"}; !slices.Equal(c.Probe.Names, want) {
		t.Errorf("names = %q, want %q (folded)", c.Probe.Names, want)
	}
	if d := Default(); len(d.Probe.Names) != 0 {
		t.Errorf("by default no domain is covered: %q", d.Probe.Names)
	}

	c, err = Load(write(t, "[permissions]\nprobe_containers = true\n"))
	if err != nil || !c.Permissions.Docker || !c.Permissions.ProbeContainers || !c.Permissions.Netns {
		t.Errorf("a partial file keeps the other defaults: %+v, %v", c, err)
	}

	c, err = Load(write(t, "[permissions]\nnetns = false\n"))
	if err != nil || c.Permissions.Netns || !c.Permissions.Docker {
		t.Errorf("netns = false turns only the netns executor off: %+v, %v", c, err)
	}
}

func TestLoadRejects(t *testing.T) {
	tests := map[string]string{
		"typo":           "[permissions]\nprobe_container = true\n",
		"unknown table":  "[perms]\ndocker = true\n",
		"bad duration":   "[timeouts]\ndiagnosis = \"soon\"\n",
		"deadline short": "[timeouts]\ndiagnosis = \"1s\"\n",
		"deadline long":  "[timeouts]\ndiagnosis = \"5m\"\n",
		"not toml":       "permissions: {docker: true}\n",
		"wrong type":     "[permissions]\nprobe_containers = \"yes\"\n",
		"bad allow":      "[probe]\nallow = [\"lan\"]\n",
		"bad CIDR":       "[probe]\nallow = [\"10.0.0.0/33\"]\n",
		"zero rate":      "[probe]\nrate_per_minute = 0\n",
		"huge rate":      "[probe]\nrate_per_minute = 100000\n",
		"name wildcard":  "[probe]\nnames = [\"*.example.com\"]\n",
		"name address":   "[probe]\nnames = [\"10.0.0.1\"]\n",
		"name with port": "[probe]\nnames = [\"example.com:53\"]\n",
		"empty name":     "[probe]\nnames = [\"\"]\n",
		"names a string": "[probe]\nnames = \"example.com\"\n",
		"name a TLD":     "[probe]\nnames = [\"com\"]\n",
	}
	for name, content := range tests {
		if _, err := Load(write(t, content)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
	_, err := Load(write(t, "[permissions]\nprobe_container = true\n"))
	if err == nil || !strings.Contains(err.Error(), "permissions.probe_container") {
		t.Errorf("the error should name the unknown key: %v", err)
	}
}

func TestPath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/tmp/xdg")
	p, err := Path()
	if err != nil {
		t.Fatal(err)
	}
	if want := "/tmp/xdg/whyreach/config.toml"; runtime.GOOS == "linux" && p != want {
		t.Errorf("Path() = %q, want %q", p, want)
	}
}

func TestAllowPrefixes(t *testing.T) {
	tests := map[string]int{"loopback": 2, "RFC1918": 3, "docker": 0, "100.64.0.0/10": 1, "192.168.1.50": 1, "fd00::/8": 1}
	for entry, n := range tests {
		got, err := AllowPrefixes(entry)
		if err != nil || len(got) != n {
			t.Errorf("AllowPrefixes(%q) = %v, %v; want %d prefixes", entry, got, err, n)
		}
	}
	if got, _ := AllowPrefixes("192.168.1.50"); got[0].String() != "192.168.1.50/32" {
		t.Errorf("an address is a /32: %v", got)
	}
	if _, err := AllowPrefixes("everything"); err == nil {
		t.Error("an unknown class must be rejected")
	}
}

func TestDirs(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("XDG directories are Linux's")
	}
	t.Setenv("XDG_STATE_HOME", "/tmp/xdg-state")
	t.Setenv("XDG_DATA_HOME", "relative/ignored")
	t.Setenv("HOME", "/home/someone")
	if p, _ := AuditPath(); p != "/tmp/xdg-state/whyreach/audit.jsonl" {
		t.Errorf("AuditPath() = %q", p)
	}
	if p, _ := ReportsDir(); p != "/home/someone/.local/share/whyreach/reports" {
		t.Errorf("ReportsDir() = %q (a relative XDG_DATA_HOME must be ignored)", p)
	}
}
