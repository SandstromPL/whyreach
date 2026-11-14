// Package platform detects what kind of machine whyreach runs on: its
// privileges, and whether it runs inside a container or WSL2 (INITIAL.md
// §3.7). Host-level evidence describes whyreach's own environment, so these
// decide what that evidence means.
package platform

import (
	"bytes"
	"regexp"
	"strings"
)

// Info is what whyreach knows about where it runs.
type Info struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Root        bool   `json:"root"`
	Netns       bool   `json:"netns"`        // may enter other processes' network namespaces (tier 3: the netns executor)
	Openat2     bool   `json:"openat2"`      // openat2(2) with RESOLVE_IN_ROOT works (Linux 5.6+): the netns executor reads containers' files with it
	InContainer bool   `json:"in_container"` // host checks then describe the container, not the host
	WSL         bool   `json:"wsl"`          // host checks then describe the WSL2 VM, not Windows
}

// NetnsExecutor reports whether container checks can run by entering the
// containers' network namespaces (the netns executor, INITIAL.md §4.7), and
// why not. It needs the privileges (Netns: root, as a rule), and whyreach
// must run on the host itself: inside a container, Docker's PIDs aren't its
// own, and it uses probe containers instead (§3.5). The engine also needs
// Docker Engine on this machine (linux-engine or wsl2-engine), which it
// checks per diagnosis: Docker Desktop's PIDs live in its own VM.
func (i Info) NetnsExecutor() (bool, string) {
	switch {
	case i.OS != "linux":
		return false, "entering a network namespace needs Linux"
	case !i.Netns:
		return false, "it needs root (CAP_SYS_ADMIN and CAP_SYS_PTRACE in the host's user namespace)"
	case i.InContainer:
		return false, "whyreach runs inside a container, where Docker's PIDs are not its own"
	case !i.Openat2:
		return false, "the kernel lacks openat2 (Linux 5.6 or later), which reading a container's files safely needs"
	}
	return true, ""
}

// Platform names (INITIAL.md §3.7, item 4): where Docker runs its
// containers, seen from where whyreach runs.
const (
	LinuxEngine    = "linux-engine"    // Docker Engine on this Linux machine
	WSL2Engine     = "wsl2-engine"     // Docker Engine installed in this WSL2 distro
	WSL2Desktop    = "wsl2-desktop"    // Docker Desktop's WSL integration: the containers run in Docker Desktop's VM
	LinuxDesktop   = "linux-desktop"   // Docker Desktop for Linux: the containers run in its VM (v0.3)
	MacOSDesktop   = "macos-desktop"   // v0.3
	WindowsDesktop = "windows-desktop" // v0.3
	// Other is none of these: no Docker API, a daemon for Windows
	// containers, or whyreach inside a container on Docker Desktop (M7).
	Other = "other"
)

// Daemon is what the Docker daemon says about itself (GET /version). The
// zero value means whyreach couldn't ask it.
type Daemon struct {
	OS       string // "linux"
	Platform string // "Docker Engine - Community", "Docker Desktop 4.50.0 (…)"
	Kernel   string // the daemon's kernel
}

// Desktop reports Docker Desktop's daemon, whose containers live in a VM
// of its own: its PIDs are processes in that VM.
func (d Daemon) Desktop() bool { return strings.Contains(d.Platform, "Desktop") }

// Classify names the platform from where whyreach runs and what the daemon
// says (INITIAL.md §3.7, item 4). Only Docker Engine on whyreach's own
// machine (LinuxEngine, WSL2Engine) runs containers whose PIDs are
// whyreach's to read; see EngineHere.
//
// WSL2 comes from Info.WSL, which needs more than the kernel's name. The
// one exception: whyreach inside a container, which can't see WSL's
// marker, on Docker Engine whose kernel is WSL2's (Docker Engine in a WSL2
// distro: Docker Desktop's daemon says so in its name). Its view of the
// host, when it has one (--network host), is the WSL2 VM's.
func Classify(i Info, d Daemon) string {
	if d.OS != "linux" {
		return Other
	}
	desktop := d.Desktop()
	switch i.OS {
	case "linux":
		switch {
		case i.WSL && desktop:
			return WSL2Desktop
		case i.WSL:
			return WSL2Engine
		case i.InContainer && desktop:
			return Other
		case desktop:
			return LinuxDesktop
		case i.InContainer && wslKernel(d.Kernel):
			return WSL2Engine
		default:
			return LinuxEngine
		}
	case "darwin":
		if desktop {
			return MacOSDesktop
		}
	case "windows":
		if desktop {
			return WindowsDesktop
		}
	}
	return Other
}

// EngineHere reports a platform where Docker Engine runs on whyreach's own
// machine (a Linux host or a WSL2 distro), so Docker's PIDs are processes
// in whyreach's /proc: listeners can be read through /proc/<pid>, and as
// root the netns executor can enter them. Everywhere else a PID from
// Docker names a process in another machine's or VM's PID namespace, and a
// /proc/<pid> read or setns would reach an unrelated local process.
func EngineHere(name string) bool { return name == LinuxEngine || name == WSL2Engine }

// wslKernel reports a kernel release with WSL's marker: current WSL2
// kernels end in -microsoft-standard-WSL2. Only a hint: containers on a
// WSL2 kernel report it too, and a custom kernel may not.
func wslKernel(release string) bool {
	return strings.Contains(strings.ToLower(release), "microsoft")
}

// WSL's marker files: the interop entry WSL registers with binfmt_misc to
// run Windows programs, under either name (with systemd, WSL registers it
// again as WSLInterop-late).
var wslInterop = []string{"/proc/sys/fs/binfmt_misc/WSLInterop", "/proc/sys/fs/binfmt_misc/WSLInterop-late"}

// environment decides, from the files Detect reads, whether whyreach runs
// inside a container or in a WSL2 distro. read and exists read the real
// filesystem, or a test's fixtures.
//
// A container runtime in PID 1's cgroup settles "container". Otherwise
// WSL2 needs its kernel's name to say microsoft (only a hint: containers
// on a WSL2 kernel say so too) and WSL's interop entry, which WSL's own
// init registers and containers don't see (binfmt_misc isn't mounted in
// them; INITIAL.md §3.7, item 4). Docker's /.dockerenv and Podman's
// /run/.containerenv mark a container only without that entry: a distro
// imported with wsl --import from a docker export keeps the export's
// /.dockerenv.
func environment(read func(string) ([]byte, error), exists func(string) bool) (inContainer, wsl bool) {
	if b, err := read("/proc/1/cgroup"); err == nil && (bytes.Contains(b, []byte("docker")) || bytes.Contains(b, []byte("containerd"))) {
		return true, false
	}
	if b, err := read("/proc/sys/kernel/osrelease"); err == nil && wslKernel(string(b)) {
		for _, f := range wslInterop {
			if exists(f) {
				return false, true
			}
		}
	}
	return exists("/.dockerenv") || exists("/run/.containerenv"), false
}

// containerFile matches a file Docker mounts into a container from the
// container's own directory: <data-root>/containers/<id>/resolv.conf,
// hostname or hosts.
var containerFile = regexp.MustCompile(`/containers/([0-9a-f]{64})/(?:resolv\.conf|hostname|hosts)$`)

// containerIDFrom finds the ID of the Docker container whose resolv.conf,
// hostname or hosts file is mounted over /etc, in a mountinfo listing
// (proc_pid_mountinfo(5): the fourth field is the mount's root within its
// filesystem, the fifth its mount point). It returns "" when there is none.
func containerIDFrom(mountinfo string) string {
	for line := range strings.Lines(mountinfo) {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		switch f[4] {
		case "/etc/resolv.conf", "/etc/hostname", "/etc/hosts":
			if m := containerFile.FindStringSubmatch(f[3]); m != nil {
				return m[1]
			}
		}
	}
	return ""
}
