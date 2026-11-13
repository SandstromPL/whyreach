// Package platform detects what kind of machine whyreach runs on: its
// privileges, and whether it runs inside a container or WSL2 (INITIAL.md
// §3.7). Host-level evidence describes whyreach's own environment, so these
// decide what that evidence means.
package platform

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
// own, and it uses probe containers instead (§3.5). The engine also needs a
// Linux Docker Engine on this machine, which it checks per diagnosis.
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
