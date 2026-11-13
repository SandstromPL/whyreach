// Package platform detects what kind of machine whyreach runs on: its
// privileges, and whether it runs inside a container or WSL2 (INITIAL.md
// §3.7). Host-level evidence describes whyreach's own environment, so these
// decide what that evidence means.
package platform

// Info is what whyreach knows about where it runs.
type Info struct {
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	Root        bool   `json:"root"`         // tier 3 (the netns executor, M3) needs it
	InContainer bool   `json:"in_container"` // host checks then describe the container, not the host
	WSL         bool   `json:"wsl"`          // host checks then describe the WSL2 VM, not Windows
}
