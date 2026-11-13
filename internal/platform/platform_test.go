package platform

import (
	"os"
	"runtime"
	"testing"
)

func TestDetect(t *testing.T) {
	i := Detect()
	if i.OS != runtime.GOOS || i.Arch != runtime.GOARCH {
		t.Errorf("Detect() = %+v", i)
	}
	if os.Geteuid() != 0 && i.Netns {
		t.Errorf("Detect() = %+v: a regular user can't enter network namespaces", i)
	}
}

func TestNetnsExecutor(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want bool
	}{
		{"root on a Linux host", Info{OS: "linux", Root: true, Netns: true}, true},
		{"capabilities without root", Info{OS: "linux", Netns: true}, true},
		{"a regular user", Info{OS: "linux"}, false},
		{"root without the capabilities", Info{OS: "linux", Root: true}, false},
		{"root inside a container", Info{OS: "linux", Root: true, Netns: true, InContainer: true}, false},
		{"macOS", Info{OS: "darwin", Root: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, why := tt.info.NetnsExecutor()
			if got != tt.want || (got == (why != "")) {
				t.Errorf("NetnsExecutor() = %v, %q; want %v and a reason exactly when false", got, why, tt.want)
			}
		})
	}
}
