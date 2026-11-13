package platform

import (
	"os"
	"runtime"
	"strings"
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
	if runtime.GOOS == "linux" && !i.Openat2 {
		t.Logf("openat2 is unavailable here: the netns executor would stay off")
	}
}

func TestNetnsExecutor(t *testing.T) {
	tests := []struct {
		name string
		info Info
		want bool
	}{
		{"root on a Linux host", Info{OS: "linux", Root: true, Netns: true, Openat2: true}, true},
		{"capabilities without root", Info{OS: "linux", Netns: true, Openat2: true}, true},
		{"a regular user", Info{OS: "linux", Openat2: true}, false},
		{"root without the capabilities", Info{OS: "linux", Root: true, Openat2: true}, false},
		{"root inside a container", Info{OS: "linux", Root: true, Netns: true, InContainer: true, Openat2: true}, false},
		{"root on a kernel without openat2", Info{OS: "linux", Root: true, Netns: true}, false},
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

func TestContainerIDFrom(t *testing.T) {
	id := strings.Repeat("0123456789abcdef", 4)
	tests := map[string]struct {
		mountinfo string
		want      string
	}{
		"Docker": {
			"1063 1040 0:120 / / rw,relatime master:426 - overlay overlay rw\n" +
				"1072 1063 259:2 /var/lib/docker/containers/" + id + "/resolv.conf /etc/resolv.conf rw,relatime - ext4 /dev/nvme0n1p2 rw\n" +
				"1073 1063 259:2 /var/lib/docker/containers/" + id + "/hostname /etc/hostname rw,relatime - ext4 /dev/nvme0n1p2 rw\n",
			id,
		},
		"Docker's data-root on a filesystem of its own": {
			"1074 1063 259:3 /containers/" + id + "/hosts /etc/hosts rw,relatime - ext4 /dev/sdb1 rw\n", id,
		},
		"the host": {"22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw\n", ""},
		"a container's directory mounted elsewhere": {
			"1080 1063 259:2 /var/lib/docker/containers/" + id + "/resolv.conf /data/resolv.conf rw - ext4 /dev/nvme0n1p2 rw\n", "",
		},
		"Podman": {
			"1090 1063 0:44 /containers/storage/overlay-containers/" + id + "/userdata/resolv.conf /etc/resolv.conf rw - tmpfs tmpfs rw\n", "",
		},
	}
	for name, tt := range tests {
		if got := containerIDFrom(tt.mountinfo); got != tt.want {
			t.Errorf("%s: %q, want %q", name, got, tt.want)
		}
	}
}
