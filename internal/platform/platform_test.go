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

// fixture is a filesystem for environment: file contents, and paths that
// exist without contents worth reading.
type fixture map[string]string

func (f fixture) read(path string) ([]byte, error) {
	if s, ok := f[path]; ok {
		return []byte(s), nil
	}
	return nil, os.ErrNotExist
}

func (f fixture) exists(path string) bool { _, ok := f[path]; return ok }

func TestEnvironment(t *testing.T) {
	const (
		wslKernel    = "6.6.87.2-microsoft-standard-WSL2\n"
		ubuntuKernel = "6.8.0-87-generic\n"
		interop      = "enabled\ninterpreter /init\nflags: PF\noffset 0\nmagic 4d5a\n"
	)
	tests := []struct {
		name                string
		files               fixture
		inContainer, wslOut bool
	}{
		{"a Linux host", fixture{"/proc/sys/kernel/osrelease": ubuntuKernel, "/proc/1/cgroup": "0::/init.scope\n"}, false, false},
		{"a WSL2 distro", fixture{"/proc/sys/kernel/osrelease": wslKernel, "/proc/sys/fs/binfmt_misc/WSLInterop": interop, "/proc/1/cgroup": "0::/\n"}, false, true},
		{"a WSL2 distro with systemd (WSLInterop-late)", fixture{"/proc/sys/kernel/osrelease": wslKernel, "/proc/sys/fs/binfmt_misc/WSLInterop-late": interop, "/proc/1/cgroup": "0::/init.scope\n"}, false, true},
		{"a WSL kernel without WSL's interop entry: only a hint", fixture{"/proc/sys/kernel/osrelease": wslKernel}, false, false},
		{"WSL's interop entry on another kernel", fixture{"/proc/sys/kernel/osrelease": ubuntuKernel, "/proc/sys/fs/binfmt_misc/WSLInterop": interop}, false, false},
		{"a Docker container on a WSL2 kernel", fixture{"/proc/sys/kernel/osrelease": wslKernel, "/.dockerenv": "", "/proc/1/cgroup": "0::/\n"}, true, false},
		{"a WSL2 distro imported from a docker export keeps its /.dockerenv", fixture{"/proc/sys/kernel/osrelease": wslKernel, "/.dockerenv": "", "/proc/sys/fs/binfmt_misc/WSLInterop": interop, "/proc/1/cgroup": "0::/init.scope\n"}, false, true},
		{"a container found by its cgroup, WSL's entry or not", fixture{"/proc/sys/kernel/osrelease": wslKernel, "/proc/sys/fs/binfmt_misc/WSLInterop": interop, "/proc/1/cgroup": "0::/system.slice/docker-" + strings.Repeat("ab", 32) + ".scope\n"}, true, false},
		{"a Podman container", fixture{"/proc/sys/kernel/osrelease": ubuntuKernel, "/run/.containerenv": ""}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in, wsl := environment(tt.files.read, tt.files.exists)
			if in != tt.inContainer || wsl != tt.wslOut {
				t.Errorf("environment() = container %v, WSL %v; want %v, %v", in, wsl, tt.inContainer, tt.wslOut)
			}
		})
	}
}

func TestClassify(t *testing.T) {
	engine := Daemon{OS: "linux", Platform: "Docker Engine - Community", Kernel: "6.8.0-87-generic"}
	wslEngine := Daemon{OS: "linux", Platform: "Docker Engine - Community", Kernel: "6.6.87.2-microsoft-standard-WSL2"}
	desktop := Daemon{OS: "linux", Platform: "Docker Desktop 4.50.0 (209931)", Kernel: "6.6.87.2-microsoft-standard-WSL2"}
	linuxDesktop := Daemon{OS: "linux", Platform: "Docker Desktop 4.50.0 (209931)", Kernel: "6.10.14-linuxkit"}
	windowsContainers := Daemon{OS: "windows", Platform: "Docker Desktop 4.50.0 (209931)"}
	host := Info{OS: "linux"}
	wsl := Info{OS: "linux", WSL: true}
	ctr := Info{OS: "linux", InContainer: true}
	tests := []struct {
		name string
		info Info
		d    Daemon
		want string
		here bool
	}{
		{"Docker Engine on a Linux host", host, engine, LinuxEngine, true},
		{"Docker Engine in a WSL2 distro", wsl, wslEngine, WSL2Engine, true},
		{"Docker Desktop's WSL integration", wsl, desktop, WSL2Desktop, false},
		{"Docker Desktop's WSL integration, root in the distro", Info{OS: "linux", WSL: true, Root: true, Netns: true, Openat2: true}, desktop, WSL2Desktop, false},
		{"Docker Desktop for Linux", host, linuxDesktop, LinuxDesktop, false},
		{"a WSL kernel but no WSL marker (interop off): not WSL2", host, wslEngine, LinuxEngine, true},
		{"whyreach's image on Docker Engine in a WSL2 distro", ctr, wslEngine, WSL2Engine, true},
		{"whyreach's image on Docker Engine", ctr, engine, LinuxEngine, true},
		{"whyreach's image on Docker Desktop", ctr, desktop, Other, false},
		{"no Docker API", wsl, Daemon{}, Other, false},
		{"Windows containers", Info{OS: "windows"}, windowsContainers, Other, false},
		{"macOS with Docker Desktop", Info{OS: "darwin"}, linuxDesktop, MacOSDesktop, false},
		{"Windows with Docker Desktop", Info{OS: "windows"}, desktop, WindowsDesktop, false},
		{"macOS with a remote Docker Engine", Info{OS: "darwin"}, engine, Other, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Classify(tt.info, tt.d)
			if got != tt.want || EngineHere(got) != tt.here {
				t.Errorf("Classify() = %q (Docker's PIDs here: %v), want %q (%v)", got, EngineHere(got), tt.want, tt.here)
			}
		})
	}
}
