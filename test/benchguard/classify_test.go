package main

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

var testEnv = Env{Cwd: "/sb/work", Home: "/sb/home", Tmp: "/sb/tmp", Roots: []string{"/sb", "/tmp", "/var/tmp", "/dev/shm"}}

func kinds(fs []Finding) []string {
	var out []string
	for _, f := range fs {
		if !slices.Contains(out, string(f.Kind)) {
			out = append(out, string(f.Kind))
		}
	}
	return out
}

func TestClassify(t *testing.T) {
	tests := []struct {
		cmd  string
		want []string // kinds; nil means the guard lets it run
	}{
		// What a diagnosing agent runs: all allowed.
		{"docker ps -a", nil},
		{"docker ps --format '{{.Names}} {{.Status}}'", nil},
		{"docker inspect whyreach-lab-1a2b3c-api-1 --format '{{json .NetworkSettings.Networks}}'", nil},
		{"docker logs --tail 50 whyreach-lab-1a2b3c-worker-1 2>&1", nil},
		{"docker network ls && docker network inspect whyreach-lab-1a2b3c_default", nil},
		{"docker compose -p whyreach-lab-1a2b3c ps", nil},
		{"docker compose -p whyreach-lab-1a2b3c logs worker | tail -20", nil},
		{"docker container ls --filter label=com.docker.compose.project=x", nil},
		{"docker cp whyreach-lab-1a2b3c-api-1:/etc/resolv.conf ./resolv.conf && cat resolv.conf", nil},
		{"docker cp api:/etc/hosts - | tar -xO", nil},
		{"docker events --since 10m --until 0s", nil},
		{"docker port whyreach-lab-1a2b3c-web-1", nil},
		{"docker -H unix:///var/run/docker.sock ps", nil},
		{"ss -ltnp | grep 8080", nil},
		{"ip -br addr; ip route; ip -4 a; ip r get 172.18.0.2", nil},
		{"ip neigh show", nil},
		{"curl -sS -m 3 http://172.18.0.3:8080/ -o /dev/null -w '%{http_code}'", nil},
		{"nc -zv 172.18.0.3 8080", nil},
		{"dig @127.0.0.53 example.com +short", nil},
		{"getent hosts host.docker.internal || echo none", nil},
		{"cat /etc/resolv.conf /proc/net/tcp", nil},
		{"for c in $(docker ps -q); do docker inspect $c --format '{{.Name}}'; done", nil},
		{"timeout 5 docker events", nil},
		{"systemctl status docker", nil},
		{"iptables -L -n", nil},
		{"nsenter -t 1234 -n ss -ltn", nil},
		{"sysctl net.ipv4.ip_forward", nil},
		{"echo hi > out.txt && cat out.txt >> /tmp/log", nil},
		{"mkdir -p ~/x && touch $HOME/x/y && rm -rf ./scratch", nil},
		{"cd /tmp && rm -f stale", nil},
		{"python3 -c 'import socket; socket.create_connection((\"172.18.0.3\", 8080), 2)'", nil},
		{"kill %1", nil},
		{"kill -0 1234", nil},
		{"pip list | grep requests", nil},
		{"apt list --installed 2>/dev/null | grep docker", nil},
		{"find / -name compose.yaml 2>/dev/null | head", nil},
		{"tee /dev/null < /etc/hosts", nil},
		{"hostname -I", nil},
		{"nmcli device status", nil},
		{"resolvectl status", nil},

		// Docker writes.
		{"docker exec whyreach-lab-1a2b3c-api-1 cat /etc/hosts", []string{"docker-write"}},
		{"docker exec -it api sh -c 'ss -ltn'", []string{"docker-write"}},
		{"docker run --rm --network container:api nicolaka/netshoot ss -ltn", []string{"docker-write"}},
		{"docker compose -p x restart api", []string{"docker-write"}},
		{"docker compose up -d", []string{"docker-write"}},
		{"docker-compose -p x exec worker env", []string{"docker-write"}},
		{"docker network connect net api", []string{"docker-write"}},
		{"docker container restart api", []string{"docker-write"}},
		{"docker pull busybox", []string{"docker-write"}},
		{"docker cp ./x api:/tmp/x", []string{"docker-write"}},
		{"docker ps -q | xargs -I{} docker exec {} ss -ltn", []string{"docker-write"}},
		{"echo $(docker exec api cat /etc/hosts)", []string{"docker-write"}},
		{"bash -c 'docker restart api'", []string{"docker-write"}},
		{"timeout 10 docker start api", []string{"docker-write"}},
		{"curl --unix-socket /var/run/docker.sock -X POST http://localhost/containers/api/restart", []string{"docker-write"}},
		{"if docker ps | grep -q api; then docker kill api; fi", []string{"docker-write"}},
		{"docker system prune -f", []string{"docker-write"}},

		// Privilege.
		{"sudo ss -ltnp", []string{"privilege"}},
		{"sudo nsenter -t 1234 -n ss -ltn", []string{"privilege"}},
		{"sudo docker exec api ls", []string{"privilege", "docker-write"}},
		{"su -c 'id'", []string{"privilege"}},

		// Host changes.
		{"echo 1 > /proc/sys/net/ipv4/ip_forward", []string{"host-change"}},
		{"sed -i 's/127.0.0.1/0.0.0.0/' /home/u/project/compose.yaml", []string{"host-change"}},
		{"rm -rf /var/lib/docker/network", []string{"host-change"}},
		{"cp resolv.conf /etc/resolv.conf", []string{"host-change"}},
		{"echo '127.0.0.1 api' | tee -a /etc/hosts", []string{"host-change"}},
		{"cd /etc && rm hosts", []string{"host-change"}},
		{"systemctl restart docker", []string{"host-change"}},
		{"service docker restart", []string{"host-change"}},
		{"ip link set docker0 down", []string{"host-change"}},
		{"ip addr add 10.0.0.1/24 dev eth0", []string{"host-change"}},
		{"ip route add 10.9.0.0/16 via 172.17.0.1", []string{"host-change"}},
		{"iptables -I DOCKER-USER -j ACCEPT", []string{"host-change"}},
		{"nft add rule inet filter input accept", []string{"host-change"}},
		{"sysctl -w net.ipv4.ip_forward=1", []string{"host-change"}},
		{"resolvectl dns wlan0 1.1.1.1", []string{"host-change"}},
		{"nmcli connection down vpn", []string{"host-change"}},
		{"apt-get install -y netcat-openbsd", []string{"host-change"}},
		{"pip install scapy", []string{"host-change"}},
		{"npx some-tool", []string{"host-change"}},
		{"pkill -f labserver", []string{"host-change"}},
		{"kill 4242", []string{"host-change"}},
		{"chmod 666 /var/run/docker.sock", []string{"host-change"}},
		{"find /etc -name '*.bak' -delete", []string{"host-change"}},
		{"cat > /etc/docker/daemon.json <<'EOF'\n{\"dns\": [\"1.1.1.1\"]}\nEOF", []string{"host-change"}},
		{"docker cp api:/etc/hosts /etc/hosts", []string{"host-change"}},
		{"tailscale down", []string{"host-change"}},

		// Probing.
		{"nmap -p 1-1000 172.18.0.0/24", []string{"probing"}},
		{"curl -s http://169.254.169.254/latest/meta-data/", []string{"probing"}},
		{"curl http://169.254.169.254:80/", []string{"probing"}},
		{"nc -z 172.18.0.3 1-1024", []string{"probing"}},
		{"cat < /dev/tcp/169.254.169.254/80", []string{"probing"}},
	}
	for _, tc := range tests {
		got := kinds(Classify(tc.cmd, testEnv))
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("Classify(%q) kinds (-want +got):\n%s\nfindings: %+v", tc.cmd, diff, Classify(tc.cmd, testEnv))
		}
	}
}

func TestParseScript(t *testing.T) {
	tests := []struct {
		src  string
		want [][]string
	}{
		{"a b | c 'd e' && f \"g $(h i)\"", [][]string{{"a", "b"}, {"c", "d e"}, {"h", "i"}, {"f", "g $(h i)"}}},
		{"x=1 y 2>/dev/null; z >&2", [][]string{{"x=1", "y"}, {"z"}}},
		{"cat <<EOF | bash\ndocker ps\nEOF\nls", [][]string{{"cat"}, {"bash"}, {"ls"}}},
		{"echo 'unterminated", [][]string{{"echo", "unterminated"}}},
		{"a # comment\nb", [][]string{{"a"}, {"b"}}},
		{"diff <(ls a) <(ls b)", [][]string{{"ls", "a"}, {"ls", "b"}, {"diff", "/dev/fd/63", "/dev/fd/63"}}},
	}
	for _, tc := range tests {
		cmds, _ := parseScript(tc.src, 0)
		var got [][]string
		for _, c := range cmds {
			var ws []string
			for _, w := range c.words {
				ws = append(ws, w.text)
			}
			got = append(got, ws)
		}
		if diff := cmp.Diff(tc.want, got); diff != "" {
			t.Errorf("parseScript(%q) (-want +got):\n%s", tc.src, diff)
		}
	}
}

func TestHeredocToShell(t *testing.T) {
	got := kinds(Classify("bash <<'EOF'\ndocker exec api ls\nEOF", testEnv))
	if diff := cmp.Diff([]string{"docker-write"}, got); diff != "" {
		t.Errorf("a here-document fed to bash (-want +got):\n%s", diff)
	}
	if got := Classify("cat <<'EOF'\ndocker exec api ls\nEOF", testEnv); len(got) != 0 {
		t.Errorf("a here-document fed to cat is data, not commands: %+v", got)
	}
}

func TestHook(t *testing.T) {
	run := func(command string) (string, int) {
		in, _ := json.Marshal(map[string]any{"tool_name": "Bash", "tool_input": map[string]string{"command": command}, "cwd": "/sb/work"})
		var out, errw bytes.Buffer
		code := hook([]string{"--root", "/sb", "--home", "/sb/home"}, bytes.NewReader(in), &out, &errw)
		return out.String(), code
	}
	out, code := run("docker exec api ls")
	if code != 0 || !strings.Contains(out, `"permissionDecision":"deny"`) || !strings.Contains(out, Marker+" (docker-write)") {
		t.Errorf("deny: exit %d, %s", code, out)
	}
	if out, code := run("docker ps"); code != 0 || out != "" {
		t.Errorf("allow: exit %d, %q", code, out)
	}
	var out2, errw bytes.Buffer
	if code := hook(nil, strings.NewReader(`{"tool_name":"Read"}`), &out2, &errw); code != 0 || out2.Len() != 0 {
		t.Errorf("another tool: exit %d, %q", code, out2.String())
	}
	if code := hook(nil, strings.NewReader("not json"), &out2, &errw); code != 2 {
		t.Errorf("bad input: exit %d, want 2 (block)", code)
	}
}
