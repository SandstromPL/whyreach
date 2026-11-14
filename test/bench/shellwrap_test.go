package bench

import "testing"

func TestAgentCommand(t *testing.T) {
	const pre = `source /x/snapshot.sh 2>/dev/null || true && { \builtin unalias -- 'which'; } >/dev/null 2>&1 || true && `
	tests := []struct {
		wrapped, want string
		ok            bool
	}{
		{pre + `eval 'docker ps -a' < /dev/null && pwd -P >| /tmp/claude-1-cwd`, "docker ps -a", true},
		{pre + `eval 'echo '\''a b'\'' | grep a' < /dev/null && pwd -P >| /tmp/claude-1-cwd`, "echo 'a b' | grep a", true},
		// A command that redirects its own input gets no "< /dev/null".
		{pre + `eval 'for t in a:1; do bash -c "exec 3<>/dev/tcp/$h/$p; head -c 1 <&3"; done' && pwd -P >| /tmp/claude-2-cwd`,
			`for t in a:1; do bash -c "exec 3<>/dev/tcp/$h/$p; head -c 1 <&3"; done`, true},
		{`'/r/bin/benchguard' hook --root '/r/sb'`, "", false},
	}
	for _, tc := range tests {
		got, ok := AgentCommand(tc.wrapped)
		if got != tc.want || ok != tc.ok {
			t.Errorf("AgentCommand(%q) = %q, %v; want %q, %v", tc.wrapped, got, ok, tc.want, tc.ok)
		}
	}
}
