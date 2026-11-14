package bench

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.yaml.in/yaml/v3"
)

func TestHints(t *testing.T) {
	cases := []struct {
		scenario, text string
		want           []string // Hints
		wantName       []string // NameHints
	}{
		// What the agent checks used to show: make lab's project name,
		// t.TempDir()'s directory, the new-user test's project name, and a
		// prompt's example answer.
		{"wr002-loopback-bind", "whyreach-lab-wr002-loopback-bind-1a2b",
			[]string{"WR002", "bind", "loopback", "loopback-bind", "wr002-loopback-bind"}, []string{"WR002", "loopback-bind", "wr002-loopback-bind"}},
		{"wr002-loopback-bind", "/tmp/TestAgentwr002-loopback-bind123/001",
			[]string{"WR002", "loopback", "loopback-bind", "wr002-loopback-bind"}, []string{"WR002", "loopback-bind", "wr002-loopback-bind"}},
		{"demo-localhost", "the worker service of the Docker Compose project whyreach-lab-demo", []string{"demo"}, nil},
		{"wr007-localhost", "naming the rule of the cause whyreach found (such as WR002)", []string{"WR002"}, []string{"WR002"}},
		{"healthy", "whyreach-lab-healthy-3c4d", []string{"healthy"}, []string{"healthy"}},
		{"wr011-host-docker-internal", "it uses host.docker.internal", []string{"host.docker.internal", "internal"}, []string{"host.docker.internal"}},
		// A Compose setting may hold the cause's words; only Hints minds.
		{"wr009-default-bridge", "network_mode: bridge", []string{"bridge"}, nil},
		// Words a report needs, a word inside a longer one, neutral names.
		{"wr011-host-docker-internal", "On this machine (the host itself, not inside a container), a Docker Compose project", nil, nil},
		{"wr003-wrong-port", "a report in a supported format", nil, nil},
		{"inconclusive-app-closes", "an application's port closed", nil, nil},
		{"wr002-loopback-bind", "/tmp/whyreach-agent-2718281828/work whyreach-lab-1a2b3c", nil, nil},
	}
	for _, c := range cases {
		if d := cmp.Diff(c.want, Hints(c.scenario, c.text)); d != "" {
			t.Errorf("Hints(%q, %q) (-want +got):\n%s", c.scenario, c.text, d)
		}
		if d := cmp.Diff(c.wantName, NameHints(c.scenario, c.text)); d != "" {
			t.Errorf("NameHints(%q, %q) (-want +got):\n%s", c.scenario, c.text, d)
		}
	}
}

func TestNeutralProject(t *testing.T) {
	re := regexp.MustCompile(`^whyreach-lab-[0-9a-f]{6}$`)
	a, b := NeutralProject(), NeutralProject()
	if !re.MatchString(a) || !re.MatchString(b) || a == b {
		t.Errorf("NeutralProject() = %q, %q; want two different whyreach-lab-<6 hex>", a, b)
	}
}

func TestStripComments(t *testing.T) {
	src := []byte(`# api listens on loopback only (WR002).
x-server: &server # shared settings
  image: lab
services:
  api:
    <<: *server
    command: ["serve", "127.0.0.1:8080"] # loopback only
  # worker connects to api
  worker:
    <<: *server
# the end
`)
	out, err := StripComments(src)
	if err != nil {
		t.Fatal(err)
	}
	if c := comments(t, out); len(c) > 0 || strings.Contains(string(out), "#") {
		t.Errorf("comments left %q in:\n%s", c, out)
	}
	sameSettings(t, src, out)
}

// TestScenariosGiveNoHints checks, for every lab scenario, what the agent
// checks hand an agent before it calls a tool (test/e2e: TestAgent,
// TestAgentNewUser): the problem report, with the target left out since
// it is the problem itself, a neutral project name, and the copies of the
// scenario's Compose files, which carry its settings without the comments
// that explain them. TestAgent and TestAgentNewUser check their actual
// values, directories included, again before each agent starts.
func TestScenariosGiveNoHints(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "lab", "*", "scenario.yaml"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no scenarios: %v", err)
	}
	for _, path := range paths {
		dir := filepath.Dir(path)
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			var s struct {
				From     string   `yaml:"from"`
				To       string   `yaml:"to"`
				Projects []string `yaml:"projects"`
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := yaml.Unmarshal(raw, &s); err != nil {
				t.Fatal(err)
			}
			project := NeutralProject()
			if h := Hints(name, project); len(h) > 0 {
				t.Errorf("the project name %s names the scenario: %v", project, h)
			}
			// The values the lab harness fills in, made up.
			vars := strings.NewReplacer("${PROJECT}", project, "${LAB_PORT}", "18080", "${HOST_PORT}", "18081", "${UNUSED_IP}", "192.0.2.200")
			from, to := vars.Replace(s.From), vars.Replace(s.To)
			if from == "" || to == "" || strings.Contains(from+to, "${") {
				t.Fatalf("from %q, to %q", from, to)
			}
			report := strings.ReplaceAll(DiagnosePrompt(from, to, ""), to, "<target>")
			if h := Hints(name, report); len(h) > 0 {
				t.Errorf("the problem report names the scenario or its cause (%v):\n%s", h, report)
			}
			if len(s.Projects) == 0 {
				s.Projects = []string{"compose.yaml"}
			}
			for _, f := range s.Projects {
				src, err := os.ReadFile(filepath.Join(dir, f))
				if err != nil {
					t.Fatal(err)
				}
				out, err := StripComments(src)
				if err != nil {
					t.Fatalf("%s: %v", f, err)
				}
				if c := comments(t, out); len(c) > 0 {
					t.Errorf("%s: the copy keeps comments: %q", f, c)
				}
				sameSettings(t, src, out)
				if h := NameHints(name, string(out)); len(h) > 0 {
					t.Errorf("%s: the copy names the scenario or a rule: %v", f, h)
				}
			}
		})
	}
}

// comments returns the comments a YAML document still has.
func comments(t *testing.T, doc []byte) []string {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal(doc, &n); err != nil {
		t.Fatal(err)
	}
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		for _, c := range []string{n.HeadComment, n.LineComment, n.FootComment} {
			if c != "" {
				out = append(out, c)
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&n)
	return out
}

// sameSettings checks that two YAML documents hold the same data.
func sameSettings(t *testing.T, a, b []byte) {
	t.Helper()
	var x, y any
	if err := yaml.Unmarshal(a, &x); err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &y); err != nil {
		t.Fatal(err)
	}
	if d := cmp.Diff(x, y); d != "" {
		t.Errorf("the copy's settings differ (-original +copy):\n%s", d)
	}
}
