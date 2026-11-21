package bench

// An agent in the agent checks (make lab-agent) or the benchmark must see a
// scenario only as a developer would: nothing the harness hands it may
// name the scenario or its cause (docs/research/agent-benchmark.md,
// "Arms"). make lab's project names (whyreach-lab-<scenario>-<rand>), the
// Compose files' comments and t.TempDir()'s directory names all would.

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// NeutralProject returns a Compose project name that says nothing about
// the scenario: whyreach-lab-<6 hex digits>.
func NeutralProject() string {
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return LabPrefix + hex.EncodeToString(b)
}

// StripComments returns a YAML document without its comments, and with
// everything else, anchors and merge keys included, as it was: the lab's
// Compose files explain their scenario in comments.
func StripComments(src []byte) ([]byte, error) {
	var n yaml.Node
	if err := yaml.Unmarshal(src, &n); err != nil {
		return nil, err
	}
	var clear func(*yaml.Node)
	clear = func(n *yaml.Node) {
		n.HeadComment, n.LineComment, n.FootComment = "", "", ""
		for _, c := range n.Content {
			clear(c)
		}
	}
	clear(&n)
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&n); err != nil {
		return nil, err
	}
	return buf.Bytes(), enc.Close()
}

// DiagnosePrompt is the problem report the agent checks give an agent that
// has only whyreach's tools: who can't connect to what, what the developer
// saw (symptom, or ""), and how to answer; nothing about the cause. from
// and to are as whyreach's --from and target: from is host or
// service:<name>@<project>.
//
// The answer it asks for is the one the checks judge by: a likely cause
// counts as a cause (the scenario's likely_cause verdict), and none means
// no problem or no cause named. Until v0.2 it said "no settled cause",
// which an agent read as excluding a likely one (wr013-subnet-overlap).
func DiagnosePrompt(from, to, symptom string) string {
	who := "On this machine (the host itself, not inside a container), a program"
	if svc, ok := strings.CutPrefix(from, "service:"); ok {
		name, project, _ := strings.Cut(svc, "@")
		who = fmt.Sprintf("In the Docker Compose project %q on this machine, the %s service", project, name)
	}
	if symptom != "" {
		to += " (" + symptom + ")"
	}
	return who + " can't connect to " + to + ". Find out why, using the whyreach tools. " +
		"Finish with one line `RESULT: <rule ID>` naming the rule of the cause whyreach found, certain or likely (its ID: WR and three digits), " +
		"or `RESULT: none` if whyreach reproduced no problem or named no cause."
}

var (
	// ruleID matches a rule ID anywhere, inside a longer word too:
	// t.TempDir() names a subtest's directory TestAgentwr002-loopback-bind<digits>.
	ruleID     = regexp.MustCompile(`(?i)wr\d{3}`)
	ruleIDWord = regexp.MustCompile(`(?i)^wr\d{3}$`)
)

// reportWords are words of scenario names that a problem report needs
// anyway: every report names Docker, a report from the host says so, and
// "not" and "only" say nothing on their own (the benchmark's prompt says
// "Only investigate").
var reportWords = []string{"docker", "host", "not", "only"}

// Hints returns what in text would tell an agent which scenario it faces,
// sorted: a rule ID; the scenario's name, or what follows its rule ID, with
// one of - _ . or a space between the words, or nothing; or a word of the
// name standing alone, other than docker, host, not and only. text is something
// the harness hands the agent: its prompt, with the target left out (the
// target is the problem itself), its arguments and environment, the names
// of its Compose project and directories.
func Hints(scenario, text string) []string {
	found := NameHints(scenario, text)
	lower := strings.ToLower(text)
	for _, w := range strings.Split(strings.ToLower(scenario), "-") {
		if w == "" || ruleIDWord.MatchString(w) || slices.Contains(reportWords, w) {
			continue
		}
		if hasWord(lower, w) {
			found = append(found, w)
		}
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// NameHints is Hints without the single words, for a scenario's Compose
// files: their settings are the scenario, so they may well hold its
// cause's words (network_mode: bridge, dns:), while a rule ID or the
// scenario's name in them could only be a label.
func NameHints(scenario, text string) []string {
	var found []string
	for _, m := range ruleID.FindAllString(text, -1) {
		found = append(found, strings.ToUpper(m))
	}
	for _, re := range namePhrases(scenario) {
		found = append(found, re.FindAllString(text, -1)...)
	}
	slices.Sort(found)
	return slices.Compact(found)
}

// namePhrases matches a scenario's name and, when it starts with a rule
// ID, the rest of it, ignoring case and with one of - _ . or a space
// between the words, or nothing.
func namePhrases(scenario string) []*regexp.Regexp {
	phrase := func(words []string) *regexp.Regexp {
		q := make([]string, len(words))
		for i, w := range words {
			q[i] = regexp.QuoteMeta(w)
		}
		return regexp.MustCompile(`(?i)` + strings.Join(q, `[-_. ]?`))
	}
	words := strings.Split(scenario, "-")
	out := []*regexp.Regexp{phrase(words)}
	if len(words) > 1 && ruleIDWord.MatchString(words[0]) {
		out = append(out, phrase(words[1:]))
	}
	return out
}

// hasWord reports whether w occurs in s with no letter or digit right
// before or after it.
func hasWord(s, w string) bool {
	for i := 0; ; {
		j := strings.Index(s[i:], w)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(w)
		if (j == 0 || !isAlnum(s[j-1])) && (end == len(s) || !isAlnum(s[end])) {
			return true
		}
		i = j + 1
	}
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
