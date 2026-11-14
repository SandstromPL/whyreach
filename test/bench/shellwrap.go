package bench

import (
	"regexp"
	"strings"
)

// Claude Code runs a Bash call as "… && eval '<command>' < /dev/null &&
// pwd -P >| <file>", leaving out "< /dev/null" when the command redirects
// its own input (as "<&3" does). Quotes inside the command are written
// '\” (or '"'"').
var evalRe = regexp.MustCompile(`(?s)eval '((?:[^']|'\\''|'"'"')*)'(?: < /dev/null)? && pwd -P >\|`)

// AgentCommand recovers the agent's command from the string Claude Code
// hands its shell prefix; ok is false for anything else (a hook).
func AgentCommand(wrapped string) (string, bool) {
	m := evalRe.FindStringSubmatch(wrapped)
	if m == nil {
		return "", false
	}
	return strings.NewReplacer(`'\''`, "'", `'"'"'`, "'").Replace(m[1]), true
}
