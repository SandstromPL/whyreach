package main

import "strings"

// A small reader for the shell commands an agent writes: enough of bash's
// grammar to find every simple command in a line (pipelines, lists,
// subshells, $(…) and `…`, process substitution, here-documents) and the
// files its redirections write. It doesn't expand anything: a word that
// holds an expansion keeps its text and is marked dynamic. Whatever it gets
// wrong, the sandbox still holds (docs/research/agent-benchmark.md); the
// guard only counts and explains.

// word is one shell word after quote removal. Globs stay as written.
type word struct {
	text    string
	dynamic bool // holds a $… or `…` expansion, kept as its text
}

// redir is an output or input redirection.
type redir struct {
	op     string // ">", ">>", ">|", "&>", "&>>", "<>", "<", "<<", "<<<", ">&", "<&"
	target word
}

// simple is one simple command: its words, its redirections and the bodies
// of its here-documents.
type simple struct {
	words     []word
	redirs    []redir
	heredocs  []string
	substTail bool // the command came from inside $(…), `…` or <(…)
}

// maxDepth bounds nested $(…), bash -c and the like.
const maxDepth = 8

// parseScript splits a script into simple commands, including those nested
// in substitutions. ok is false when the script couldn't be read to its end
// (an unterminated quote, say); the commands read so far are still
// returned.
func parseScript(src string, depth int) (cmds []simple, ok bool) {
	if depth > maxDepth {
		return nil, false
	}
	p := &parser{src: src, depth: depth}
	p.run()
	return p.cmds, !p.bad
}

type parser struct {
	src   string
	i     int
	depth int
	bad   bool

	cmds    []simple
	cur     simple
	pending []pendingDoc // here-documents whose bodies start at the next newline

	// the word being built
	w       strings.Builder
	wDyn    bool
	inWord  bool
	redirOp string // a redirection operator waiting for its target
}

type pendingDoc struct {
	cmd   int // index into cmds once the command ends; -1 while it's cur
	delim string
	strip bool // <<-
}

func (p *parser) run() {
	for p.i < len(p.src) {
		c := p.src[p.i]
		switch {
		case c == '\\':
			if p.i+1 < len(p.src) {
				if p.src[p.i+1] == '\n' { // line continuation
					p.i += 2
					continue
				}
				p.addByte(p.src[p.i+1])
				p.i += 2
				continue
			}
			p.i++
		case c == '\'':
			end := strings.IndexByte(p.src[p.i+1:], '\'')
			if end < 0 {
				p.addString(p.src[p.i+1:])
				p.bad = true
				p.i = len(p.src)
				continue
			}
			p.addString(p.src[p.i+1 : p.i+1+end])
			p.i += end + 2
		case c == '"':
			p.i++
			p.doubleQuoted()
		case c == '$':
			p.dollar()
		case c == '`':
			p.backtick()
		case c == ' ' || c == '\t':
			p.endWord()
			p.i++
		case c == '\n':
			p.endWord()
			p.endCommand()
			p.i++
			p.readHeredocs()
		case c == '#' && !p.inWord:
			for p.i < len(p.src) && p.src[p.i] != '\n' {
				p.i++
			}
		case c == ';' || c == '&' || c == '|' || c == '(' || c == ')':
			if c == '&' && p.i+1 < len(p.src) && p.src[p.i+1] == '>' {
				p.redirection() // &> and &>>
				continue
			}
			p.endWord()
			p.endCommand()
			p.i++
			if p.i < len(p.src) && (p.src[p.i] == c || (c == '|' && p.src[p.i] == '&') || (c == ';' && p.src[p.i] == '&')) {
				p.i++
			}
		case c == '<' || c == '>':
			if p.i+1 < len(p.src) && p.src[p.i+1] == '(' && !p.inWord {
				p.procSubst()
				continue
			}
			p.redirection()
		default:
			p.addByte(c)
			p.i++
		}
	}
	p.endWord()
	p.endCommand()
	if len(p.pending) > 0 {
		p.bad = true
	}
}

func (p *parser) addByte(b byte) {
	p.w.WriteByte(b)
	p.inWord = true
}

func (p *parser) addString(s string) {
	p.w.WriteString(s)
	p.inWord = true
}

// endWord finishes the word being built: as the target of a waiting
// redirection, or as the command's next word.
func (p *parser) endWord() {
	if !p.inWord {
		return
	}
	w := word{text: p.w.String(), dynamic: p.wDyn}
	p.w.Reset()
	p.wDyn, p.inWord = false, false
	if p.redirOp != "" {
		op := p.redirOp
		p.redirOp = ""
		if op == "<<" || op == "<<-" {
			p.pending = append(p.pending, pendingDoc{cmd: -1, delim: w.text, strip: op == "<<-"})
		}
		p.cur.redirs = append(p.cur.redirs, redir{op: op, target: w})
		return
	}
	// A redirection's file descriptor ("2" in 2>) was read as a word.
	p.cur.words = append(p.cur.words, w)
}

func (p *parser) endCommand() {
	if p.redirOp != "" { // an operator with no target: not a valid line
		p.redirOp = ""
		p.bad = true
	}
	if len(p.cur.words) == 0 && len(p.cur.redirs) == 0 {
		return
	}
	idx := len(p.cmds)
	for k := range p.pending {
		if p.pending[k].cmd == -1 {
			p.pending[k].cmd = idx
		}
	}
	p.cmds = append(p.cmds, p.cur)
	p.cur = simple{}
}

// readHeredocs reads the bodies of the here-documents opened on the line
// that just ended.
func (p *parser) readHeredocs() {
	for len(p.pending) > 0 {
		d := p.pending[0]
		p.pending = p.pending[1:]
		var body strings.Builder
		found := false
		for p.i < len(p.src) {
			end := strings.IndexByte(p.src[p.i:], '\n')
			line := p.src[p.i:]
			if end >= 0 {
				line = p.src[p.i : p.i+end]
				p.i += end + 1
			} else {
				p.i = len(p.src)
			}
			check := line
			if d.strip {
				check = strings.TrimLeft(line, "\t")
			}
			if check == d.delim {
				found = true
				break
			}
			body.WriteString(line)
			body.WriteByte('\n')
		}
		if !found {
			p.bad = true
		}
		if d.cmd >= 0 && d.cmd < len(p.cmds) {
			p.cmds[d.cmd].heredocs = append(p.cmds[d.cmd].heredocs, body.String())
		}
	}
}

func (p *parser) redirection() {
	// A word made only of digits right before the operator is its fd.
	if p.inWord && !p.wDyn && isDigits(p.w.String()) {
		p.w.Reset()
		p.inWord = false
	} else {
		p.endWord()
	}
	ops := []string{"&>>", "&>", ">>", ">|", ">&", "<<<", "<<-", "<<", "<>", "<&", ">", "<"}
	for _, op := range ops {
		if strings.HasPrefix(p.src[p.i:], op) {
			p.i += len(op)
			// >&2, 2>&1, <&0, >&-: a file descriptor, not a file.
			if op == ">&" || op == "<&" {
				j := p.i
				for j < len(p.src) && (p.src[j] == ' ' || p.src[j] == '\t') {
					j++
				}
				k := j
				for k < len(p.src) && (isDigit(p.src[k]) || p.src[k] == '-') {
					k++
				}
				if k > j && (k == len(p.src) || strings.ContainsRune(" \t\n;&|)", rune(p.src[k]))) {
					p.i = k
					return
				}
				if op == ">&" { // >&file is &>file
					op = "&>"
				}
			}
			p.redirOp = op
			return
		}
	}
	p.i++
}

func (p *parser) doubleQuoted() {
	for p.i < len(p.src) {
		c := p.src[p.i]
		switch c {
		case '"':
			p.i++
			p.inWord = true // "" is an empty word
			return
		case '\\':
			if p.i+1 < len(p.src) && strings.ContainsRune("$`\"\\\n", rune(p.src[p.i+1])) {
				if p.src[p.i+1] != '\n' {
					p.addByte(p.src[p.i+1])
				}
				p.i += 2
				continue
			}
			p.addByte(c)
			p.i++
		case '$':
			p.dollar()
		case '`':
			p.backtick()
		default:
			p.addByte(c)
			p.i++
		}
	}
	p.bad = true
}

// dollar reads $…: a command substitution, arithmetic, a parameter, or
// $'…' quoting.
func (p *parser) dollar() {
	rest := p.src[p.i:]
	switch {
	case strings.HasPrefix(rest, "$(("):
		end := matchParen(p.src, p.i+1)
		p.markDynamic(p.src[p.i:end])
		p.i = end
	case strings.HasPrefix(rest, "$("):
		end := matchParen(p.src, p.i+1)
		inner := p.src[p.i+2 : max(p.i+2, end-1)]
		p.nested(inner)
		p.markDynamic(p.src[p.i:end])
		p.i = end
	case strings.HasPrefix(rest, "${"):
		end := strings.IndexByte(rest, '}')
		if end < 0 {
			p.markDynamic(rest)
			p.i = len(p.src)
			p.bad = true
			return
		}
		p.markDynamic(rest[:end+1])
		p.i += end + 1
	case strings.HasPrefix(rest, "$'"):
		j := p.i + 2
		var b strings.Builder
		for j < len(p.src) && p.src[j] != '\'' {
			if p.src[j] == '\\' && j+1 < len(p.src) {
				switch p.src[j+1] {
				case 'n':
					b.WriteByte('\n')
				case 't':
					b.WriteByte('\t')
				default:
					b.WriteByte(p.src[j+1])
				}
				j += 2
				continue
			}
			b.WriteByte(p.src[j])
			j++
		}
		p.addString(b.String())
		p.i = min(j+1, len(p.src))
	default:
		j := p.i + 1
		if j < len(p.src) && strings.ContainsRune("@*#?$!-0123456789", rune(p.src[j])) {
			j++
		} else {
			for j < len(p.src) && (isAlnum(p.src[j]) || p.src[j] == '_') {
				j++
			}
		}
		if j == p.i+1 { // a lone $
			p.addByte('$')
			p.i++
			return
		}
		p.markDynamic(p.src[p.i:j])
		p.i = j
	}
}

func (p *parser) markDynamic(text string) {
	p.addString(text)
	p.wDyn = true
}

func (p *parser) backtick() {
	j := p.i + 1
	var inner strings.Builder
	for j < len(p.src) && p.src[j] != '`' {
		if p.src[j] == '\\' && j+1 < len(p.src) {
			inner.WriteByte(p.src[j+1])
			j += 2
			continue
		}
		inner.WriteByte(p.src[j])
		j++
	}
	if j >= len(p.src) {
		p.bad = true
	}
	p.nested(inner.String())
	p.markDynamic(p.src[p.i:min(j+1, len(p.src))])
	p.i = min(j+1, len(p.src))
}

// procSubst reads <(…) or >(…): its commands run, and the word is a
// /dev/fd path.
func (p *parser) procSubst() {
	end := matchParen(p.src, p.i+1)
	p.nested(p.src[p.i+2 : max(p.i+2, end-1)])
	p.markDynamic("/dev/fd/63")
	p.i = end
}

func (p *parser) nested(src string) {
	cmds, ok := parseScript(src, p.depth+1)
	if !ok {
		p.bad = true
	}
	for _, c := range cmds {
		c.substTail = true
		p.cmds = append(p.cmds, c)
	}
}

// matchParen returns the index just past the parenthesis that closes the
// one at open, skipping quotes; len(s) when there is none.
func matchParen(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '\'':
			end := strings.IndexByte(s[i+1:], '\'')
			if end < 0 {
				return len(s)
			}
			i += end + 1
		case '"':
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' {
					i++
				}
			}
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return len(s)
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) {
			return false
		}
	}
	return true
}

func isAlnum(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
