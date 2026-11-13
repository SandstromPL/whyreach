// Package ruledocs holds the rule pages, docs/rules/WRxxx.md, one per rule
// in the catalog (INITIAL.md §4.6), so that `whyreach rules explain` prints
// the same page offline that the repository shows.
package ruledocs

import (
	"embed"
	"io/fs"
	"strings"
)

//go:embed WR*.md
var pages embed.FS

// Page returns the page for a rule ID such as "WR002".
func Page(id string) ([]byte, bool) {
	b, err := fs.ReadFile(pages, strings.ToUpper(id)+".md")
	return b, err == nil
}

// Title is the page's title without its rule ID: the pitfall in a phrase.
func Title(page []byte) string {
	first, _, _ := strings.Cut(string(page), "\n")
	_, title, ok := strings.Cut(strings.TrimPrefix(first, "# "), ": ")
	if !ok {
		return ""
	}
	return title
}
