package main

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const module = "github.com/SandstromPL/whyreach/"

// TestImportDirection enforces INITIAL.md §4.1:
//
//	cli and mcpserver → policy → engine → { rules, collect/*, executor, evidence }
//	rules → evidence only; executor → probe; nothing imports cli or mcpserver
//
// main wires cli and mcpserver. The front ends may use the engine's result
// types, but only policy builds an engine: everything reaches it through
// policy.
func TestImportDirection(t *testing.T) {
	imports := map[string][]string{} // package → whyreach packages it imports (non-test files)
	builders := map[string]bool{}    // packages that call engine.New
	err := filepath.WalkDir(filepath.Join("..", "..", "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		pkg := strings.TrimPrefix(filepath.ToSlash(filepath.Dir(path)), "../../")
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.Contains(string(src), "engine.New(") {
			builders[pkg] = true
		}
		for _, imp := range f.Imports {
			p := strings.Trim(imp.Path.Value, `"`)
			if rest, ok := strings.CutPrefix(p, module); ok && !slices.Contains(imports[pkg], rest) {
				imports[pkg] = append(imports[pkg], rest)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(imports) < 10 {
		t.Fatalf("found only %d packages: %v", len(imports), imports)
	}
	for pkg := range builders {
		if pkg != "internal/policy" {
			t.Errorf("%s builds an engine: only policy may, so nothing bypasses it", pkg)
		}
	}
	for pkg, deps := range imports {
		for _, dep := range deps {
			switch {
			case dep == "internal/cli" || dep == "internal/mcpserver":
				t.Errorf("%s imports %s: only main may", pkg, dep)
			case pkg == "internal/rules" && dep != "internal/evidence":
				t.Errorf("rules may import only evidence, not %s", dep)
			case dep == "internal/engine" && !slices.Contains([]string{"internal/policy", "internal/report", "internal/cli", "internal/mcpserver"}, pkg):
				t.Errorf("%s imports the engine", pkg)
			case dep == "internal/policy" && pkg != "internal/cli" && pkg != "internal/mcpserver":
				t.Errorf("%s imports policy: only the front ends may", pkg)
			case strings.HasPrefix(pkg, "internal/collect/") && (dep == "internal/rules" || dep == "internal/engine"):
				t.Errorf("%s must know nothing about %s", pkg, dep)
			case pkg == "internal/executor" && dep == "internal/rules":
				t.Errorf("executor decides where probes run, never what they mean: it imports rules")
			}
		}
	}
}
