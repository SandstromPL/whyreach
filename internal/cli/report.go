package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	ruledocs "github.com/SandstromPL/whyreach/docs/rules"
	"github.com/SandstromPL/whyreach/internal/config"
	"github.com/SandstromPL/whyreach/internal/engine"
	"github.com/SandstromPL/whyreach/internal/report"
	"github.com/SandstromPL/whyreach/internal/rules"
)

// saveBundle writes the diagnosis as an unredacted report bundle in
// whyreach's data directory: the user's own record, made by the user. A
// copy to share comes from `whyreach report export`, which redacts it
// (INITIAL.md §4.12, §10 Q12).
func saveBundle(w io.Writer, o Options, d *engine.Diagnosis) error {
	dir, err := config.ReportsDir()
	if err != nil {
		return err
	}
	saved, err := report.Save(d, report.SaveOptions{Dir: dir, Redact: false, Version: o.Version})
	if err != nil {
		return fmt.Errorf("save the report bundle: %w", err)
	}
	fmt.Fprintf(w, "whyreach: saved the report bundle %s (not redacted). To share it, make a redacted copy: whyreach report export %s\n",
		report.Sanitize(saved.Path), d.ID)
	return nil
}

func newReport(o Options) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "report",
		Short: "List, show and export saved report bundles",
		Long: `Report bundles hold a diagnosis with all its evidence: manifest.json,
diagnosis.json, evidence.jsonl and report.md, in whyreach's data directory
($XDG_DATA_HOME/whyreach/reports). "whyreach diagnose --report" saves one,
not redacted; the MCP tool save_report saves a redacted one.

"whyreach report export ID" makes a redacted copy to attach to an issue.`,
	}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List saved report bundles, newest first",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := config.ReportsDir()
			if err != nil {
				return internalErr(err)
			}
			bundles, err := report.ListBundles(dir)
			if err != nil {
				return internalErr(err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				if bundles == nil {
					bundles = []report.Bundle{}
				}
				return writeJSON(out, bundles)
			}
			if len(bundles) == 0 {
				_, err := fmt.Fprintf(out, "No report bundles in %s. Save one with whyreach diagnose --report, or save_report through MCP.\n", report.Sanitize(dir))
				return wrote(err)
			}
			tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tSAVED (UTC)\tREDACTED\tVERDICT\tRULE\tFROM → TO")
			for _, b := range bundles {
				redacted, rule := "no", b.Primary
				if b.Redacted {
					redacted = "yes"
				}
				if rule == "" {
					rule = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", b.ID, b.CreatedAt.UTC().Format("2006-01-02 15:04"), redacted,
					report.Sanitize(b.Verdict), report.Sanitize(rule), report.Sanitize(b.From+" → "+b.To))
			}
			return wrote(tw.Flush())
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print the list as JSON")

	show := &cobra.Command{
		Use:   "show ID",
		Short: "Print a bundle's report (Markdown)",
		Long:  "Print report.md of the bundle for diagnosis ID. A diagnosis saved both ways shows the unredacted bundle.",
		Args:  oneID("show"),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := findBundle(args[0])
			if err != nil {
				return err
			}
			md, err := report.ReadReport(b)
			if err != nil {
				return internalErr(err)
			}
			_, err = fmt.Fprint(cmd.OutOrStdout(), report.Sanitize(string(md)))
			return wrote(err)
		},
	}

	var redactPrivate bool
	export := &cobra.Command{
		Use:   "export ID [--redact-private]",
		Short: "Make a redacted copy of a bundle to attach to an issue",
		Long: `Write a redacted copy of the bundle for diagnosis ID as ID.tar.gz in the
reports directory, and print its path. Public IP addresses, host names, MAC
addresses and container IDs are replaced by pseudonyms that are stable within
the copy (ip-…, host-…, ctr-…), and your home directory by ~. Private
addresses (10/8, 172.16/12, 192.168/16) are kept unless --redact-private is
set, or redact_private = true under [report] in the config file.
Check the copy before you share it.`,
		Args: oneID("export"),
		RunE: func(cmd *cobra.Command, args []string) error {
			b, err := findBundle(args[0])
			if err != nil {
				return err
			}
			path, err := config.Path()
			if err != nil {
				return internalErr(err)
			}
			cfg, err := config.Load(path)
			if err != nil {
				return usageErr(err)
			}
			dir, err := config.ReportsDir()
			if err != nil {
				return internalErr(err)
			}
			home, _ := os.UserHomeDir() // without one, nothing is replaced by ~
			ex, err := report.Export(b, report.ExportOptions{
				Dir: dir, RedactPrivate: redactPrivate || cfg.Report.RedactPrivate, Home: home, Version: o.Version,
			})
			if err != nil {
				return internalErr(err)
			}
			private := "private addresses kept"
			if !ex.PrivateKept {
				private = "private addresses replaced too"
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s\nRedacted copy of %s: %s, %s and %s replaced; %s. Check it before you share it.\n",
				report.Sanitize(ex.Path), b.ID, count(ex.Replaced[report.ClassIP], "address", "addresses"),
				count(ex.Replaced[report.ClassHost], "host name", "host names"), count(ex.Replaced[report.ClassContainer], "container ID", "container IDs"), private)
			return wrote(err)
		},
	}
	export.Flags().BoolVar(&redactPrivate, "redact-private", false, "replace private (RFC 1918) addresses too")
	cmd.AddCommand(list, show, export)
	return cmd
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func oneID(verb string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return usageErr(fmt.Errorf("report %s takes one diagnosis ID (whyreach report list shows them)", verb))
		}
		return nil
	}
}

func findBundle(ref string) (report.Bundle, error) {
	dir, err := config.ReportsDir()
	if err != nil {
		return report.Bundle{}, internalErr(err)
	}
	b, err := report.FindBundle(dir, ref)
	if err != nil {
		if errors.Is(err, report.ErrNoBundle) || errors.Is(err, report.ErrBadID) {
			return report.Bundle{}, usageErr(err)
		}
		return report.Bundle{}, internalErr(err)
	}
	return b, nil
}

// ruleInfo is one rule in `whyreach rules list --json`.
type ruleInfo struct {
	ID        string `json:"id"`
	Layer     int    `json:"layer"`
	LayerName string `json:"layer_name"`
	Title     string `json:"title"`
	Doc       string `json:"doc"`
}

func catalog() []ruleInfo {
	var out []ruleInfo
	for _, r := range rules.All() {
		page, _ := ruledocs.Page(r.ID())
		out = append(out, ruleInfo{
			ID: r.ID(), Layer: int(r.Layer()), LayerName: r.Layer().String(), Title: ruledocs.Title(page), Doc: rules.DocURL(r.ID()),
		})
	}
	slices.SortFunc(out, func(a, b ruleInfo) int { return strings.Compare(a.ID, b.ID) })
	return out
}

func newRules() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "List the rules whyreach diagnoses with, or explain one",
	}
	var asJSON bool
	list := &cobra.Command{
		Use:   "list",
		Short: "List the rules: ID, layer and the pitfall each one detects",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			c := catalog()
			if asJSON {
				return writeJSON(cmd.OutOrStdout(), c)
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(tw, "RULE\tLAYER\tPITFALL")
			for _, r := range c {
				fmt.Fprintf(tw, "%s\t%d %s\t%s\n", r.ID, r.Layer, r.LayerName, strings.ReplaceAll(r.Title, "`", ""))
			}
			if err := tw.Flush(); err != nil {
				return wrote(err)
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "\nThe earliest layer with a finding gives the primary cause. whyreach rules explain WRxxx prints a rule's page.")
			return wrote(err)
		},
	}
	list.Flags().BoolVar(&asJSON, "json", false, "print the rules as JSON")
	explain := &cobra.Command{
		Use:   "explain WRxxx",
		Short: "Print a rule's page: the pitfall, the evidence, the fix and false positives",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usageErr(errors.New("rules explain takes one rule ID, such as WR002"))
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToUpper(strings.TrimSpace(args[0]))
			if _, ok := rules.ByID(id); !ok {
				var ids []string
				for _, r := range catalog() {
					ids = append(ids, r.ID)
				}
				return usageErr(fmt.Errorf("no rule %q; the rules are %s", report.Sanitize(args[0]), strings.Join(ids, ", ")))
			}
			page, ok := ruledocs.Page(id)
			if !ok {
				return internalErr(fmt.Errorf("this build has no page for %s", id))
			}
			_, err := fmt.Fprint(cmd.OutOrStdout(), string(page))
			return wrote(err)
		},
	}
	cmd.AddCommand(list, explain)
	return cmd
}
