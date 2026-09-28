package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

const catalogUsage = `Usage:
  wbft-inspector catalog list [--chapter A-05] [--json]
      list the checker catalog: requirement, priority, checker, and whether
      the checker is implemented in this build or planned
  wbft-inspector catalog coverage --spec DIR [--chapters A-05,A-06]
      compare the embedded requirement list with a wbft-spec checkout and
      check that every Observable requirement of the chapters has a catalog
      row; exit 1 on a difference or a missing row
  wbft-inspector catalog extract --spec DIR --commit C --reference R [--out FILE]
      write the requirement list of a wbft-spec checkout (requirements.json)
`

func runCatalog(args []string, stdout, stderr io.Writer) int {
	sub := "list"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	fs := newFlags("catalog "+sub, stderr)
	fs.Usage = func() { fmt.Fprint(stderr, catalogUsage); fs.PrintDefaults() }
	switch sub {
	case "list":
		chapter := fs.String("chapter", "", "only rows of this chapter (e.g. A-05)")
		asJSON := fs.Bool("json", false, "write JSON")
		if fs.Parse(args) != nil {
			return report.ExitUsage
		}
		return catalogList(stdout, *chapter, *asJSON)
	case "coverage":
		spec := fs.String("spec", "", "the spec/ directory of a wbft-spec checkout")
		chapters := fs.String("chapters", "A-05,A-06", "chapters whose Observable requirements must have a row")
		if fs.Parse(args) != nil || *spec == "" {
			fs.Usage()
			return report.ExitUsage
		}
		return catalogCoverage(stdout, stderr, *spec, splitList(*chapters))
	case "extract":
		spec := fs.String("spec", "", "the spec/ directory of a wbft-spec checkout")
		commit := fs.String("commit", "", "wbft-spec commit of the checkout")
		ref := fs.String("reference", "", "reference implementation commit the specification is written against")
		out := fs.String("out", "", "output file (default: standard output)")
		if fs.Parse(args) != nil || *spec == "" || *commit == "" || *ref == "" {
			fs.Usage()
			return report.ExitUsage
		}
		reqs, err := catalog.Extract(*spec)
		if err != nil {
			fmt.Fprintf(stderr, "catalog extract: %v\n", err)
			return report.ExitNoInput
		}
		f := catalog.File{Spec: catalog.Spec{Repo: "github.com/0xmhha/wbft-spec", Commit: *commit, ReferenceCommit: *ref}, Requirements: reqs}
		b, err := json.MarshalIndent(f, "", "  ")
		if err != nil {
			return report.ExitInternal
		}
		b = append(b, '\n')
		if *out == "" {
			_, err = stdout.Write(b)
		} else {
			err = os.WriteFile(*out, b, 0o644)
		}
		if err != nil {
			fmt.Fprintf(stderr, "catalog extract: %v\n", err)
			return report.ExitInternal
		}
		return report.ExitOK
	}
	fmt.Fprint(stderr, catalogUsage)
	return report.ExitUsage
}

type listRow struct {
	Requirement string   `json:"requirement"`
	Chapter     string   `json:"chapter"`
	Level       string   `json:"level"`
	Tags        []string `json:"tags"`
	Priority    string   `json:"priority"`
	Checker     string   `json:"checker"`
	Status      string   `json:"status"` // implemented or planned
}

func catalogList(stdout io.Writer, chapter string, asJSON bool) int {
	var rows []listRow
	for _, r := range catalog.Rows() {
		req, _ := catalog.Lookup(r.Requirement)
		if chapter != "" && req.Chapter != chapter {
			continue
		}
		lr := listRow{Requirement: r.Requirement, Chapter: req.Chapter, Level: req.Level, Tags: req.Tags, Priority: r.Priority, Checker: r.Checker, Status: "planned"}
		if c, ok := check.ForRequirement(r.Requirement); ok {
			lr.Checker, lr.Status = c.Name(), "implemented"
		}
		rows = append(rows, lr)
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rows); err != nil {
			return report.ExitInternal
		}
		return report.ExitOK
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REQUIREMENT\tPRIORITY\tCHECKER\tSTATUS\tTAGS")
	impl := 0
	for _, r := range rows {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Requirement, r.Priority, r.Checker, r.Status, strings.Join(r.Tags, ","))
		if r.Status == "implemented" {
			impl++
		}
	}
	_ = tw.Flush()
	fmt.Fprintf(stdout, "\n%d rows, %d implemented, %d planned\n", len(rows), impl, len(rows)-impl)
	return report.ExitOK
}

func catalogCoverage(stdout, stderr io.Writer, specDir string, chapters []string) int {
	reqs, err := catalog.Extract(specDir)
	if err != nil {
		fmt.Fprintf(stderr, "catalog coverage: %v\n", err)
		return report.ExitNoInput
	}
	bad := false
	embedded := map[string]catalog.Requirement{}
	for _, r := range catalog.Requirements() {
		embedded[r.ID] = r
	}
	found := map[string]bool{}
	for _, r := range reqs {
		found[r.ID] = true
		e, ok := embedded[r.ID]
		switch {
		case !ok:
			fmt.Fprintf(stdout, "DRIFT %s: in the specification, not in the embedded list\n", r.ID)
			bad = true
		case e.Level != r.Level || strings.Join(e.Tags, ",") != strings.Join(r.Tags, ",") || e.Withdrawn != r.Withdrawn || e.Chapter != r.Chapter:
			fmt.Fprintf(stdout, "DRIFT %s: embedded %+v, specification %+v\n", r.ID, e, r)
			bad = true
		}
	}
	var gone []string
	for id := range embedded {
		if !found[id] {
			gone = append(gone, id)
		}
	}
	sort.Strings(gone)
	for _, id := range gone {
		fmt.Fprintf(stdout, "DRIFT %s: in the embedded list, not in the specification\n", id)
		bad = true
	}
	want := map[string]bool{}
	for _, c := range chapters {
		want[c] = true
	}
	total, rowsN, impl := 0, 0, 0
	for _, r := range reqs {
		if !want[r.Chapter] || !r.Observable() || r.Withdrawn {
			continue
		}
		total++
		if _, ok := catalog.RowOf(r.ID); !ok {
			fmt.Fprintf(stdout, "MISSING %s: Observable (%s) without a catalog row\n", r.ID, strings.Join(r.Tags, ","))
			bad = true
			continue
		}
		rowsN++
		if _, ok := check.ForRequirement(r.ID); ok {
			impl++
		}
	}
	fmt.Fprintf(stdout, "chapters %s: %d Observable requirements, %d with a catalog row, %d with an implemented checker\n",
		strings.Join(chapters, ","), total, rowsN, impl)
	if bad {
		return report.ExitFail
	}
	return report.ExitOK
}
