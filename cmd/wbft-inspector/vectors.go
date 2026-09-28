package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/buildinfo"
	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/report"
	"github.com/0xmhha/wbft-inspector/internal/vector"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const vectorsUsage = `Usage: wbft-inspector vectors --impl "CMD ARGS" [--impl ...] --vectors DIR [flags]

Runs the conformance vectors of DIR (<runner>/<handler>/<case>/) against the
adapters with the protocol wbft-vector/1 (wbft-spec A-11 §3.4) and writes a
report with one result per case (vectors.cases) and one verdict per
requirement the cases list (results). A case is offered to the adapters that
list its handler, in the order of --impl; one answered "unsupported" goes to
the next. An adapter that exits, exceeds the time limit or breaks the
protocol is restarted.

Exit codes: 0 all cases passed or unsupported, 1 a case failed, 3 files of
the selection were not read (WBFT-VEC-012), 64 usage error (including an
adapter of another protocol), 69 an adapter could not be started.

Flags:
`

func runVectors(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("vectors", stderr)
	var impls multi
	fs.Var(&impls, "impl", "adapter command, split at spaces (repeatable)")
	dir := fs.String("vectors", "", "vector directory (the vectors/ directory of wbft-spec)")
	runnerSel := fs.String("runner", "", "run only this runner (e.g. timers)")
	handlerSel := fs.String("handler", "", "run only this handler (e.g. round_timeout)")
	caseTimeout := fs.Duration("case-timeout", 10*time.Second, "time limit of a pure or chain case")
	stepsTimeout := fs.Duration("steps-timeout", 60*time.Second, "time limit of a steps case")
	specCommit := fs.String("spec-commit", "", "wbft-spec commit of the vectors, sent in hello (default: the commit the catalog was generated from)")
	outPath := fs.String("out", "", "report file (default: standard output)")
	fs.Usage = func() { fmt.Fprint(stderr, vectorsUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if len(impls) == 0 || *dir == "" || fs.NArg() > 0 {
		fs.Usage()
		return report.ExitUsage
	}
	if *specCommit == "" {
		*specCommit = catalog.SpecInfo().Commit
	}
	started := time.Now().UTC()
	var cmds [][]string
	for _, s := range impls {
		cmds = append(cmds, strings.Fields(s))
	}
	o := vector.Options{Dir: *dir, Impls: cmds, Select: vector.Selection{Runner: *runnerSel, Handler: *handlerSel},
		CaseTimeout: *caseTimeout, StepsTimeout: *stepsTimeout, SpecCommit: *specCommit,
		RunnerName: "wbft-inspector", RunnerVer: buildinfo.Version}
	res, err := vector.Run(context.Background(), o)
	if err != nil {
		fmt.Fprintf(stderr, "vectors: %v\n", err)
		if vector.IsProtocolError(err) {
			return report.ExitUsage
		}
		return report.ExitNoInput
	}
	rep := &report.Report{Schema: report.SchemaID}
	rep.Run.Inputs = append(rep.Run.Inputs, report.Input{ID: "vectors", Kind: "vectors", Path: *dir})
	var implIDs []string
	for _, a := range res.Adapters {
		h := a.Hello
		imp := h.Improvements
		if imp == nil {
			imp = []string{}
		}
		rep.Run.Inputs = append(rep.Run.Inputs, report.Input{ID: a.InputID, Kind: "impl", Impl: &report.Impl{Cmd: a.Cmd,
			Name: h.Impl.Name, Version: h.Impl.Version, Commit: h.Impl.Commit, Lang: h.Impl.Lang, Handlers: h.Handlers,
			Build: h.Impl.Build, Improvements: imp}})
		implIDs = append(implIDs, a.InputID)
	}
	rep.Vectors = &report.Vectors{Dir: *dir, SpecCommit: *specCommit, Impls: implIDs, Diagnostic: res.Diagnostic,
		Totals: res.Totals, Cases: res.Cases, UnaccessedFiles: res.Unaccessed}
	if rep.Vectors.UnaccessedFiles == nil {
		rep.Vectors.UnaccessedFiles = []string{}
	}
	for _, p := range res.InvalidVectors {
		rep.Errors = append(rep.Errors, report.Error{Input: "vectors", Message: "invalid vector case " + p})
	}
	if res.Diagnostic {
		rep.Errors = append(rep.Errors, report.Error{Message: "an adapter reports enabled improvement items: this is a diagnostic run, and its case results are not taken into requirement verdicts (this build cannot map the items to requirements)"})
	}

	// One result per requirement the cases list.
	var entries []report.Entry
	for _, id := range sortedKeysOf(res.Instances) {
		var handlers []string
		for h := range res.HandlersByReq[id] {
			handlers = append(handlers, h)
		}
		sort.Strings(handlers)
		checker := "vector:" + strings.Join(handlers, ",")
		e := report.Entry{ID: id, Checker: checker, VectorCases: res.CasesByReq[id]}
		if _, known := catalog.Lookup(id); known {
			e.Instances = res.Instances[id]
		} else {
			e.Undecided = verdict.NotInBuild
			e.Detail = "this build does not know the requirement; the verdicts of its cases are not taken"
		}
		entries = append(entries, e)
	}
	for _, e := range entries {
		rep.Results = append(rep.Results, report.MakeResult(e))
	}
	report.SortResults(rep.Results)
	sum, _ := report.Summarize(rep.Results, entries, report.Policy{})
	exit := report.ExitOK
	if res.Failed() {
		exit = report.ExitFail
	} else if len(res.Unaccessed) > 0 {
		exit = report.ExitUnaccessed
	}
	sum.ExitCode = exit
	rep.Summary = sum
	options := map[string]any{"runner": *runnerSel, "handler": *handlerSel, "case_timeout": caseTimeout.String(), "steps_timeout": stepsTimeout.String()}
	fillRun(rep, "vectors", []string{*dir, fmt.Sprint(cmds), fmt.Sprint(options)}, started)
	rep.Run.Clock = report.Clock{Model: "unknown"}
	rep.Run.Options = options
	if err := writeReport(*outPath, stdout, rep); err != nil {
		fmt.Fprintf(stderr, "vectors: %v\n", err)
		return report.ExitInternal
	}
	t := res.Totals
	fmt.Fprintf(stderr, "cases=%d pass=%d fail=%d error=%d timeout=%d (passed by timeout %d) unsupported=%d unaccessed_files=%d\n",
		t.Cases, t.Pass, t.Fail, t.Error, t.Timeout, t.TimeoutPassed, t.Unsupported, len(res.Unaccessed))
	return exit
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
