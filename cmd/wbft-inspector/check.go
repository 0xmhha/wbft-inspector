package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/buildinfo"
	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/report"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const checkUsage = `Usage: wbft-inspector check --events PATH [--events PATH ...] [--frames DIR ...] [flags]

Decides the requirements of the checker catalog from consensus event
streams (JSON Lines, one event per line; a directory stands for its *.jsonl
files) and frame dumps in the R-01 format (frames-<run>.jsonl and payloads/)
and writes the report. Requirements whose checker needs an input that
was not given are CANNOT_DECIDE (MISSING_DATA); requirements without a
checker in this build are NOT_RUN; requirement IDs this build does not know
are CANNOT_DECIDE (NOT_IN_BUILD).

Flags:
`

func runCheck(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("check", stderr)
	var evPaths multi
	fs.Var(&evPaths, "events", "event stream file or directory (repeatable)")
	var framePaths multi
	fs.Var(&framePaths, "frames", "frame dump directory in the R-01 format (repeatable); format problems are reported as errors")
	chainCfg := fs.String("chain-config", "", "genesis file or chain configuration (anzeon.wbft, transitions) for timer durations")
	checks := fs.String("checks", "", "comma-separated selection: requirement IDs, priorities (P0, P1, P2, V) or checker-name globs (e.g. timer.*); default: the whole catalog")
	requireDecided := fs.String("require-decided", "", "file of requirement IDs that must be decided (PASS or FAIL); otherwise exit 2")
	minCoverage := fs.Float64("min-coverage", 0, "lower bound of passed/instances for PASS results; otherwise exit 2")
	failOn := fs.String("fail-on", "critical,high,medium", "severities whose FAIL gives exit code 1")
	clockModel := fs.String("clock-model", "shared-host", "clock model of the nodes: shared-host, ntp or unknown")
	skew := fs.Float64("clock-skew-ms", 0, "upper bound of the clock skew between nodes (ms)")
	sched := fs.Float64("sched-ms", 100, "upper bound of timer callback and event loop delay (ms)")
	margin := fs.Float64("margin-ms", 100, "margin beyond the tolerance band before a timing FAIL (ms)")
	outPath := fs.String("out", "", "report file (default: standard output)")
	fs.Usage = func() { fmt.Fprint(stderr, checkUsage); fs.PrintDefaults() }
	if err := fs.Parse(args); err != nil {
		return report.ExitUsage
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "check: unexpected arguments %v\n", fs.Args())
		return report.ExitUsage
	}
	switch *clockModel {
	case "shared-host", "ntp", "unknown":
	default:
		fmt.Fprintf(stderr, "check: unknown clock model %q\n", *clockModel)
		return report.ExitUsage
	}
	started := time.Now().UTC()
	rep := &report.Report{Schema: report.SchemaID}
	exit := report.ExitOK

	// Inputs.
	in := &check.Inputs{Given: map[check.Kind]bool{},
		Clock: check.Clock{Model: *clockModel, SkewMs: *skew, SchedMs: *sched, Margin: *margin}}
	var idParts []string
	files, err := events.Expand(evPaths)
	if err != nil {
		rep.Errors = append(rep.Errors, report.Error{Message: "events: " + err.Error()})
		exit = report.ExitNoInput
	}
	if len(files) > 0 {
		set, err := events.Load(files)
		if err != nil {
			rep.Errors = append(rep.Errors, report.Error{Message: "events: " + err.Error()})
			exit = report.ExitNoInput
		} else {
			in.Events = set
			in.Given[check.Events] = true
			for _, x := range set.Inputs {
				ri := report.Input{ID: x.ID, Kind: "events", Path: x.Path, SHA256: x.SHA256, Records: x.Records}
				if len(x.Nodes) == 1 {
					ri.Node = x.Nodes[0]
				}
				if x.FirstWall != "" {
					ri.TimeRange = &report.TimeRange{First: x.FirstWall, Last: x.LastWall}
				}
				rep.Run.Inputs = append(rep.Run.Inputs, ri)
				idParts = append(idParts, x.SHA256)
			}
			for _, m := range set.Errors {
				rep.Errors = append(rep.Errors, report.Error{Message: m})
			}
			var unknown []string
			for k := range set.UnknownKinds {
				unknown = append(unknown, k)
			}
			sort.Strings(unknown)
			for _, k := range unknown {
				rep.Errors = append(rep.Errors, report.Error{Message: fmt.Sprintf("event kind %s (%d records) is not known to this build; its records were not interpreted", k, set.UnknownKinds[k])})
			}
			rep.Run.Nodes = nodesOf(set)
		}
	}
	for _, dir := range framePaths {
		d, err := frames.Load(dir)
		if err != nil {
			rep.Errors = append(rep.Errors, report.Error{Message: "frames: " + err.Error()})
			exit = report.ExitNoInput
			continue
		}
		id := fmt.Sprintf("in-%d", len(rep.Run.Inputs)+1)
		d.SetInput(id)
		in.Frames = append(in.Frames, d)
		in.Given[check.Frames] = true
		h := sha256.New()
		for _, name := range d.Files {
			b, err := os.ReadFile(filepath.Join(dir, name))
			if err == nil {
				h.Write(b)
			}
		}
		sum := hex.EncodeToString(h.Sum(nil))
		ri := report.Input{ID: id, Kind: "frames", Path: dir, SHA256: sum, Records: len(d.Records)}
		if nodes := frameNodes(d); len(nodes) == 1 {
			ri.Node = nodes[0]
		}
		rep.Run.Inputs = append(rep.Run.Inputs, ri)
		idParts = append(idParts, sum)
		for _, p := range frames.Validate(d).Problems {
			rep.Errors = append(rep.Errors, report.Error{Message: "frames " + dir + ": " + p})
		}
	}
	if *chainCfg != "" {
		b, err := os.ReadFile(*chainCfg)
		if err != nil {
			rep.Errors = append(rep.Errors, report.Error{Message: "chain config: " + err.Error()})
			exit = report.ExitNoInput
		} else if cfg, err := params.ParseGenesis(b); err != nil {
			rep.Errors = append(rep.Errors, report.Error{Message: "chain config: " + err.Error()})
			exit = report.ExitNoInput
		} else {
			in.Config = cfg
			in.Given[check.ChainConfig] = true
			id := fmt.Sprintf("in-%d", len(rep.Run.Inputs)+1)
			sum := sha256Hex(b)
			rep.Run.Inputs = append(rep.Run.Inputs, report.Input{ID: id, Kind: "genesis", Path: *chainCfg, SHA256: sum})
			idParts = append(idParts, sum)
		}
	}

	// Selection.
	var sel []string
	if *checks != "" {
		sel = splitList(*checks)
	}
	selected, unknown := selectRows(sel)
	var required []string
	if *requireDecided != "" {
		ids, err := readIDs(*requireDecided)
		if err != nil {
			fmt.Fprintf(stderr, "check: %v\n", err)
			return report.ExitUsage
		}
		required = ids
		for _, id := range ids {
			if _, ok := catalog.Lookup(id); !ok {
				unknown = append(unknown, id)
			} else if _, ok := catalog.RowOf(id); ok {
				selected[id] = true
			}
		}
	}

	// Checkers.
	out := check.Run(context.Background(), in, selected)
	for _, m := range out.Errors {
		rep.Errors = append(rep.Errors, report.Error{Message: m})
		exit = maxExit(exit, report.ExitInternal)
	}
	var entries []report.Entry
	for _, id := range sortedKeys(selected) {
		row, _ := catalog.RowOf(id)
		e := report.Entry{ID: id, Checker: row.Checker}
		c, ok := check.ForRequirement(id)
		switch {
		case !ok:
			e.NotRun, e.Detail = true, "no checker for this requirement in this build yet"
		case out.Missing[c.Name()] != nil:
			e.Checker = c.Name()
			e.Undecided = verdict.MissingData
			e.Detail = fmt.Sprintf("the checker needs input of kind %v", out.Missing[c.Name()])
		case !out.Ran[c.Name()]:
			e.Checker = c.Name()
			e.Undecided = verdict.MissingData
			e.Detail = "the checker failed; see errors"
		default:
			e.Checker = c.Name()
			e.Instances = out.Instances[id]
		}
		entries = append(entries, e)
	}
	seen := map[string]bool{}
	for _, id := range unknown {
		if seen[id] || selected[id] {
			continue
		}
		seen[id] = true
		entries = append(entries, report.Entry{ID: id, Undecided: verdict.NotInBuild,
			Detail: "this build does not know the requirement; it has no checker for it"})
	}
	for _, e := range entries {
		rep.Results = append(rep.Results, report.MakeResult(e))
	}
	report.SortResults(rep.Results)
	for _, o := range out.Observations {
		rep.Observations = append(rep.Observations, observation(len(rep.Observations)+1, o))
	}

	// Summary and exit code.
	pol := report.Policy{FailOn: map[string]bool{}, RequireDecided: required, MinCoverage: *minCoverage}
	for _, s := range splitList(*failOn) {
		pol.FailOn[s] = true
	}
	sum, problems := report.Summarize(rep.Results, entries, pol)
	for _, p := range problems {
		rep.Errors = append(rep.Errors, report.Error{Message: "coverage policy: " + p})
	}
	sum.Observations = len(rep.Observations)
	exit = combineExit(exit, sum.ExitCode)
	sum.ExitCode = exit
	rep.Summary = sum

	options := map[string]any{"checks": sel, "fail_on": splitList(*failOn), "min_coverage": *minCoverage}
	if *requireDecided != "" {
		options["require_decided"] = required
	}
	fillRun(rep, "check", append(idParts, fmt.Sprint(options), *clockModel), started)
	rep.Run.Clock = report.Clock{Model: *clockModel, SkewMs: *skew, SchedMs: *sched, MarginMs: *margin}
	rep.Run.Options = options
	if err := writeReport(*outPath, stdout, rep); err != nil {
		fmt.Fprintf(stderr, "check: %v\n", err)
		return report.ExitInternal
	}
	return exit
}

// selectRows returns the catalog rows chosen by the selection tokens, and
// the requirement IDs among the tokens that this build does not know.
func selectRows(tokens []string) (map[string]bool, []string) {
	sel := map[string]bool{}
	var unknown []string
	rows := catalog.Rows()
	if len(tokens) == 0 {
		for _, r := range rows {
			sel[r.Requirement] = true
		}
		return sel, nil
	}
	for _, t := range tokens {
		switch {
		case catalog.ValidID(t):
			if _, ok := catalog.RowOf(t); ok {
				sel[t] = true
			} else {
				unknown = append(unknown, t)
			}
		case t == "P0" || t == "P1" || t == "P2" || t == "V":
			for _, r := range rows {
				if r.Priority == t {
					sel[r.Requirement] = true
				}
			}
		default:
			for _, r := range rows {
				if ok, _ := path.Match(t, r.Checker); ok {
					sel[r.Requirement] = true
				}
			}
		}
	}
	return sel, unknown
}

func nodesOf(set *events.Set) []report.Node {
	inputs := map[string][]string{}
	for _, x := range set.Inputs {
		for _, n := range x.Nodes {
			inputs[n] = append(inputs[n], x.ID)
		}
	}
	senders := map[string]bool{}
	for _, r := range set.Runs {
		for _, e := range r.Events {
			if e.Kind == "SEND" && e.Str("cause") == "broadcast" {
				senders[r.Node] = true
				break
			}
		}
	}
	var out []report.Node
	for _, n := range sortedKeysOf(set.Nodes) {
		info := set.Nodes[n]
		role := "unknown"
		if senders[n] {
			role = "validator"
		}
		out = append(out, report.Node{ID: n, Address: n, Impl: info.Impl, Role: role, Inputs: inputs[n]})
	}
	return out
}

func observation(n int, o check.Observation) report.Observation {
	x := report.Observation{ID: fmt.Sprintf("OBS-%04d", n), Kind: o.Kind, Imp: o.Labels, Requirements: o.Requirements,
		Checker: o.Checker, Node: o.Node, Count: 1, Note: o.Note, Evidence: o.Instance.Evidence}
	if x.Imp == nil {
		x.Imp = []string{}
	}
	return x
}

func fillRun(rep *report.Report, command string, idParts []string, started time.Time) {
	spec := catalog.SpecInfo()
	all, obs := catalog.Counts()
	rep.Run.ID = report.RunID(append([]string{command, catalog.SHA256()}, idParts...)...)
	rep.Run.StartedAt = started.Format(time.RFC3339Nano)
	rep.Run.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	rep.Run.Inspector = report.Inspector{Version: buildinfo.Version, Commit: buildinfo.Commit(), Go: buildinfo.Go(),
		Build: buildinfo.Build(), CatalogSHA256: catalog.SHA256()}
	rep.Run.Spec = report.Spec{Repo: spec.Repo, Commit: spec.Commit, ReferenceCommit: spec.ReferenceCommit,
		RequirementCount: all, ObservableCount: obs}
	rep.Run.Command = append([]string{"wbft-inspector"}, os.Args[1:]...)
}

// combineExit returns the smallest non-zero exit code of a and b.
func combineExit(a, b int) int {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	case a < b:
		return a
	}
	return b
}

func maxExit(a, b int) int {
	if a == 0 {
		return b
	}
	return combineExit(a, b)
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeysOf[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// frameNodes lists the nodes of a frame dump.
func frameNodes(d *frames.Dump) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range d.Records {
		if !seen[r.Node] {
			seen[r.Node] = true
			out = append(out, r.Node)
		}
	}
	sort.Strings(out)
	return out
}
