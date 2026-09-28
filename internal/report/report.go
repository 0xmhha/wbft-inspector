// Package report writes the inspector report: one JSON document with the
// run description (run), the requirement verdicts (results), findings that
// are not verdicts (observations), the vector runner results (vectors) and
// tool errors (errors). The format is schema/report-v1.json
// ("wbft-inspector-report/1").
//
// Reports are deterministic: the same inputs and options give the same
// document except run.started_at and run.finished_at. Results are sorted by
// requirement ID, findings by node and instance key.
package report

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/vector"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// SchemaID is the value of the "schema" field.
const SchemaID = "wbft-inspector-report/1"

// Report is the whole document.
type Report struct {
	Schema       string        `json:"schema"`
	Run          Run           `json:"run"`
	Summary      Summary       `json:"summary"`
	Results      []Result      `json:"results"`
	Observations []Observation `json:"observations"`
	Vectors      *Vectors      `json:"vectors,omitempty"`
	Errors       []Error       `json:"errors"`
}

// Run describes what was run on which inputs with which tool.
type Run struct {
	ID         string         `json:"id"`
	StartedAt  string         `json:"started_at"`
	FinishedAt string         `json:"finished_at"`
	Inspector  Inspector      `json:"inspector"`
	Spec       Spec           `json:"spec"`
	Command    []string       `json:"command"`
	Inputs     []Input        `json:"inputs"`
	Nodes      []Node         `json:"nodes"`
	Clock      Clock          `json:"clock"`
	Options    map[string]any `json:"options"`
}

// Inspector identifies the tool and its build.
type Inspector struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	Go            string `json:"go"`
	Build         string `json:"build"`
	CatalogSHA256 string `json:"catalog_sha256"`
}

// Spec identifies the specification the build knows.
type Spec struct {
	Repo             string `json:"repo"`
	Commit           string `json:"commit"`
	ReferenceCommit  string `json:"reference_commit"`
	RequirementCount int    `json:"requirement_count"`
	ObservableCount  int    `json:"observable_count"`
}

// Input is one input of the run.
type Input struct {
	ID        string     `json:"id"`
	Kind      string     `json:"kind"`
	Node      string     `json:"node,omitempty"`
	Path      string     `json:"path,omitempty"`
	SHA256    string     `json:"sha256,omitempty"`
	Records   int        `json:"records,omitempty"`
	TimeRange *TimeRange `json:"time_range,omitempty"`
	Impl      *Impl      `json:"impl,omitempty"`
}

// TimeRange is the first and last timestamp of an input.
type TimeRange struct {
	First string `json:"first"`
	Last  string `json:"last"`
}

// Impl describes a vector adapter as its hello reported it.
type Impl struct {
	Cmd          []string `json:"cmd"`
	Name         string   `json:"name"`
	Version      string   `json:"version"`
	Commit       string   `json:"commit"`
	Lang         string   `json:"lang"`
	Handlers     []string `json:"handlers"`
	Build        string   `json:"build"`
	Improvements []string `json:"improvements"`
}

// Node is a node seen in the inputs.
type Node struct {
	ID      string   `json:"id"`
	Address string   `json:"address,omitempty"`
	Impl    string   `json:"impl,omitempty"`
	Role    string   `json:"role"`
	Inputs  []string `json:"inputs,omitempty"`
}

// Clock is the clock model of the run.
type Clock struct {
	Model    string  `json:"model"`
	SkewMs   float64 `json:"skew_ms"`
	SchedMs  float64 `json:"sched_ms"`
	MarginMs float64 `json:"margin_ms"`
}

// Counts counts requirement verdicts.
type Counts struct {
	Total        int `json:"total"`
	Pass         int `json:"pass"`
	Fail         int `json:"fail"`
	CannotDecide int `json:"cannot_decide"`
	NotRun       int `json:"not_run"`
}

func (c *Counts) add(v verdict.Verdict) {
	c.Total++
	switch v {
	case verdict.Pass:
		c.Pass++
	case verdict.Fail:
		c.Fail++
	case verdict.CannotDecide:
		c.CannotDecide++
	default:
		c.NotRun++
	}
}

// Summary aggregates the results.
type Summary struct {
	Requirements   Counts            `json:"requirements"`
	ByPriority     map[string]Counts `json:"by_priority"`
	ByTag          map[string]Counts `json:"by_tag"`
	ByNode         map[string]Counts `json:"by_node,omitempty"`
	FailBySeverity map[string]int    `json:"fail_by_severity"`
	Observations   int               `json:"observations"`
	ExitCode       int               `json:"exit_code"`
}

// Result is the verdict of one requirement.
type Result struct {
	Requirement         string    `json:"requirement"`
	Tags                []string  `json:"tags"`
	Level               *string   `json:"level"`
	Priority            *string   `json:"priority"`
	Checker             string    `json:"checker"`
	CheckerVersion      int       `json:"checker_version,omitempty"`
	Verdict             string    `json:"verdict"`
	Reason              *Reason   `json:"reason,omitempty"`
	Severity            string    `json:"severity,omitempty"`
	Coverage            Coverage  `json:"coverage"`
	Violations          []Finding `json:"violations,omitempty"`
	ViolationsTruncated int       `json:"violations_truncated,omitempty"`
	UndecidedSamples    []Finding `json:"undecided_samples,omitempty"`
	VectorCases         []string  `json:"vector_cases,omitempty"`
}

// Reason explains a CANNOT_DECIDE or NOT_RUN result.
type Reason struct {
	Code   string   `json:"code,omitempty"`
	Detail string   `json:"detail,omitempty"`
	Unlock []string `json:"unlock,omitempty"`
}

// Coverage counts the instances behind a result.
type Coverage struct {
	Instances    int            `json:"instances"`
	Pass         int            `json:"pass"`
	Fail         int            `json:"fail"`
	CannotDecide int            `json:"cannot_decide"`
	Reasons      map[string]int `json:"reasons,omitempty"`
	Sources      []string       `json:"sources,omitempty"`
}

// Finding is one violation or undecided instance.
type Finding struct {
	Instance string             `json:"instance"`
	Node     string             `json:"node,omitempty"`
	Verdict  string             `json:"verdict,omitempty"`
	Reason   string             `json:"reason,omitempty"`
	Message  string             `json:"message"`
	Expected any                `json:"expected,omitempty"`
	Actual   any                `json:"actual,omitempty"`
	Step     string             `json:"step,omitempty"`
	Evidence []evidence.Pointer `json:"evidence"`
}

// Observation is a finding that is not a verdict and does not change the
// exit code.
type Observation struct {
	ID           string             `json:"id"`
	Kind         string             `json:"kind"`
	Imp          []string           `json:"imp"`
	Requirements []string           `json:"requirements,omitempty"`
	Checker      string             `json:"checker"`
	Node         string             `json:"node,omitempty"`
	Count        int                `json:"count"`
	Note         string             `json:"note,omitempty"`
	Evidence     []evidence.Pointer `json:"evidence"`
}

// Error is a tool error, not a verdict.
type Error struct {
	Input   string `json:"input,omitempty"`
	Checker string `json:"checker,omitempty"`
	Message string `json:"message"`
	At      string `json:"at,omitempty"`
}

// Entry is the material of one result.
type Entry struct {
	ID        string
	Checker   string
	Instances []verdict.Instance
	// NotRun marks a requirement whose checker did not run; Detail says why.
	NotRun bool
	Detail string
	// Undecided sets a CANNOT_DECIDE verdict with this reason when there
	// are no instances (for example NOT_IN_BUILD, MISSING_DATA).
	Undecided   verdict.Reason
	VectorCases []string
}

// MakeResult turns an entry into a result.
func MakeResult(e Entry) Result {
	res := Result{Requirement: e.ID, Checker: e.Checker, Tags: []string{}, VectorCases: e.VectorCases}
	if r, ok := catalog.Lookup(e.ID); ok {
		res.Tags = append(res.Tags, r.Tags...)
		if r.Level != "" {
			l := r.Level
			res.Level = &l
		}
		res.Severity = catalog.DefaultSeverity(e.ID)
	}
	if row, ok := catalog.RowOf(e.ID); ok {
		p := row.Priority
		res.Priority = &p
		if res.Checker == "" {
			res.Checker = row.Checker
		}
		res.CheckerVersion = 1
	}
	switch {
	case e.NotRun:
		res.Verdict = string(verdict.NotRun)
		if e.Detail != "" {
			res.Reason = &Reason{Detail: e.Detail}
		}
		return res
	case e.Undecided != "" && len(e.Instances) == 0:
		res.Verdict = string(verdict.CannotDecide)
		res.Reason = &Reason{Code: string(e.Undecided), Detail: e.Detail}
		return res
	}
	agg := verdict.Aggregate(e.Instances)
	res.Verdict = string(agg.Verdict)
	if agg.Verdict == verdict.CannotDecide {
		res.Reason = &Reason{Code: string(agg.Reason), Detail: agg.Detail}
	}
	res.Coverage = Coverage{Instances: agg.Instances, Pass: agg.Pass, Fail: agg.Fail, CannotDecide: agg.CannotDecide, Sources: agg.Sources}
	if len(agg.Reasons) > 0 {
		res.Coverage.Reasons = map[string]int{}
		for k, v := range agg.Reasons {
			res.Coverage.Reasons[string(k)] = v
		}
	}
	for _, x := range agg.Violations {
		res.Violations = append(res.Violations, finding(x))
	}
	res.ViolationsTruncated = agg.ViolationsTruncated
	for _, x := range agg.Undecided {
		res.UndecidedSamples = append(res.UndecidedSamples, finding(x))
	}
	return res
}

func finding(x verdict.Instance) Finding {
	f := Finding{Instance: x.Key, Node: x.Node, Verdict: string(x.Verdict), Reason: string(x.Reason), Message: x.Message,
		Expected: x.Expected, Actual: x.Actual, Step: x.Step, Evidence: x.Evidence}
	if f.Evidence == nil {
		f.Evidence = []evidence.Pointer{{Kind: evidence.KindComputed, Name: "instance", Value: x.Key}}
	}
	return f
}

// Policy decides the exit code.
type Policy struct {
	FailOn         map[string]bool // severities that make exit code 1
	RequireDecided []string        // requirement IDs that must not stay undecided
	MinCoverage    float64         // lower bound of pass/instances of PASS results
}

// Exit codes.
const (
	ExitOK         = 0
	ExitFail       = 1
	ExitCoverage   = 2
	ExitUnaccessed = 3
	ExitUsage      = 64
	ExitNoInput    = 69
	ExitInternal   = 70
)

// Summarize fills the summary and returns the exit code of the verdicts
// and the coverage policy. byNode are the per-node instance lists.
func Summarize(results []Result, entries []Entry, p Policy) (Summary, []string) {
	s := Summary{ByPriority: map[string]Counts{}, ByTag: map[string]Counts{}, FailBySeverity: map[string]int{}}
	var problems []string
	failing := false
	for _, r := range results {
		v := verdict.Verdict(r.Verdict)
		s.Requirements.add(v)
		prio := "none"
		if r.Priority != nil {
			prio = *r.Priority
		}
		c := s.ByPriority[prio]
		c.add(v)
		s.ByPriority[prio] = c
		for _, t := range r.Tags {
			c := s.ByTag[t]
			c.add(v)
			s.ByTag[t] = c
		}
		if v == verdict.Fail {
			s.FailBySeverity[r.Severity]++
			if p.FailOn[r.Severity] {
				failing = true
			}
		}
		if v == verdict.Pass && p.MinCoverage > 0 && r.Coverage.Instances > 0 {
			if ratio := float64(r.Coverage.Pass) / float64(r.Coverage.Instances); ratio < p.MinCoverage {
				problems = append(problems, fmt.Sprintf("%s: coverage %.4f below %.4f", r.Requirement, ratio, p.MinCoverage))
			}
		}
	}
	byID := map[string]Result{}
	for _, r := range results {
		byID[r.Requirement] = r
	}
	for _, id := range p.RequireDecided {
		r, ok := byID[id]
		switch {
		case !ok:
			problems = append(problems, id+": required to be decided but not in the report")
		case r.Verdict != string(verdict.Pass) && r.Verdict != string(verdict.Fail):
			problems = append(problems, id+": required to be decided, verdict "+r.Verdict)
		}
	}
	// Per-node verdicts: aggregate the instances of each node separately.
	nodes := map[string]map[string][]verdict.Instance{}
	for _, e := range entries {
		for _, x := range e.Instances {
			if x.Node == "" {
				continue
			}
			if nodes[x.Node] == nil {
				nodes[x.Node] = map[string][]verdict.Instance{}
			}
			nodes[x.Node][e.ID] = append(nodes[x.Node][e.ID], x)
		}
	}
	if len(nodes) > 0 {
		s.ByNode = map[string]Counts{}
		for n, reqs := range nodes {
			var c Counts
			for _, insts := range reqs {
				c.add(verdict.Aggregate(insts).Verdict)
			}
			s.ByNode[n] = c
		}
	}
	switch {
	case failing:
		s.ExitCode = ExitFail
	case len(problems) > 0:
		s.ExitCode = ExitCoverage
	}
	return s, problems
}

// RunID derives a stable UUID (version 8) from the material of a run, so
// that the same inputs and options give the same id.
func RunID(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x80
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// SortResults sorts results by requirement ID.
func SortResults(rs []Result) {
	sort.Slice(rs, func(i, j int) bool { return rs[i].Requirement < rs[j].Requirement })
}

// Write writes the report as indented JSON.
func Write(w io.Writer, r *Report) error {
	if r.Results == nil {
		r.Results = []Result{}
	}
	if r.Observations == nil {
		r.Observations = []Observation{}
	}
	if r.Errors == nil {
		r.Errors = []Error{}
	}
	if r.Run.Inputs == nil {
		r.Run.Inputs = []Input{}
	}
	if r.Run.Nodes == nil {
		r.Run.Nodes = []Node{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// Vectors is the vector runner part of a report.
type Vectors struct {
	Dir             string              `json:"dir"`
	SpecCommit      string              `json:"spec_commit,omitempty"`
	Impls           []string            `json:"impls"`
	Diagnostic      bool                `json:"diagnostic"`
	Totals          vector.Totals       `json:"totals"`
	Cases           []vector.CaseResult `json:"cases"`
	UnaccessedFiles []string            `json:"unaccessed_files"`
}
