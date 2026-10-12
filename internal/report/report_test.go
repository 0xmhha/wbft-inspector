package report

import (
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func inst(id, node, key string, v verdict.Verdict) verdict.Instance {
	return verdict.Instance{Requirement: id, Node: node, Key: key, Verdict: v}
}

// TestSummaryKeepsOutcomesApart: passed, failed and undecided requirements
// are counted apart, partly decided ones as a part of the undecided, in the
// totals and per node; the coverage policy applies to partly decided
// results.
func TestSummaryKeepsOutcomesApart(t *testing.T) {
	entries := []Entry{
		{ID: "WBFT-SM-011", Instances: []verdict.Instance{inst("WBFT-SM-011", "n1", "a", verdict.Pass), inst("WBFT-SM-011", "n2", "b", verdict.Pass)}},
		{ID: "WBFT-SM-012", Instances: []verdict.Instance{inst("WBFT-SM-012", "n1", "a", verdict.Pass), inst("WBFT-SM-012", "n2", "b", verdict.CannotDecide)}},
		{ID: "WBFT-SM-013", Instances: []verdict.Instance{inst("WBFT-SM-013", "n1", "a", verdict.Pass), inst("WBFT-SM-013", "n2", "b", verdict.Fail)}},
		{ID: "WBFT-SM-014", Instances: []verdict.Instance{inst("WBFT-SM-014", "n1", "a", verdict.CannotDecide)}},
		{ID: "WBFT-SM-015", NotRun: true},
	}
	var results []Result
	for _, e := range entries {
		results = append(results, MakeResult(e))
	}
	want := map[string]string{"WBFT-SM-011": "PASS", "WBFT-SM-012": "CANNOT_DECIDE/PARTLY_DECIDED", "WBFT-SM-013": "FAIL",
		"WBFT-SM-014": "CANNOT_DECIDE/MISSING_DATA", "WBFT-SM-015": "NOT_RUN"}
	for _, r := range results {
		got := r.Verdict
		if r.Reason != nil && r.Reason.Code != "" {
			got += "/" + r.Reason.Code
		}
		if got != want[r.Requirement] {
			t.Errorf("%s: %s, want %s", r.Requirement, got, want[r.Requirement])
		}
	}
	if r := results[1]; r.Coverage.Pass != 1 || r.Coverage.CannotDecide != 1 || !strings.Contains(r.Reason.Detail, "1 of 2 instances passed") {
		t.Errorf("partly decided result: %+v %+v", r.Coverage, r.Reason)
	}

	s, problems := Summarize(results, entries, Policy{MinCoverage: 0.6})
	if c := s.Requirements; c != (Counts{Total: 5, Pass: 1, Fail: 1, CannotDecide: 2, PartlyDecided: 1, NotRun: 1}) {
		t.Errorf("counts %+v", c)
	}
	// n2 alone: SM-011 passed, SM-012 undecided only, SM-013 failed.
	if c := s.ByNode["n2"]; c != (Counts{Total: 3, Pass: 1, Fail: 1, CannotDecide: 1}) {
		t.Errorf("n2 counts %+v", c)
	}
	if len(problems) != 1 || !strings.HasPrefix(problems[0], "WBFT-SM-012: coverage 0.5000 below 0.6000") {
		t.Errorf("problems %v", problems)
	}
	if s.ExitCode != ExitCoverage {
		t.Errorf("exit %d", s.ExitCode)
	}
	line := s.Requirements.Line()
	if line != "5 requirements: 1 passed, 1 failed, 2 could not be decided (1 of them partly passed), 1 not run" {
		t.Errorf("line %q", line)
	}
}
