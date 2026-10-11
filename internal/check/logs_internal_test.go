package check

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// seenRuns is a checker that records the runs it was given.
type seenRuns struct {
	Base
	seen []string
}

func (c *seenRuns) Run(_ context.Context, in *Inputs, _ Emitter) error {
	for _, r := range in.Events.Runs {
		c.seen = append(c.seen, r.ID)
	}
	return nil
}

type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

// TestLogRunGate: a checker that judges logs reads the stream run and the
// complete log run, and gets LOG_LEVEL for the incomplete one; a checker
// that does not reads the stream run only and gets NEEDS_NODE_FEATURE for
// both log runs.
func TestLogRunGate(t *testing.T) {
	set := &events.Set{Runs: []*events.Run{
		{ID: "stream", Node: "0xaa"},
		{ID: "log-1", Node: "0xbb", Input: "log-1", FromLog: true, Complete: true},
		{ID: "log-2", Node: "0xcc", Input: "log-2", FromLog: true},
	}}
	in := &Inputs{Events: set, Given: map[Kind]bool{Events: true}}
	for _, c := range []struct {
		judges bool
		seen   []string
		skip   map[string]verdict.Reason
	}{
		{true, []string{"stream", "log-1"}, map[string]verdict.Reason{"logrun:log-2": verdict.LogLevel}},
		{false, []string{"stream"}, map[string]verdict.Reason{"logrun:log-1": verdict.NeedsNodeFeature, "logrun:log-2": verdict.NeedsNodeFeature}},
	} {
		ch := &seenRuns{Base: Base{ID: "x", Reqs: []string{"R-1", "R-2"}, ReadsLogs: c.judges}}
		cin, skipped := forChecker(in, ch)
		var out sink
		for _, r := range skipped {
			skipLogRun(ch, r, &out)
		}
		if err := ch.Run(context.Background(), cin, &out); err != nil {
			t.Fatal(err)
		}
		if len(ch.seen) != len(c.seen) || ch.seen[0] != c.seen[0] || ch.seen[len(ch.seen)-1] != c.seen[len(c.seen)-1] {
			t.Errorf("judges=%v: saw %v, want %v", c.judges, ch.seen, c.seen)
		}
		if len(out) != 2*len(c.skip) {
			t.Fatalf("judges=%v: instances %+v", c.judges, out)
		}
		for _, x := range out {
			if x.Verdict != verdict.CannotDecide || x.Reason != c.skip[x.Key] {
				t.Errorf("judges=%v: %+v", c.judges, x)
			}
		}
		if len(set.Runs) != 3 {
			t.Fatal("the gate changed the caller's set")
		}
	}
	// Without log runs the inputs pass through.
	plain := &Inputs{Events: &events.Set{Runs: []*events.Run{{ID: "stream"}}}}
	if cin, skipped := forChecker(plain, &seenRuns{}); cin != plain || skipped != nil {
		t.Fatal("inputs without log runs were copied")
	}
}

// TestApplyLost: a FAIL anchored at an event of a run that lost records
// becomes MISSING_DATA; a PASS there, a FAIL of another run and a FAIL
// anchored at a frame are kept.
func TestApplyLost(t *testing.T) {
	in := &Inputs{Events: &events.Set{Runs: []*events.Run{
		{ID: "r1", Node: "0xaa", Lost: []events.Span{{From: 7, To: 9}}},
		{ID: "r2", Node: "0xaa"},
	}}}
	out := &Outcome{Instances: map[string][]verdict.Instance{"R-1": {
		{Requirement: "R-1", Node: "0xaa", Key: "event:r1:3", Verdict: verdict.Fail, Message: "m"},
		{Requirement: "R-1", Node: "0xaa", Key: "event:r1:4", Verdict: verdict.Pass},
		{Requirement: "R-1", Node: "0xaa", Key: "event:r2:3", Verdict: verdict.Fail},
		{Requirement: "R-1", Node: "0xaa", Key: "frame:r1:3", Verdict: verdict.Fail},
	}}}
	applyLost(in, out)
	got := out.Instances["R-1"]
	if got[0].Verdict != verdict.CannotDecide || got[0].Reason != verdict.MissingData || got[0].Message == "m" {
		t.Errorf("lost run FAIL %+v", got[0])
	}
	for _, x := range got[1:] {
		if x.Reason != "" {
			t.Errorf("changed %+v", x)
		}
	}
}
