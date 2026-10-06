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
