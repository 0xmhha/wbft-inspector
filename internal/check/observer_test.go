package check

import (
	"context"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type observerGateModel struct{ Base }

func (observerGateModel) Run(context.Context, *Inputs, Emitter) error { return nil }

// The gate is tested with unsigned verdict metadata, not consensus messages.
func TestObserverCollectorOnlyAcceptsRawCannot(t *testing.T) {
	out := &Outcome{Instances: map[string][]verdict.Instance{}}
	var errs []string
	c := &collector{c: observerGateModel{Base{ID: "model", Reqs: []string{"WBFT-SEC-041"}}},
		want: map[string]bool{"WBFT-SEC-041": true}, out: out, errs: &errs, observationOnly: true}
	for _, v := range []verdict.Verdict{verdict.Pass, verdict.Fail, verdict.NotRun, ""} {
		c.Emit(verdict.Instance{Requirement: "WBFT-SEC-041", Verdict: v})
	}
	c.Emit(verdict.Instance{Requirement: "WBFT-SEC-040", Verdict: verdict.CannotDecide})
	if len(errs) != 5 || len(out.Instances) != 0 {
		t.Fatalf("observer escaped: %+v %v", out, errs)
	}
	c.Emit(verdict.Instance{Requirement: "WBFT-SEC-041", Verdict: verdict.CannotDecide, Reason: verdict.ObserverScope})
	if len(errs) != 5 || len(out.Instances["WBFT-SEC-041"]) != 1 {
		t.Fatalf("CANNOT observation lost: %+v %v", out, errs)
	}
}

func TestOptionalObserverFiltersLogsWithoutDroppingFrames(t *testing.T) {
	dump := &frames.Dump{Input: "unsigned-frame-model"}
	in := &Inputs{Frames: []*frames.Dump{dump}, Events: &events.Set{Runs: []*events.Run{
		{ID: "complete", FromLog: true, Complete: true},
		{ID: "incomplete", FromLog: true, Complete: false},
	}}}
	c := observerGateModel{Base{ID: "model", Kinds: []Kind{Frames}, ReadsLogs: true}}
	filtered, skipped := executionInputs(in, c, true)
	if len(filtered.Frames) != 1 || filtered.Frames[0] != dump || len(filtered.Events.Runs) != 1 ||
		filtered.Events.Runs[0].ID != "complete" || len(skipped) != 0 {
		t.Fatalf("optional filtering restored logs or lost frames: %+v %v", filtered, skipped)
	}
	_, skipped = executionInputs(in, c, false)
	if len(skipped) != 1 || skipped[0].ID != "incomplete" || len(in.Events.Runs) != 2 {
		t.Fatal("primary filtering or original input changed")
	}
	c.Kinds = []Kind{Frames, Events}
	_, skipped = executionInputs(in, c, true)
	if len(skipped) != 1 {
		t.Fatal("mandatory event input became optional")
	}
}
