package check

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type retryPolicyTestChecker struct{ Base }

func (retryPolicyTestChecker) Run(context.Context, *Inputs, Emitter) error { return nil }

func retryPolicyTestInputs() *Inputs {
	start := func(run, input, names string) *events.Run {
		return &events.Run{Node: "0xaa", ID: run, Input: input, Events: []*events.Event{{Node: "0xaa", Run: run, Input: input, Kind: "NODE_START", F: map[string]json.RawMessage{"improvements": json.RawMessage(names)}}}}
	}
	return &Inputs{Events: &events.Set{Runs: []*events.Run{start("on", "events-on", `[{"name":"round_change_retry","source":"node"}]`), start("off", "events-off", `[]`)}, Nodes: map[string]*events.NodeInfo{"0xaa": {Address: "0xaa", Optional: true, Behaviours: []string{"round_change_retry"}}}}}
}
func TestRetryPolicyGatesBeforeCollectorRetainsPassOrFail(t *testing.T) {
	in := retryPolicyTestInputs()
	index := newRetryPolicyIndex(in)
	for _, initial := range []verdict.Verdict{verdict.Pass, verdict.Fail} {
		for _, req := range []string{"WBFT-TIMER-003", "WBFT-TIMER-020"} {
			out := &Outcome{Instances: map[string][]verdict.Instance{}}
			checker := retryPolicyTestChecker{Base{ID: "normal-policy", Reqs: []string{req}}}
			collector := &collector{retry: index, c: checker, want: map[string]bool{req: true}, out: out, errs: &out.Errors}
			for _, run := range []string{"on", "off"} {
				collector.Emit(verdict.Instance{Requirement: req, Node: "0xaa", Source: "events-" + run, Key: "event:" + run + ":1", Verdict: initial})
			}
			applyOptional(in, out)
			got := out.Instances[req]
			if len(got) != 2 || got[0].Verdict != verdict.CannotDecide || got[0].Reason != verdict.NotInBuild || got[1].Verdict != initial {
				t.Fatal("run policy or initial/later interval verdict escaped gate", got)
			}
		}
	}
	unrelated := verdict.Instance{Requirement: "WBFT-HDR-001", Node: "0xaa", Source: "events-on", Key: "event:on:2", Verdict: verdict.Fail}
	out := &Outcome{Instances: map[string][]verdict.Instance{unrelated.Requirement: {index.gate(unrelated)}}}
	applyOptional(in, out)
	if out.Instances[unrelated.Requirement][0].Verdict != verdict.Fail {
		t.Fatal("unrelated failure softened")
	}
	wrongInput := verdict.Instance{Requirement: "WBFT-TIMER-003", Node: "0xaa", Source: "unrelated-input", Key: "event:on:1", Verdict: verdict.Fail}
	if got := index.gate(wrongInput); got.Verdict != verdict.CannotDecide || got.Reason != verdict.MissingData {
		t.Fatal("missing input declaration was inferred from another input", got)
	}
}
func TestRetryPolicyFramesRequireTheirOwnDeclarationAndSources(t *testing.T) {
	for _, tc := range []struct {
		name         string
		decl, source json.RawMessage
		code, cause  string
		want         verdict.Verdict
		reason       verdict.Reason
	}{
		{"legacy", nil, nil, "0x15", "retry", verdict.Fail, ""},
		{"missing-frame-policy-in-known-retry-run", nil, nil, "0x15", "retry", verdict.CannotDecide, verdict.MissingData},
		{"declared", json.RawMessage(`{"profile":"1","max_interval_ms":"8000"}`), nil, "0x15", "retry", verdict.CannotDecide, verdict.NotInBuild},
		{"uppercase", json.RawMessage(`{"profile":"1"}`), nil, "0X15", "retry", verdict.CannotDecide, verdict.NotInBuild},
		{"suppressed-no-code", json.RawMessage(`{"profile":"1"}`), nil, "", "retry", verdict.CannotDecide, verdict.NotInBuild},
		{"unknown", json.RawMessage(`{"profile":"99"}`), nil, "0x15", "retry", verdict.CannotDecide, verdict.NotInBuild},
		{"source-no-declaration", nil, json.RawMessage(`{"version":"1"}`), "0x15", "retry", verdict.CannotDecide, verdict.MissingData},
		{"unrelated-code", json.RawMessage(`{"profile":"1"}`), nil, "0x13", "relay", verdict.Fail, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := &frames.Record{Input: "frames", Node: "0xaa", Run: "on", Seq: 2, Code: tc.code, Cause: tc.cause, RoundChangeRetry: tc.decl, RoundChangeRetrySource: tc.source}
			in := retryPolicyTestInputs()
			if tc.name == "legacy" {
				in.Events = nil
			}
			in.Frames = []*frames.Dump{{Records: []*frames.Record{r}}}
			index := newRetryPolicyIndex(in)
			for _, req := range []string{"WBFT-TIMER-024", "WBFT-NET-023", "WBFT-NET-032"} {
				got := index.gate(FrameInstance(req, r, verdict.Fail, "", "normal metadata fixture"))
				if got.Verdict != tc.want || got.Reason != tc.reason {
					t.Fatal(req, got)
				}
			}
		})
	}
}
func TestRetryPolicySameScopeConflictIsUndecidable(t *testing.T) {
	in := retryPolicyTestInputs()
	duplicate := *in.Events.Runs[0].Events[0]
	duplicate.F = map[string]json.RawMessage{"improvements": json.RawMessage(`[]`)}
	in.Events.Runs[0].Events = append(in.Events.Runs[0].Events, &duplicate)
	got := newRetryPolicyIndex(in).gate(verdict.Instance{Requirement: "WBFT-TIMER-003", Node: "0xaa", Source: "events-on", Key: "event:on:2", Verdict: verdict.Pass})
	if got.Verdict != verdict.CannotDecide || got.Reason != verdict.InconsistentInput {
		t.Fatal(got)
	}
}
