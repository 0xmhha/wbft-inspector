package sec

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/report"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// Model observations are unsigned metadata. They are not recovered packets.
func modelPrepare(digest string, nested bool, index int) prepareObservationWitness {
	return prepareObservationWitness{Input: "capture", Node: "node", Run: "run", Sequence: "18446744073709551617",
		Round: "4294967299", Code: message.CodePrepare, Signer: "signer", Digest: digest,
		Signature: "unsigned-model-" + digest, Nested: nested, Index: index,
		Pointer: evidence.Pointer{Kind: evidence.KindFrame, Input: "capture", FrameID: digest, Field: "model"},
		Binding: prepareObservationBinding{Status: "unbound", Reason: "model"}}
}

func TestUnsignedPreparePairRepresentativeModel(t *testing.T) {
	a, b, nestedA, nestedB := modelPrepare("a", false, -1), modelPrepare("b", false, -1),
		modelPrepare("a", true, 0), modelPrepare("b", true, 1)
	for _, test := range []struct {
		name  string
		votes []prepareObservationWitness
		want  int
	}{
		{"outer_only", []prepareObservationWitness{a, b}, 0},
		{"same_digest", []prepareObservationWitness{a, nestedA, nestedA}, 0},
		{"mixed", []prepareObservationWitness{a, nestedB}, 1},
		{"nested_first", []prepareObservationWitness{nestedA, b}, 1},
		{"nested_pair", []prepareObservationWitness{nestedA, nestedB}, 1},
		{"later_nested_same_first", []prepareObservationWitness{a, b, nestedA}, 1},
		{"one_representative", []prepareObservationWitness{a, nestedB, nestedA, b}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			pairs := representativePreparePairs(test.votes)
			if len(pairs) != test.want {
				t.Fatalf("got %+v", pairs)
			}
			if len(pairs) > 0 && (pairs[0][0].Digest == pairs[0][1].Digest || !pairs[0][0].Nested && !pairs[0][1].Nested) {
				t.Fatal("not a qualifying pair")
			}
		})
	}
	for _, change := range []func(*prepareObservationWitness){
		func(v *prepareObservationWitness) { v.Input = "another" },
		func(v *prepareObservationWitness) { v.Node = "another" },
		func(v *prepareObservationWitness) { v.Run = "another" },
		func(v *prepareObservationWitness) { v.Sequence = "18446744073709551618" },
		func(v *prepareObservationWitness) { v.Round = "4294967300" },
		func(v *prepareObservationWitness) { v.Signer = "another" },
		func(v *prepareObservationWitness) { v.Code = message.CodeCommit },
	} {
		other := nestedB
		change(&other)
		if pairs := representativePreparePairs([]prepareObservationWitness{a, other}); len(pairs) != 0 {
			t.Fatalf("cross-scope pair %+v", pairs)
		}
	}
	first := representativePreparePairs([]prepareObservationWitness{nestedA, b})[0]
	if !first[0].Nested || first[1].Nested {
		t.Fatal("representative order changed")
	}
	boundLater := nestedB
	boundLater.Index = 9
	boundLater.Binding.Status = "node_membership_observed"
	pair := representativePreparePairs([]prepareObservationWitness{a, nestedB, boundLater})[0]
	if pair[1].Index != 1 || pair[1].Binding.Status != "unbound" {
		t.Fatal("later binding silently replaced the original representative")
	}
	pointer := &evidence.Pointer{Kind: evidence.KindEvent, Line: 7}
	nestedB.Binding.Outcome = pointer
	copyPair := representativePreparePairs([]prepareObservationWitness{a, nestedB})[0]
	pointer.Line = 99
	if copyPair[1].Binding.Outcome.Line != 7 {
		t.Fatal("representative aliases an input outcome pointer")
	}
}

func modelOutcome() *events.Event {
	step := uint64(7)
	f := map[string]json.RawMessage{}
	for k, v := range map[string]any{"code": 21, "dedup_key": "key", "row": 5, "via": "direct", "check": "INVALID", "source": "outer", "peer": "peer"} {
		f[k], _ = json.Marshal(v)
	}
	return &events.Event{Input: "events", Node: "node", Run: "run", Seq: 11, Kind: "MSG_OUTCOME",
		View: &events.View{Seq: "10", Round: "2"}, Step: &step, F: f}
}

func TestUnsignedPerSightingBindingModel(t *testing.T) {
	peer := "peer"
	r := &frames.Record{Node: "node", Run: "run", Peer: &peer}
	id := prepareContainerIdentity{DedupKey: "key", Code: 21, Sequence: "10", Round: "2", Signer: "outer"}
	bind := func(eventsIn ...*events.Event) prepareObservationBinding {
		set := &events.Set{Runs: []*events.Run{{Node: "node", ID: "run", Events: eventsIn}}}
		return bindPrepareObservation(id, r, 1, prepareOutcomeClaims(set, "node", "run"))
	}
	if got := bind(modelOutcome()); got.Status != "node_membership_observed" || got.Outcome == nil {
		t.Fatalf("valid IGNORE/invalid semantic row lost: %+v", got)
	}
	for _, mutate := range []func(*events.Event){
		func(e *events.Event) { e.F["via"] = json.RawMessage(`"backlog"`) },
		func(e *events.Event) { e.F["check"] = json.RawMessage(`"prefilter"`) },
		func(e *events.Event) { e.F["row"] = json.RawMessage(`2`) },
		func(e *events.Event) { e.F["row"] = json.RawMessage(`29`) },
		func(e *events.Event) { e.F["source"] = json.RawMessage(`"other"`) },
		func(e *events.Event) { e.F["peer"] = json.RawMessage(`"other"`) },
		func(e *events.Event) { e.F["dedup_key"] = json.RawMessage(`"other"`) },
		func(e *events.Event) { e.View.Round = "3" },
		func(e *events.Event) { e.Run = "another" },
		func(e *events.Event) { e.Step = nil },
	} {
		e := modelOutcome()
		mutate(e)
		if got := bind(e); got.Status == "node_membership_observed" {
			t.Fatalf("unbound model granted authority: %+v", e)
		}
	}
	if got := bind(modelOutcome(), modelOutcome()); got.Status != "ambiguous" {
		t.Fatalf("duplicate outcomes: %+v", got)
	}
	for _, mutate := range []func(*events.Event){
		func(e *events.Event) { e.View.Round = "3" },
		func(e *events.Event) { e.View = nil },
		func(e *events.Event) { e.F["code"] = json.RawMessage(`19`) },
		func(e *events.Event) { delete(e.F, "code") },
		func(e *events.Event) { e.F["source"] = json.RawMessage(`"another"`) },
		func(e *events.Event) { e.F["row"] = json.RawMessage(`2`) },
	} {
		conflict := modelOutcome()
		mutate(conflict)
		if got := bind(modelOutcome(), conflict); got.Status != "ambiguous" {
			t.Fatalf("good claim hid a contradiction: %+v", got)
		}
	}
	if got := bindPrepareObservation(id, r, 2, prepareClaims{}); got.Status != "ambiguous" {
		t.Fatalf("duplicate frames: %+v", got)
	}
	if got := bind(); got.Status != "unbound" {
		t.Fatal(got)
	}
}

func TestIncompleteCaptureLeavesUnsignedPairModelUnbound(t *testing.T) {
	peer := "peer"
	r := &frames.Record{Node: "node", Run: "run", Peer: &peer}
	id := prepareContainerIdentity{DedupKey: "key", Code: 21, Sequence: "10", Round: "2", Signer: "outer"}
	for _, run := range []*events.Run{
		{Node: "node", ID: "run", FromLog: true, Complete: false, Events: []*events.Event{modelOutcome()}},
		{Node: "node", ID: "run", Lost: []events.Span{{From: 1, To: 2}}, Events: []*events.Event{modelOutcome()}},
	} {
		claims := prepareOutcomeClaims(&events.Set{Runs: []*events.Run{run}}, "node", "run")
		binding := bindPrepareObservation(id, r, 1, claims)
		if binding.Status != "unbound" || binding.Reason != "capture_incomplete" {
			t.Fatalf("incomplete matching outcome granted authority: %+v", binding)
		}
		a, b := modelPrepare("a", false, -1), modelPrepare("b", true, 0)
		a.Binding, b.Binding = binding, binding
		inst := prepareObservationInstance(representativePreparePairs([]prepareObservationWitness{a, b})[0])
		result := report.MakeResult(report.Entry{ID: reqReported, Instances: []verdict.Instance{inst}})
		encoded, err := json.Marshal(result)
		if err != nil || len(inst.Evidence) != 2 || !strings.Contains(string(encoded), "cryptographic_candidate") ||
			!strings.Contains(string(encoded), "capture_incomplete") || !strings.Contains(string(encoded), `"frame_id":"a"`) ||
			!strings.Contains(string(encoded), `"frame_id":"b"`) {
			t.Fatalf("candidate or pointers lost: %s %v", encoded, err)
		}
	}
	if got := bindPrepareObservation(id, r, -1, prepareClaims{}); got.Status != "unbound" {
		t.Fatal("dropped frame context granted membership binding", got)
	}
}

// This serializes unsigned model results through the real report renderer;
// it is not a conflicting signed-pair CLI or cryptographic end-to-end test.
func TestUnsignedPrepareObservationReportJSON(t *testing.T) {
	a, b := modelPrepare("a", false, -1), modelPrepare("b", true, 0)
	inst := prepareObservationInstance(representativePreparePairs([]prepareObservationWitness{a, b})[0])
	if inst.Verdict != verdict.CannotDecide || len(inst.Evidence) != 2 {
		t.Fatal(inst)
	}
	result := report.MakeResult(report.Entry{ID: reqReported, Instances: []verdict.Instance{
		{Requirement: reqReported, Verdict: verdict.Pass, Node: "node"}, inst}})
	if result.Reason == nil || result.Reason.Code != string(verdict.PartlyDecided) || result.Coverage.Pass != 1 || result.Coverage.CannotDecide != 1 {
		t.Fatalf("aggregate %+v", result)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{prepareObservationSchema, "cryptographic_candidate", "unsigned-model-a", "unsigned-model-b", "frame_id"} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("missing %s from %s", want, encoded)
		}
	}
	var document bytes.Buffer
	if err := report.Write(&document, &report.Report{Schema: report.SchemaID, Results: []report.Result{result}}); err != nil {
		t.Fatal(err)
	}
	var parsed report.Report
	if err := json.Unmarshal(document.Bytes(), &parsed); err != nil || parsed.Schema != report.SchemaID ||
		len(parsed.Results) != 1 || len(parsed.Results[0].UndecidedSamples) != 1 ||
		len(parsed.Results[0].UndecidedSamples[0].Evidence) != 2 {
		t.Fatalf("report roundtrip %+v %v", parsed, err)
	}
	a.Binding.Status = "node_membership_observed"
	p := representativePreparePairs([]prepareObservationWitness{a, b})[0]
	if got := prepareObservationInstance(p).Actual.(prepareObservation).Status; got != "cryptographic_candidate" {
		t.Fatal("one bound witness promoted the pair")
	}
	b.Binding.Status = "node_membership_observed"
	p = representativePreparePairs([]prepareObservationWitness{a, b})[0]
	if got := prepareObservationInstance(p); got.Verdict != verdict.CannotDecide || got.Actual.(prepareObservation).Status != "node_membership_observed" {
		t.Fatal("conditional node claim changed the node verdict", got)
	}
}
