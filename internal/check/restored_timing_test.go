package check

import (
	"encoding/json"
	"math"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func timingField(e *events.Event, key string, value any) {
	raw, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	e.F[key] = raw
}

func restoredTimingFixture() (*Inputs, *events.Event, *events.Event) {
	start := &events.Event{Node: "node", Run: "run", Seq: 1, TMono: 1_000_000_000, Kind: "ENGINE_START", F: map[string]json.RawMessage{}}
	timingField(start, "engine_run", 1)
	timingField(start, "replay", map[string]any{"replayed": true, "records": 1, "stopped": nil, "available": true, "enabled": true})
	arm := &events.Event{Node: "node", Run: "run", Seq: 2, TMono: 1_000_100_000, Kind: "TIMER_ARM", View: &events.View{Seq: "10", Round: "0"}, F: map[string]json.RawMessage{}}
	for key, value := range map[string]any{"engine_run": 1, "timer": "round", "gen": 17, "duration_ms": 2000, "deadline_mono_ns": 3_000_010_000, "rearmed": true} {
		timingField(arm, key, value)
	}
	step := uint64(1)
	fire := &events.Event{Node: "node", Run: "run", Seq: 3, TMono: 3_000_011_000, Kind: "TIMER_FIRE", View: &events.View{Seq: "10", Round: "0"}, Step: &step, F: map[string]json.RawMessage{}}
	for key, value := range map[string]any{"engine_run": 1, "timer": "round", "gen": 17, "stale": false} {
		timingField(fire, key, value)
	}
	run := &events.Run{Node: "node", ID: "run", Events: []*events.Event{start, arm, fire}}
	return &Inputs{Events: &events.Set{Runs: []*events.Run{run}}, Clock: Clock{SchedMs: 1, Margin: 1}}, arm, fire
}

func TestRestoredTimingUsesLogicalOriginWithoutChangingTolerance(t *testing.T) {
	in, arm, fire := restoredTimingFixture()
	old := fire.TMono - arm.TMono
	if in.Clock.Timing(old, 2_000_000_000) != verdict.CannotDecide {
		t.Fatal("fixture does not exercise the later writing timestamp")
	}
	d, why, evidence := NewTimerTiming(in).Elapsed(arm, fire)
	if why != "" || d != 2_000_001_000 || len(evidence) != 2 || evidence[0] != in.Events.Runs[0].Events[0] || evidence[1] != arm {
		t.Fatal("logical origin or original evidence lost", d, why, evidence)
	}
	if in.Clock.Timing(d, 2_000_000_000) != verdict.Pass || in.Clock.AtLeast(d, 2_000_000_000) != verdict.Pass {
		t.Fatal("valid expiry not established")
	}
	// A real early expiry remains a failure using the same clock model.
	fire.TMono = 2_900_010_000
	d, why, _ = NewTimerTiming(in).Elapsed(arm, fire)
	if why != "" || in.Clock.Timing(d, 2_000_000_000) != verdict.Fail || in.Clock.AtLeast(d, 2_000_000_000) != verdict.Fail {
		t.Fatal("real early expiry hidden", d, why)
	}
}

func TestRestoredTimingPreservesLegacyAndOrdinaryArms(t *testing.T) {
	for _, key := range []string{"deadline_mono_ns", "rearmed"} {
		t.Run(key, func(t *testing.T) {
			in, arm, fire := restoredTimingFixture()
			delete(arm.F, key)
			d, why, evidence := NewTimerTiming(in).Elapsed(arm, fire)
			if d != fire.TMono-arm.TMono || why != "" || len(evidence) != 0 {
				t.Fatal("legacy timing changed", d, why, evidence)
			}
		})
	}
}

func TestRestoredTimingRejectsUnprovenOrigins(t *testing.T) {
	tests := []struct {
		name string
		edit func(*Inputs, *events.Event, *events.Event)
	}{
		{"missing start", func(in *Inputs, _, _ *events.Event) { in.Events.Runs[0].Events = in.Events.Runs[0].Events[1:] }},
		{"source error", func(in *Inputs, _, _ *events.Event) { in.Events.Errors = []string{"damaged source"} }},
		{"unknown kind", func(in *Inputs, _, _ *events.Event) { in.Events.UnknownKinds = map[string]int{"unknown": 1} }},
		{"lost span", func(in *Inputs, _, _ *events.Event) { in.Events.Runs[0].Lost = []events.Span{{From: 2, To: 2}} }},
		{"log source", func(in *Inputs, _, _ *events.Event) { in.Events.Runs[0].FromLog = true }},
		{"log arm", func(_ *Inputs, a, _ *events.Event) { a.FromLog = true }},
		{"wrong node", func(_ *Inputs, _, f *events.Event) { f.Node = "other" }},
		{"wrong run", func(_ *Inputs, _, f *events.Event) { f.Run = "other" }},
		{"seq gap", func(_ *Inputs, _, f *events.Event) { f.Seq++ }},
		{"seq duplicate", func(_ *Inputs, _, f *events.Event) { f.Seq-- }},
		{"clock regression", func(_ *Inputs, a, f *events.Event) { f.TMono = a.TMono - 1 }},
		{"negative clock", func(_ *Inputs, a, _ *events.Event) { a.TMono = -1 }},
		{"wrong engine", func(_ *Inputs, _, f *events.Event) { timingField(f, "engine_run", 2) }},
		{"wrong generation", func(_ *Inputs, _, f *events.Event) { timingField(f, "gen", 18) }},
		{"missing generation", func(_ *Inputs, a, _ *events.Event) { delete(a.F, "gen") }},
		{"wrong view", func(_ *Inputs, _, f *events.Event) { f.View.Round = "1" }},
		{"wrong timer", func(_ *Inputs, _, f *events.Event) { timingField(f, "timer", "retry") }},
		{"stale fire", func(_ *Inputs, _, f *events.Event) { timingField(f, "stale", true) }},
		{"missing stale status", func(_ *Inputs, _, f *events.Event) { delete(f.F, "stale") }},
		{"null stale status", func(_ *Inputs, _, f *events.Event) { timingField(f, "stale", nil) }},
		{"duplicate replay status", func(in *Inputs, _, _ *events.Event) {
			in.Events.Runs[0].Events[0].F["replay"] = json.RawMessage(`{"replayed":false,"replayed":true,"records":1,"stopped":null}`)
		}},
		{"unknown replay field", func(in *Inputs, _, _ *events.Event) {
			timingField(in.Events.Runs[0].Events[0], "replay", map[string]any{"replayed": true, "records": 1, "stopped": nil, "unknown": true})
		}},
		{"missing fire step", func(_ *Inputs, _, f *events.Event) { f.Step = nil }},
		{"arm has step", func(_ *Inputs, a, f *events.Event) { a.Step = f.Step }},
		{"false rearmed", func(_ *Inputs, a, _ *events.Event) { timingField(a, "rearmed", false) }},
		{"quoted deadline", func(_ *Inputs, a, _ *events.Event) { timingField(a, "deadline_mono_ns", "3000010000") }},
		{"null deadline", func(_ *Inputs, a, _ *events.Event) { timingField(a, "deadline_mono_ns", nil) }},
		{"overflow deadline", func(_ *Inputs, a, _ *events.Event) { a.F["deadline_mono_ns"] = json.RawMessage("9223372036854775808") }},
		{"negative duration", func(_ *Inputs, a, _ *events.Event) { timingField(a, "duration_ms", -1) }},
		{"overflow duration", func(_ *Inputs, a, _ *events.Event) { timingField(a, "duration_ms", int64(math.MaxInt64/1_000_000+1)) }},
		{"origin before start", func(_ *Inputs, a, _ *events.Event) { timingField(a, "deadline_mono_ns", 2_000_000_000) }},
		{"origin after write", func(_ *Inputs, a, _ *events.Event) { timingField(a, "deadline_mono_ns", 3_100_000_000) }},
	}
	for _, state := range []string{"cancelled", "replaced", "stopped", "new engine", "core step before restore"} {
		state := state
		tests = append(tests, struct {
			name string
			edit func(*Inputs, *events.Event, *events.Event)
		}{state, func(in *Inputs, a, f *events.Event) {
			run := in.Events.Runs[0]
			extra := &events.Event{Node: run.Node, Run: run.ID, Seq: 3, TMono: a.TMono + 1, Kind: "TIMER_CANCEL", F: map[string]json.RawMessage{}}
			timingField(extra, "timer", "round")
			switch state {
			case "replaced":
				extra.Kind = "TIMER_ARM"
			case "stopped":
				extra.Kind = "ENGINE_STOP"
			case "new engine":
				extra.Kind = "ENGINE_START"
			case "core step before restore":
				extra.Kind, extra.Seq, extra.TMono, extra.Step = "ROUND_ENTER", 2, a.TMono-1, f.Step
				a.Seq, f.Seq = 3, 4
				run.Events = []*events.Event{run.Events[0], extra, a, f}
				return
			}
			f.Seq = 4
			run.Events = []*events.Event{run.Events[0], a, extra, f}
		}})
	}
	for name, replay := range map[string]map[string]any{
		"replay failed":       {"replayed": false, "records": 1, "stopped": nil},
		"no replay records":   {"replayed": true, "records": 0, "stopped": nil},
		"quoted replay count": {"replayed": true, "records": "1", "stopped": nil},
		"partial replay":      {"replayed": true, "records": 1, "stopped": "incomplete"},
		"WAL unavailable":     {"replayed": true, "records": 1, "stopped": nil, "available": false},
		"replay disabled":     {"replayed": true, "records": 1, "stopped": nil, "enabled": false},
	} {
		tests = append(tests, struct {
			name string
			edit func(*Inputs, *events.Event, *events.Event)
		}{name, func(in *Inputs, _, _ *events.Event) { timingField(in.Events.Runs[0].Events[0], "replay", replay) }})
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in, arm, fire := restoredTimingFixture()
			test.edit(in, arm, fire)
			if _, why, evidence := NewTimerTiming(in).Elapsed(arm, fire); why == "" || len(evidence) != 0 {
				t.Fatal("unproven restored origin accepted", why, evidence)
			}
		})
	}
}

func TestRestoredTimingKeepsProvedPrefixAfterShutdown(t *testing.T) {
	in, arm, fire := restoredTimingFixture()
	stop := &events.Event{Node: "node", Run: "run", Seq: 4, TMono: fire.TMono + 1, Kind: "ENGINE_STOP"}
	in.Events.Runs[0].Events = append(in.Events.Runs[0].Events, stop)
	if d, why, _ := NewTimerTiming(in).Elapsed(arm, fire); why != "" || d != 2_000_001_000 {
		t.Fatal("later shutdown changed an earlier proved expiry", d, why)
	}
}
