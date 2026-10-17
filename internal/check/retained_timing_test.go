package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func retainedTimingFixture(t *testing.T, edit func(*Inputs, []map[string]any)) (*Inputs, *events.Event, *events.Event) {
	t.Helper()
	in, arm, fire := restoredTimingFixture()
	delete(arm.F, "deadline_mono_ns")
	node := "0xaa00000000000000000000000000000000000000"
	run := in.Events.Runs[0]
	run.Node = node
	for _, e := range run.Events {
		e.Node = node
	}
	fire.TWall = "2026-01-01T00:00:03.000011Z"
	run.Events = append([]*events.Event{{Node: node, Run: run.ID, Seq: 0, Kind: "NODE_START", TMono: 999_900_000}}, run.Events...)
	stop := &events.Event{Node: node, Run: run.ID, Seq: 4, Kind: "ENGINE_STOP", TMono: 4_000_003_000, F: map[string]json.RawMessage{}}
	timingField(stop, "engine_run", 1)
	run.Events = append(run.Events, stop, &events.Event{Node: node, Run: run.ID, Seq: 5, Kind: "NODE_STOP", TMono: 4_000_004_000})
	base := func(seq int, kind string, mono int64) map[string]any {
		return map[string]any{"v": 1, "node": node, "run": run.ID, "seq": seq, "type": kind, "t_mono_ns": mono, "t_wall": "2026-01-01T00:00:00Z", "journal_segment": 1, "journal_offset": seq * 100}
	}
	op := func(seq, number int, action, source string, step uint64, mono int64) map[string]any {
		r := base(seq, "timer_operation", mono)
		r["engine_run"] = 1
		r["step"] = step
		o := map[string]any{"sequence": strconv.Itoa(number), "action": action, "source": source, "output": "0", "arm_engine_run": "1", "arm_step": "0", "arm_output": "0", "arm_entry_mono_ns": "1000010000", "deadline_mono_ns": "3000010000", "decode": "complete", "timer": "round", "generation": "17", "height": "10", "round": "0", "timeout_sha256": strings.Repeat("a", 64), "cancel_kinds": []string{}}
		r["timer_operation"] = o
		return r
	}
	declaration := base(1, "scheduler_trace", 0)
	declaration["clock_source"] = "unavailable"
	declaration["t_wall"] = "1970-01-01T00:00:00Z"
	declaration["scheduler_trace"] = map[string]any{"version": "1", "operations": "5", "steps": "2"}
	armRow := op(2, 1, "arm", "restore", 0, 1_000_020_000)
	queue := op(3, 2, "queued", "restore", 0, 3_000_010_000)
	pop := op(4, 3, "pop", "dequeue", 1, 3_000_010_500)
	step := base(5, "scheduler_step", 3_000_012_000)
	step["engine_run"] = 1
	step["step"] = 1
	step["via"] = "timer"
	step["input_kind"] = "timeout"
	step["entry_t_mono_ns"] = "3000011000"
	step["entry_t_wall"] = fire.TWall
	cancel := op(6, 4, "cancel", "lifecycle", 2, 4_000_002_000)
	clear := op(8, 5, "clear", "lifecycle", 2, 4_000_002_100)
	for _, r := range []map[string]any{cancel, clear} {
		o := r["timer_operation"].(map[string]any)
		for _, k := range []string{"timer", "generation", "height", "round", "timeout_sha256"} {
			delete(o, k)
		}
		for _, k := range []string{"arm_engine_run", "arm_step", "arm_output", "arm_entry_mono_ns", "deadline_mono_ns"} {
			o[k] = "0"
		}
		o["decode"] = "not_applicable"
	}
	cancel["timer_operation"].(map[string]any)["cancel_kinds"] = []string{"round", "retry", "future"}
	terminal := base(7, "scheduler_step", 4_000_001_000)
	terminal["engine_run"] = 1
	terminal["step"] = 2
	terminal["via"] = "engine"
	terminal["input_kind"] = "stop"
	terminal["entry_t_mono_ns"] = "4000000000"
	terminal["entry_t_wall"] = "2026-01-01T00:00:04Z"
	rows := []map[string]any{declaration, armRow, queue, pop, step, cancel, terminal, clear}
	if edit != nil {
		edit(in, rows)
	}
	var raw strings.Builder
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(b)
		raw.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "frames-retained.jsonl"), []byte(raw.String()), 0600); err != nil {
		t.Fatal(err)
	}
	dump, err := frames.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	dump.SetInput("retained")
	in.Frames = append(in.Frames, dump)
	return in, arm, fire
}

func TestRetainedTimingUsesClosedSchedulerSource(t *testing.T) {
	for _, reverse := range []bool{false, true} {
		in, arm, fire := retainedTimingFixture(t, func(_ *Inputs, rows []map[string]any) {
			if reverse {
				slices.Reverse(rows)
			}
		})
		if result := frames.Validate(in.Frames[0]); len(result.Problems) != 0 {
			t.Fatal(result.Problems)
		}
		timing := NewTimerTiming(in)
		elapsed, why, original := timing.Elapsed(arm, fire)
		if elapsed != 2_000_001_000 || why != "" || len(original) != 4 {
			t.Fatal(elapsed, why, original)
		}
		instance := timing.Evidence(verdict.Instance{}, fire)
		if len(instance.Evidence) != 8 {
			t.Fatal("original scheduler positions missing", instance.Evidence)
		}
		if in.Clock.Timing(elapsed, 2_000_000_000) != verdict.Pass {
			t.Fatal("unchanged clock model did not establish expiry")
		}
	}
}

func TestRetainedTimingKeepsProvedPrefixWithLaterWritingClocks(t *testing.T) {
	in, arm, fire := retainedTimingFixture(t, func(in *Inputs, _ []map[string]any) {
		run := in.Events.Runs[0]
		later := []*events.Event{{Node: run.Node, Run: run.ID, Seq: 4, Kind: "BUILD_HANDOVER", TMono: 3_000_020_000}, {Node: run.Node, Run: run.ID, Seq: 5, Kind: "ROUND_ENTER", TMono: 3_000_011_000, Step: run.Events[3].Step}}
		run.Events[4].Seq = 6
		run.Events[5].Seq = 7
		run.Events = append(append(slices.Clone(run.Events[:4]), later...), run.Events[4:]...)
	})
	d, why, _ := NewTimerTiming(in).Elapsed(arm, fire)
	if d != 2_000_001_000 || why != "" {
		t.Fatal(d, why)
	}
}

func TestRetainedTimingRejectsIncompleteOrUnboundSources(t *testing.T) {
	cases := []struct {
		name string
		edit func(*Inputs, []map[string]any)
	}{
		{"missing declaration", func(_ *Inputs, r []map[string]any) { delete(r[0], "scheduler_trace") }},
		{"wrong count", func(_ *Inputs, r []map[string]any) { r[0]["scheduler_trace"].(map[string]any)["operations"] = "4" }},
		{"sequence gap", func(_ *Inputs, r []map[string]any) { r[3]["timer_operation"].(map[string]any)["sequence"] = "9" }},
		{"duplicate operation", func(_ *Inputs, r []map[string]any) { r[3]["timer_operation"].(map[string]any)["sequence"] = "2" }},
		{"outer sequence gap", func(_ *Inputs, r []map[string]any) { r[7]["seq"] = 9 }},
		{"wrong node", func(_ *Inputs, r []map[string]any) {
			for _, x := range r {
				x["node"] = "0xbb00000000000000000000000000000000000000"
			}
		}},
		{"wrong run", func(_ *Inputs, r []map[string]any) {
			for _, x := range r {
				x["run"] = "other"
			}
		}},
		{"wrong engine", func(_ *Inputs, r []map[string]any) { r[3]["engine_run"] = 2 }},
		{"wrong generation", func(_ *Inputs, r []map[string]any) { r[3]["timer_operation"].(map[string]any)["generation"] = "18" }},
		{"wrong view", func(_ *Inputs, r []map[string]any) { r[3]["timer_operation"].(map[string]any)["height"] = "11" }},
		{"wrong timeout hash", func(_ *Inputs, r []map[string]any) {
			r[3]["timer_operation"].(map[string]any)["timeout_sha256"] = strings.Repeat("b", 64)
		}},
		{"wrong arm source", func(_ *Inputs, r []map[string]any) { r[1]["timer_operation"].(map[string]any)["source"] = "core" }},
		{"wrong callback step", func(_ *Inputs, r []map[string]any) { r[3]["step"] = 2 }},
		{"wrong callback source", func(_ *Inputs, r []map[string]any) { r[4]["via"] = "engine" }},
		{"wrong callback kind", func(_ *Inputs, r []map[string]any) { r[4]["input_kind"] = "stop" }},
		{"wrong entry mono", func(_ *Inputs, r []map[string]any) { r[4]["entry_t_mono_ns"] = "3000011001" }},
		{"wrong entry wall", func(_ *Inputs, r []map[string]any) { r[4]["entry_t_wall"] = "2026-01-01T00:00:03.000012Z" }},
		{"queue before deadline", func(_ *Inputs, r []map[string]any) { r[2]["t_mono_ns"] = 3_000_009_999 }},
		{"pop after callback", func(_ *Inputs, r []map[string]any) { r[3]["t_mono_ns"] = 3_000_011_001 }},
		{"fractional duration mismatch", func(_ *Inputs, r []map[string]any) {
			for _, x := range r {
				if o, ok := x["timer_operation"].(map[string]any); ok && o["decode"] == "complete" {
					o["deadline_mono_ns"] = "3000009999"
				}
			}
		}},
		{"no terminal clear", func(_ *Inputs, r []map[string]any) { r[7]["timer_operation"].(map[string]any)["action"] = "cancel" }},
		{"no terminal stop", func(_ *Inputs, r []map[string]any) { r[6]["input_kind"] = "timeout" }},
		{"no canonical stop", func(in *Inputs, _ []map[string]any) { in.Events.Runs[0].Events = in.Events.Runs[0].Events[:4] }},
		{"stop before clear", func(in *Inputs, _ []map[string]any) { in.Events.Runs[0].Events[4].TMono = 4_000_002_000 }},
		{"null clock", func(_ *Inputs, r []map[string]any) { r[3]["t_mono_ns"] = nil }},
		{"overflow clock", func(_ *Inputs, r []map[string]any) {
			r[3]["timer_operation"].(map[string]any)["deadline_mono_ns"] = "9223372036854775808"
		}},
		{"no replay", func(in *Inputs, _ []map[string]any) {
			timingField(in.Events.Runs[0].Events[1], "replay", map[string]any{"replayed": false, "records": 1, "stopped": nil})
		}},
		{"lost prefix", func(in *Inputs, _ []map[string]any) { in.Events.Runs[0].Lost = []events.Span{{From: 1, To: 1}} }},
		{"log input", func(in *Inputs, _ []map[string]any) { in.Events.Runs[0].FromLog = true }},
	}
	cases = append(cases, []struct {
		name string
		edit func(*Inputs, []map[string]any)
	}{
		{"null deadline", func(_ *Inputs, r []map[string]any) {
			r[1]["timer_operation"].(map[string]any)["deadline_mono_ns"] = nil
		}},
		{"unknown operation field", func(_ *Inputs, r []map[string]any) { r[1]["timer_operation"].(map[string]any)["unknown"] = true }},
		{"replacement before queue", func(_ *Inputs, r []map[string]any) { r[2]["timer_operation"].(map[string]any)["action"] = "replace" }},
		{"cancellation before queue", func(_ *Inputs, r []map[string]any) { r[2]["timer_operation"].(map[string]any)["action"] = "cancelled" }},
		{"stale expiry", func(in *Inputs, _ []map[string]any) { timingField(in.Events.Runs[0].Events[3], "stale", true) }},
		{"null expiry status", func(in *Inputs, _ []map[string]any) { timingField(in.Events.Runs[0].Events[3], "stale", nil) }},
		{"false rearmed", func(in *Inputs, _ []map[string]any) { timingField(in.Events.Runs[0].Events[2], "rearmed", false) }},
		{"event parse error", func(in *Inputs, _ []map[string]any) { in.Events.Errors = []string{"damaged input"} }},
		{"unknown event", func(in *Inputs, _ []map[string]any) { in.Events.UnknownKinds = map[string]int{"UNKNOWN": 1} }},
		{"prefix clock regression", func(in *Inputs, _ []map[string]any) { in.Events.Runs[0].Events[0].TMono = 1_000_000_001 }},
		{"canonical context mismatch", func(in *Inputs, _ []map[string]any) { timingField(in.Events.Runs[0].Events[3], "gen", 18) }},
	}...)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			in, arm, fire := retainedTimingFixture(t, test.edit)
			timing := NewTimerTiming(in)
			d, why, ev := timing.Elapsed(arm, fire)
			if d != fire.TMono-arm.TMono || why != "" || len(ev) != 0 || len(timing.Evidence(verdict.Instance{}, fire).Evidence) != 0 {
				t.Fatal("unproved origin changed legacy timing", d, why, ev)
			}
		})
	}
	t.Run("duplicate source", func(t *testing.T) {
		in, arm, fire := retainedTimingFixture(t, nil)
		in.Frames = append(in.Frames, in.Frames[0])
		d, _, ev := NewTimerTiming(in).Elapsed(arm, fire)
		if d != fire.TMono-arm.TMono || len(ev) != 0 {
			t.Fatal(d, ev)
		}
	})
	t.Run("real early expiry", func(t *testing.T) {
		in, arm, fire := retainedTimingFixture(t, nil)
		fire.TMono = 2_900_010_000
		d, _, ev := NewTimerTiming(in).Elapsed(arm, fire)
		if in.Clock.Timing(d, 2_000_000_000) != verdict.Fail || len(ev) != 0 {
			t.Fatal("early expiry hidden", d, ev)
		}
	})
}
