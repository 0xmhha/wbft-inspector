package check

import (
	"math"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type retainedTimingSource struct {
	view     *schedulerView
	engine   uint64
	closure  []*events.Event
	terminal []*frames.Record
}

type retainedTimingArm struct {
	source   *retainedTimingSource
	arm      *frames.Record
	from     int64
	evidence []*frames.Record
}

// A declaration is only a locator. Full format validation and operation replay
// must succeed before its measured scheduler records can supply a timer origin.
func retainedTimingSources(in *Inputs) map[[2]string]*schedulerView {
	result := map[[2]string]*schedulerView{}
	seen := map[[2]string]bool{}
	for _, dump := range in.Frames {
		sources, problems := frames.SchedulerSources(dump)
		valid := len(problems) == 0 && len(frames.Validate(dump).Problems) == 0
		for _, source := range sources {
			key := [2]string{source.Declaration.Node, source.Declaration.Run}
			if seen[key] {
				result[key] = nil
				continue
			}
			seen[key] = true
			if !valid {
				continue
			}
			view := replayScheduler(source)
			if view.valid {
				sort.Slice(view.source.Operations, func(i, j int) bool {
					return schedulerNumber(view.source.Operations[i].TimerOperation.Sequence) < schedulerNumber(view.source.Operations[j].TimerOperation.Sequence)
				})
				result[key] = view
			}
		}
	}
	return result
}

// The first implementation deliberately supports closed single-engine runs.
// Neither a truncated live prefix nor declared counts alone establish closure.
func closedRetainedTiming(run *events.Run, view *schedulerView) *retainedTimingSource {
	if view == nil || run.FromLog || len(run.Events) == 0 || len(run.Lost) > 0 {
		return nil
	}
	var start, stop *events.Event
	if run.Events[0].Kind != "NODE_START" {
		return nil
	}
	var nodeStarts, nodeStops int
	for i, e := range run.Events {
		if e.Node != run.Node || e.Run != run.ID || e.FromLog || e.Seq != uint64(i) {
			return nil
		}
		switch e.Kind {
		case "NODE_START":
			nodeStarts++
		case "NODE_STOP":
			nodeStops++
		case "ENGINE_START":
			if start != nil {
				return nil
			}
			start = e
		case "ENGINE_STOP":
			if stop != nil {
				return nil
			}
			stop = e
		}
	}
	last := run.Events[len(run.Events)-1]
	if nodeStarts != 1 || nodeStops != 1 || start == nil || stop == nil || last.Kind != "NODE_STOP" || start.Seq >= stop.Seq || stop.Seq >= last.Seq || last.TMono < stop.TMono {
		return nil
	}
	engine, ok := timingInt(start, "engine_run")
	if !ok || engine <= 0 || !timingSameInt(start, stop, "engine_run") {
		return nil
	}
	source := view.source
	if len(source.Operations) < 2 || len(source.Steps) == 0 {
		return nil
	}
	// R01 outer sequence also has to cover the retained file without holes.
	seqs := map[uint64]bool{}
	for _, r := range source.Records {
		seqs[r.Seq] = true
	}
	for i := 1; i <= len(source.Records); i++ {
		if !seqs[uint64(i)] {
			return nil
		}
	}
	for _, r := range append(append([]*frames.Record{}, source.Operations...), source.Steps...) {
		if r.EngineRun == nil || *r.EngineRun != uint64(engine) {
			return nil
		}
	}
	count := uint64(len(source.Steps))
	step := view.steps[[2]uint64{uint64(engine), count}]
	if step == nil || step.InputKind != "stop" || step.Via != "engine" || step.EntryMono == nil {
		return nil
	}
	cancel := source.Operations[len(source.Operations)-2]
	clear := source.Operations[len(source.Operations)-1]
	if cancel.TimerOperation.Action != "cancel" || cancel.TimerOperation.Source != "lifecycle" || clear.TimerOperation.Action != "clear" || clear.TimerOperation.Source != "lifecycle" || cancel.Step == nil || clear.Step == nil || *cancel.Step != count || *clear.Step != count || clear.TMono > stop.TMono {
		return nil
	}
	return &retainedTimingSource{view: view, engine: uint64(engine), closure: []*events.Event{stop, last}, terminal: []*frames.Record{step, cancel, clear}}
}

func (s *retainedTimingSource) arm(start, e *events.Event) *retainedTimingArm {
	if s == nil {
		return nil
	}
	duration, ok := timingInt(e, "duration_ms")
	generation, gok := timingInt(e, "gen")
	engine, eok := timingInt(e, "engine_run")
	if !ok || duration < 0 || duration > math.MaxInt64/1_000_000 || !gok || generation < 0 || !eok || uint64(engine) != s.engine {
		return nil
	}
	var found *frames.Record
	for _, r := range s.view.source.Operations {
		o := r.TimerOperation
		if o.Action != "arm" || o.Source != "restore" || o.Timer != e.Str("timer") || o.Generation != strconv.FormatInt(generation, 10) || o.Height != e.View.Seq || o.Round != e.View.Round {
			continue
		}
		if found != nil {
			return nil
		}
		found = r
	}
	if found == nil {
		return nil
	}
	o := found.TimerOperation
	from, yes := frames.SchedulerMono(o.EntryMono)
	deadline, dok := frames.SchedulerMono(o.Deadline)
	if !yes || !dok || deadline < from || deadline-from != duration*1_000_000 || from < start.TMono || from > found.TMono || found.TMono > e.TMono || o.ArmStep != "0" || o.ArmOutput != "0" {
		return nil
	}
	return &retainedTimingArm{source: s, arm: found, from: from}
}

func (a *retainedTimingArm) expiry(fire *events.Event) *retainedTimingArm {
	var matching []*frames.Record
	var pops int
	for _, r := range a.source.view.source.Operations {
		if r.TimerOperation.Action == "pop" && r.Step != nil && fire.Step != nil && *r.Step == *fire.Step {
			pops++
		}
		if r.TimerOperation.TimeoutSHA256 != "" && schedulerID(r) == schedulerID(a.arm) {
			matching = append(matching, r)
		}
	}
	if len(matching) != 3 || matching[0] != a.arm || matching[1].TimerOperation.Action != "queued" || matching[2].TimerOperation.Action != "pop" || pops != 1 || fire.Step == nil {
		return nil
	}
	queue, pop := matching[1], matching[2]
	step := a.source.view.steps[[2]uint64{a.source.engine, *fire.Step}]
	if pop.Step == nil || *pop.Step != *fire.Step || step == nil || step.EntryMono == nil || step.InputKind != "timeout" || step.Via != "timer" {
		return nil
	}
	entry, ok := frames.SchedulerMono(*step.EntryMono)
	if !ok || entry != fire.TMono || !schedulerWallEqual(step.EntryWall, fire.TWall) || queue.TMono > pop.TMono || pop.TMono > entry || entry > step.TMono {
		return nil
	}
	proof := *a
	proof.evidence = append([]*frames.Record{a.source.view.source.Declaration, a.arm, queue, pop, step}, a.source.terminal...)
	return &proof
}

// Evidence retains the original source positions rather than manufacturing a
// canonical event at the measured scheduler origin.
func (t *TimerTiming) Evidence(instance verdict.Instance, fire *events.Event) verdict.Instance {
	if a := t.fires[fire]; a != nil && a.valid && a.retained != nil {
		return SchedulerEvidence(instance, a.retained.evidence)
	}
	return instance
}
