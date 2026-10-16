package check

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type schedulerSnapshot struct {
	active    map[string]*frames.Record
	queued    map[string]*frames.Record
	cancelled map[string]*frames.Record
}
type schedulerView struct {
	source frames.SchedulerSource
	steps  map[[2]uint64]*frames.Record
	before map[*frames.Record]schedulerSnapshot
	valid  bool
}

func schedulerID(r *frames.Record) string {
	o := r.TimerOperation
	return o.Timer + "/" + o.Generation + "/" + o.Height + "/" + o.Round + "/" + o.ArmEngine + "/" + o.ArmStep + "/" + o.ArmOutput + "/" + o.TimeoutSHA256 + "/" + o.EntryMono + "/" + o.Deadline
}
func copySchedulerMap(m map[string]*frames.Record) map[string]*frames.Record {
	n := map[string]*frames.Record{}
	for k, v := range m {
		n[k] = v
	}
	return n
}
func schedulerNumber(s string) uint64 { v, _ := frames.SchedulerUint(s); return v }

func replayScheduler(s frames.SchedulerSource) *schedulerView {
	v := &schedulerView{source: s, steps: map[[2]uint64]*frames.Record{}, before: map[*frames.Record]schedulerSnapshot{}, valid: true}
	stepCounts := map[uint64]uint64{}
	for _, r := range s.Steps {
		if r.EngineRun == nil || r.Step == nil || *r.EngineRun == 0 || *r.Step == 0 {
			v.valid = false
			continue
		}
		if r.EntryMono == nil && r.Via != "wal" {
			v.valid = false
		}
		v.steps[[2]uint64{*r.EngineRun, *r.Step}] = r
		stepCounts[*r.EngineRun]++
	}
	for engine, count := range stepCounts {
		for step := uint64(1); step <= count; step++ {
			if v.steps[[2]uint64{engine, step}] == nil {
				v.valid = false
			}
		}
	}
	// Sequence is global to the scheduler in this writer run, across engine
	// lifecycles. WAL replay steps have no measured entry and own no mutation.
	ops := slices.Clone(s.Operations)
	sort.Slice(ops, func(i, j int) bool {
		return schedulerNumber(ops[i].TimerOperation.Sequence) < schedulerNumber(ops[j].TimerOperation.Sequence)
	})
	active, queued, pending := map[string]*frames.Record{}, map[string]*frames.Record{}, map[string]*frames.Record{}
	var fifo []string
	var replaced *frames.Record
	lastMono, engine := int64(0), uint64(0)
	lastClear := false
	lastOutput := map[[2]uint64]uint64{}
	for i, r := range ops {
		o := r.TimerOperation
		if schedulerNumber(o.Sequence) != uint64(i+1) || r.TMono < lastMono {
			v.valid = false
		}
		lastMono = r.TMono
		if r.EngineRun == nil || *r.EngineRun == 0 || r.Step == nil {
			v.valid = false
			continue
		}
		if engine != *r.EngineRun {
			if engine != 0 && (*r.EngineRun < engine || !lastClear || len(active) > 0 || len(queued) > 0) {
				v.valid = false
			}
			engine = *r.EngineRun
		}
		lastClear = o.Action == "clear"
		step := v.steps[[2]uint64{engine, *r.Step}]
		if o.Source == "core" && o.Action != "queued" {
			k := [2]uint64{engine, *r.Step}
			output := schedulerNumber(o.Output)
			if output < lastOutput[k] {
				v.valid = false
			}
			lastOutput[k] = output
			if step == nil || step.EntryMono == nil || o.Output == "0" {
				v.valid = false
			} else {
				entry, _ := frames.SchedulerMono(*step.EntryMono)
				if entry > r.TMono || r.TMono > step.TMono {
					v.valid = false
				}
			}
		}
		if o.Source == "restore" && (*r.Step != 0 || o.Output != "0") {
			v.valid = false
		}
		if o.Source == "lifecycle" && (o.Output != "0" || (*r.Step != 0 && step == nil)) {
			v.valid = false
		}
		if o.Source == "dequeue" && (o.Action != "pop" || o.Output != "0" || step == nil || step.InputKind != "timeout" || step.Via != "timer" || r.TMono > step.TMono) {
			v.valid = false
		}
		if len(pending) > 0 && o.Action != "cancelled" && o.Action != "cancel" {
			v.valid = false
		}
		if replaced != nil {
			prev := replaced.TimerOperation
			if o.Action != "arm" || o.Timer != prev.Timer || replaced.Step == nil || *r.Step != *replaced.Step || o.Output != prev.Output || o.Source != prev.Source {
				v.valid = false
			}
			replaced = nil
		}
		v.before[r] = schedulerSnapshot{copySchedulerMap(active), copySchedulerMap(queued), copySchedulerMap(pending)}
		id := ""
		if o.TimeoutSHA256 != "" {
			id = schedulerID(r)
			if schedulerNumber(o.ArmEngine) != engine {
				v.valid = false
			}
		}
		switch o.Action {
		case "arm":
			if o.Source != "core" && o.Source != "restore" {
				v.valid = false
			}
			if schedulerNumber(o.ArmStep) != *r.Step || o.ArmOutput != o.Output || active[o.Timer] != nil || queued[id] != nil {
				v.valid = false
			}
			if o.Source == "core" && step != nil && step.EntryMono != nil && o.EntryMono != *step.EntryMono {
				v.valid = false
			}
			active[o.Timer] = r
		case "replace", "cancelled":
			if o.Source != "core" && o.Source != "lifecycle" && (o.Action != "replace" || o.Source != "restore") {
				v.valid = false
			}
			if o.Action == "replace" {
				replaced = r
			}
			a := active[o.Timer]
			if a == nil || schedulerID(a) != id {
				v.valid = false
			}
			delete(active, o.Timer)
			if o.Action == "cancelled" {
				pending[id] = r
			}
		case "queued":
			a := active[o.Timer]
			deadline, _ := frames.SchedulerMono(o.Deadline)
			if a == nil || schedulerID(a) != id || queued[id] != nil || r.TMono < deadline || o.Source != a.TimerOperation.Source || a.Step == nil || *r.Step != *a.Step || o.Output != a.TimerOperation.Output {
				v.valid = false
			}
			delete(active, o.Timer)
			queued[id] = r
			fifo = append(fifo, id)
		case "pop":
			if o.Source != "dequeue" || queued[id] == nil || len(fifo) == 0 || fifo[0] != id {
				v.valid = false
			} else {
				fifo = fifo[1:]
			}
			delete(queued, id)
		case "cancel":
			if o.Source != "core" && o.Source != "lifecycle" {
				v.valid = false
			}
			for _, p := range pending {
				if !slices.Contains(o.Kinds, p.TimerOperation.Timer) || p.EngineRun == nil || *p.EngineRun != engine || p.Step == nil || *p.Step != *r.Step || p.TimerOperation.Output != o.Output || p.TimerOperation.Source != o.Source {
					v.valid = false
				}
			}
			for _, k := range o.Kinds {
				if active[k] != nil {
					v.valid = false
				}
			}
			pending = map[string]*frames.Record{}
		case "clear":
			if o.Source != "lifecycle" || len(active) != 0 || i == 0 || ops[i-1].TimerOperation.Action != "cancel" || ops[i-1].TimerOperation.Source != "lifecycle" {
				v.valid = false
			}
			queued = map[string]*frames.Record{}
			fifo = nil
		}
	}
	if len(pending) > 0 || replaced != nil {
		v.valid = false
	}
	return v
}

// TimerCancellation binds the event's arm to measured scheduler operations.
// Deadline passage or a later FIRE alone never establishes a queued expiry.
type TimerCancellation struct {
	views map[[2]string][]*schedulerView
	bad   bool
}

func NewTimerCancellation(in *Inputs) *TimerCancellation {
	t := &TimerCancellation{views: map[[2]string][]*schedulerView{}}
	for _, d := range in.Frames {
		sources, problems := frames.SchedulerSources(d)
		if len(problems) > 0 {
			t.bad = true
		}
		for _, s := range sources {
			k := [2]string{s.Declaration.Node, s.Declaration.Run}
			t.views[k] = append(t.views[k], replayScheduler(s))
		}
	}
	return t
}

func (t *TimerCancellation) Judge(r *events.Run, i int, tm *events.Timer, roundArm *events.Event) (verdict.Verdict, string, []*frames.Record) {
	e := r.Events[i]
	unknown := func(msg string) (verdict.Verdict, string, []*frames.Record) { return verdict.CannotDecide, msg, nil }
	if roundArm == nil {
		return unknown("round arm source is unavailable")
	}
	s := StepOf(r, i)
	cancelled := s.Has(func(x *events.Event) bool {
		g, _ := x.Int("gen")
		engine, _ := x.Int("engine_run")
		return x.Kind == "TIMER_CANCEL" && x.Str("timer") == tm.Kind && g == tm.Gen && engine == tm.EngineRun
	})
	vs := t.views[[2]string{e.Node, e.Run}]
	if t.bad || len(vs) > 1 {
		return unknown("scheduler source is damaged or ambiguous")
	}
	if len(vs) == 0 {
		if cancelled {
			return verdict.Pass, "timer explicitly cancelled in the step", nil
		}
		return unknown("no measured scheduler source proves cancellation or a queued expiry")
	}
	v := vs[0]
	if !v.valid {
		return unknown("scheduler operation sequence or step binding is incomplete")
	}
	engine, ok := roundArm.Int("engine_run")
	if !ok || engine <= 0 || roundArm.Step == nil || tm.EngineRun != engine {
		return unknown("scheduler engine identity is unavailable")
	}
	step := v.steps[[2]uint64{uint64(engine), *roundArm.Step}]
	if step == nil || step.EntryMono == nil {
		return unknown("original step entry is unavailable")
	}
	entry, _ := frames.SchedulerMono(*step.EntryMono)
	if entry != roundArm.TMono || entry != e.TMono || !schedulerWallEqual(step.EntryWall, roundArm.TWall) || !schedulerWallEqual(step.EntryWall, e.TWall) {
		return unknown("event clocks differ from the original step entry")
	}
	armEvent := r.Events[tm.ArmIndex]
	armEngine, _ := armEvent.Int("engine_run")
	var own, target *frames.Record
	for _, op := range v.source.Operations {
		o := op.TimerOperation
		if o.Action != "arm" || op.EngineRun == nil || *op.EngineRun != uint64(engine) {
			continue
		}
		g := schedulerNumber(o.Generation)
		if o.Timer == "round" && g == uint64(genEvent(roundArm)) && op.Step != nil && *op.Step == *roundArm.Step && roundArm.View != nil && o.Height == roundArm.View.Seq && o.Round == roundArm.View.Round {
			if target != nil {
				return unknown("ambiguous round arm")
			}
			target = op
		}
		if o.Timer == tm.Kind && g == uint64(tm.Gen) && armEngine == engine && tm.View != nil && o.Height == tm.View.Seq && o.Round == tm.View.Round {
			if own != nil {
				return unknown("ambiguous original timer arm")
			}
			own = op
		}
	}
	if own == nil || target == nil {
		return unknown("timer arm has no unique measured source")
	}
	if own.TimerOperation.Source == "core" {
		if armEvent.Step == nil || own.Step == nil || *own.Step != *armEvent.Step || own.TimerOperation.EntryMono != strconv.FormatInt(armEvent.TMono, 10) {
			return unknown("original arm belongs to another event step")
		}
	} else {
		if !tm.Rearmed || own.TimerOperation.Source != "restore" {
			return unknown("restored arm identity is unavailable")
		}
	}
	armEntry, _ := frames.SchedulerMono(own.TimerOperation.EntryMono)
	deadline, _ := frames.SchedulerMono(own.TimerOperation.Deadline)
	if (deadline-armEntry)/1_000_000 != tm.DurationMs {
		return unknown("timer duration differs from measured source")
	}
	targetEntry, _ := frames.SchedulerMono(target.TimerOperation.EntryMono)
	targetDeadline, _ := frames.SchedulerMono(target.TimerOperation.Deadline)
	duration, durationOK := roundArm.Int("duration_ms")
	if target.TimerOperation.Source != "core" || targetEntry != entry || !durationOK || (targetDeadline-targetEntry)/1_000_000 != duration {
		return unknown("round arm differs from measured source")
	}
	if own.TimerOperation.Source == "core" {
		ownStep := v.steps[[2]uint64{uint64(engine), *own.Step}]
		if ownStep == nil || !schedulerWallEqual(ownStep.EntryWall, armEvent.TWall) {
			return unknown("original arm wall clock differs from measured source")
		}
	}
	id := schedulerID(own)
	before := v.before[target]
	if live := before.active[tm.Kind]; live != nil && schedulerID(live) == id {
		if cancelled {
			return unknown("cancel event conflicts with a measured active timer")
		}
		return verdict.Fail, "measured timer remained active when the round timer was armed", []*frames.Record{own, target, step}
	}
	ops := slices.Clone(v.source.Operations)
	sort.Slice(ops, func(i, j int) bool {
		return schedulerNumber(ops[i].TimerOperation.Sequence) > schedulerNumber(ops[j].TimerOperation.Sequence)
	})
	for n := range ops {
		op := ops[n]
		o := op.TimerOperation
		if o.Action != "cancel" || op.EngineRun == nil || *op.EngineRun != uint64(engine) || op.Step == nil || *op.Step != *roundArm.Step || schedulerNumber(o.Sequence) >= schedulerNumber(target.TimerOperation.Sequence) || !slices.Contains(o.Kinds, tm.Kind) {
			continue
		}
		state := v.before[op]
		if q := state.queued[id]; q != nil {
			if cancelled {
				return unknown("cancel event conflicts with an already queued timer")
			}
			return verdict.Pass, "measured scheduler queued the same expiry before cancellation", []*frames.Record{v.source.Declaration, own, q, op, target, step}
		}
		if c := state.cancelled[id]; c != nil {
			return verdict.Pass, "measured scheduler cancelled the same active timer", []*frames.Record{v.source.Declaration, own, c, op, target, step}
		}
	}
	return unknown("measured source does not prove this timer's cancellation boundary")
}
func genEvent(e *events.Event) int64 { g, _ := e.Int("gen"); return g }

func SchedulerEvidence(instance verdict.Instance, records []*frames.Record) verdict.Instance {
	for _, r := range records {
		p := FramePointer(r)
		p.Msg = fmt.Sprintf("%s original journal %d:%d", r.Type, *r.JournalSegment, *r.JournalOffset)
		instance.Evidence = append(instance.Evidence, p)
	}
	return instance
}

func schedulerWallEqual(a, b string) bool {
	x, ex := time.Parse(time.RFC3339Nano, a)
	y, ey := time.Parse(time.RFC3339Nano, b)
	return ex == nil && ey == nil && x.Equal(y)
}
