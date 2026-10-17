package synccontrol

import (
	"errors"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

// controlLifecycles binds only actual call cursors. A no-call handling has no
// event boundary; its journal position and posting time cannot supply one.
func controlLifecycles(v *contextView) ([][]*events.Event, error) {
	linked := make([][]*events.Event, len(v.operations))
	matched := map[uint64]bool{}
	firstBefore, lastAfter := uint64(len(v.run.Events)-1), uint64(1)
	previousAfter := uint64(0)
	for i, operation := range v.operations {
		c := operation.SyncControl
		before, after := number(c.EventBefore), number(c.EventAfter)
		if c.Action == "none" {
			if *c.EventsAvailable || before != 0 || after != 0 || *c.RunningBefore != *c.RunningAfter {
				return nil, errors.New("no-call handling has an invented boundary or concurrent state change")
			}
			continue
		}
		if !*c.EventsAvailable || before == 0 || after < before || after >= uint64(len(v.run.Events)) || before < previousAfter {
			return nil, errors.New("control call lacks an unambiguous next-sequence range")
		}
		if v.running[before] != *c.RunningBefore || v.running[after] != *c.RunningAfter {
			return nil, errors.New("recorded control state differs from its canonical range")
		}
		firstBefore = min(firstBefore, before)
		lastAfter = max(lastAfter, after)
		previousAfter = after
		want := "ENGINE_STOP"
		if c.Action == "start" {
			want = "ENGINE_START"
		}
		for _, e := range v.run.Events[before:after] {
			if e.Kind != "ENGINE_START" && e.Kind != "ENGINE_STOP" {
				continue
			}
			if e.Kind != want || matched[e.Seq] || len(linked[i]) != 0 {
				return nil, errors.New("control range contains ambiguous lifecycle changes")
			}
			linked[i] = append(linked[i], e)
			matched[e.Seq] = true
		}
	}
	var remaining []*events.Event
	for _, e := range v.run.Events {
		if (e.Kind == "ENGINE_START" || e.Kind == "ENGINE_STOP") && !matched[e.Seq] {
			remaining = append(remaining, e)
		}
	}
	if len(remaining) < 1 || len(remaining) > 2 || remaining[0].Kind != "ENGINE_START" || remaining[0].Seq >= firstBefore || v.running[len(v.run.Events)] || (len(remaining) == 2 && (remaining[1].Kind != "ENGINE_STOP" || remaining[1].Seq < lastAfter)) {
		return nil, errors.New("unattributed lifecycle changes or incomplete startup/shutdown coverage")
	}
	// Activity between an observed stop and restart may be a queued output or
	// an unobserved concurrent control. Do not attribute it from wall time.
	running := false
	for _, e := range v.run.Events {
		switch e.Kind {
		case "ENGINE_START":
			running = true
		case "ENGINE_STOP":
			running = false
		case "SEND", "ROUND_ENTER":
			if !running {
				return nil, errors.New("activity outside a recorded running lifecycle has ambiguous origin")
			}
		}
	}
	return linked, nil
}
