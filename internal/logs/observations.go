package logs

import (
	"fmt"
	"sort"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

// Observations summarizes positive legacy facts without converting them into
// requirement verdicts. Full counts remain; representative pointers are capped.
func Observations(s *events.Set) []report.Observation {
	groups := map[[2]string]*report.Observation{}
	add := func(kind string, e *events.Event, more *events.Event) {
		k := [2]string{e.Node, kind}
		o := groups[k]
		if o == nil {
			o = &report.Observation{Kind: kind, Node: e.Node, Checker: "logs.legacy", Imp: []string{}, Evidence: []evidence.Pointer{}, Note: "Positive log observation; coverage and transport delivery are not established."}
			groups[k] = o
		}
		o.Count++

		if len(o.Evidence) <= 18 {
			for _, x := range []*events.Event{e, more} {
				if x != nil {
					o.Evidence = append(o.Evidence, evidence.Pointer{Kind: "log", Input: x.Input, Node: x.Node, Line: x.Line, Number: heightOf(x), T: x.TWall})
				}
			}
		}
	}
	started := map[string]bool{}
	stopped := map[string]*events.Event{}
	for _, r := range s.Runs {
		if !r.FromLog {
			continue
		}
		var trigger *events.Event
		for _, e := range r.Events {
			switch e.Kind {
			case "ENGINE_START":
				if e.Str("address") != "" {
					prior, _ := e.Int("previous_engine_start_line")
					if started[e.Node] || stopped[e.Node] != nil || prior > 0 {
						add("engine_restart", e, stopped[e.Node])
					}
					started[e.Node] = true
				}
				trigger = nil
			case "ENGINE_STOP":
				stopped[e.Node] = e
				trigger = nil
			case "TIMER_FIRE":
				trigger = e
			case "QUORUM":
				if e.Str("what") == "F_PLUS_ONE" {
					trigger = e
				}
			case "ROUND_ENTER":
				if cause := CorrelatedTrigger(trigger, e); cause != "" {
					add("round_change_"+cause, e, trigger)
				}
				trigger = nil
			}
		}
	}
	keys := [][2]string{}
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][0] != keys[j][0] {
			return keys[i][0] < keys[j][0]
		}
		return keys[i][1] < keys[j][1]
	})
	out := []report.Observation{}
	for i, k := range keys {
		o := groups[k]
		o.ID = fmt.Sprintf("LOG-%04d", i+1)
		out = append(out, *o)
	}
	return out
}
func heightOf(e *events.Event) string {
	if e.View != nil {
		return e.View.Seq
	}
	return ""
}
