package observations

import (
	"errors"
	"strconv"
)

// Engine preserves all candidates for a concrete core instance. Started and
// stopped describe local lifecycle evidence, never full execution or delivery.
type Engine struct {
	ID          string   `json:"id"`
	ParentID    string   `json:"parent_id"`
	CreatedLine int      `json:"created_line"`
	State       string   `json:"state"`
	Stages      []Record `json:"stages"`
}

func engineStopStage(s string) bool {
	switch s {
	case "stop_enter", "timers_stopped", "unsubscribed", "handler_joined", "stop_return":
		return true
	}
	return false
}
func engineStage(s string) bool {
	switch s {
	case "start_enter", "subscribed", "handler_enter", "handler_exit", "initial_round_return", "start_return":
		return true
	}
	return engineStopStage(s)
}
func projectEngines(records []Record, starts, ends map[uint64]Record, complete bool) ([]Engine, error) {
	out := []Engine{}
	created := map[uint64]int{}
	for _, r := range records {
		if r.Type == "engine_created" {
			if _, exists := created[r.ID]; exists {
				return nil, errors.New("duplicate engine instance")
			}
			p, ok := starts[r.ParentID]
			if !ok || p.Operation != "backend_start" || p.Line >= r.Line {
				return nil, errors.New("engine without exact start parent")
			}
			created[r.ID] = len(out)
			out = append(out, Engine{ID: strconv.FormatUint(r.ID, 10), ParentID: strconv.FormatUint(r.ParentID, 10), CreatedLine: r.Line, State: "incomplete", Stages: []Record{}})
		}
		if r.Type != "engine_stage" {
			continue
		}
		index, ok := created[r.ID]
		if !ok {
			return nil, errors.New("stage without exact engine instance")
		}
		e := &out[index]
		if r.ParentID != 0 {
			p, exists := starts[r.ParentID]
			want := "backend_start"
			if engineStopStage(r.Stage) {
				want = "backend_stop"
			}
			if !exists || p.Operation != want || p.Line >= r.Line || !engineStopStage(r.Stage) && strconv.FormatUint(r.ParentID, 10) != e.ParentID {
				return nil, errors.New("engine stage parent mismatch")
			}
		} else if !engineStopStage(r.Stage) {
			return nil, errors.New("start stage parent absent")
		}
		e.Stages = append(e.Stages, r)
	}
	for i := range out {
		e := &out[i]
		by := map[string]Record{}
		duplicate := false
		stopParent := uint64(0)
		unknown := false
		for _, s := range e.Stages {
			if _, ok := by[s.Stage]; ok {
				duplicate = true
			}
			by[s.Stage] = s
			if engineStopStage(s.Stage) {
				if s.ParentID == 0 {
					unknown = true
				}
				if stopParent != 0 && stopParent != s.ParentID {
					duplicate = true
				}
				stopParent = s.ParentID
			}
		}
		if duplicate {
			e.State = "ambiguous"
			continue
		}
		if !complete || unknown {
			continue
		}
		chain := func(names ...string) bool {
			var previous uint64
			for _, n := range names {
				r, ok := by[n]
				if !ok || r.Mono < previous {
					return false
				}
				previous = r.Mono
			}
			return true
		}
		parent, _ := strconv.ParseUint(e.ParentID, 10, 64)
		end, ok := ends[parent]
		if !ok || end.Result != "ok" || !chain("start_enter", "subscribed", "initial_round_return", "start_return") || by["handler_enter"].Line == 0 {
			continue
		}
		if by["start_return"].Mono > end.Mono || records[e.CreatedLine-1].Mono < starts[parent].Mono || by["start_enter"].Mono < records[e.CreatedLine-1].Mono || by["handler_enter"].Mono < by["subscribed"].Mono {
			continue
		}
		e.State = "observed_started"
		if by["stop_enter"].Line == 0 {
			continue
		}
		e.State = "incomplete"
		stopEnd, ok := ends[stopParent]
		if !ok || stopEnd.Result != "ok" || by["stop_enter"].Mono < starts[stopParent].Mono || by["stop_enter"].Mono < by["start_return"].Mono || !chain("stop_enter", "timers_stopped", "unsubscribed", "handler_joined", "stop_return") || !chain("handler_enter", "handler_exit", "handler_joined") || by["stop_return"].Mono > stopEnd.Mono {
			continue
		}
		e.State = "observed_stopped"
	}
	return out, nil
}
