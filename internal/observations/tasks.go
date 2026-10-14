package observations

import "strconv"

// Task preserves all stages of an exact call token. It does not turn a
// function return or result-channel handover into consensus acceptance.
type Task struct {
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	ID        string   `json:"id"`
	State     string   `json:"state"`
	Stages    []Record `json:"stages"`
}

func projectTask(id uint64, stages []Record) Task {
	out := Task{ID: strconv.FormatUint(id, 10), State: "incomplete", Stages: stages}
	counts := map[string]int{}
	for _, r := range stages {
		counts[r.Stage]++
		if counts[r.Stage] > 1 || r.Height != stages[0].Height || r.Hash != stages[0].Hash {
			out.State = "ambiguous"
			return out
		}
	}
	required := func(names ...string) bool {
		for _, name := range names {
			if counts[name] != 1 {
				return false
			}
		}
		return true
	}
	terminals := 0
	for _, name := range []string{"task_duplicate", "task_skipped", "task_abandoned", "seal_unsupported", "seal_result", "seal_cancel"} {
		terminals += counts[name]
	}
	if terminals > 1 {
		out.State = "ambiguous"
		return out
	}
	if counts["task_abandoned"] > 0 && (counts["task_sent"] > 0 || counts["task_received"] > 0 || counts["seal_enter"] > 0) {
		out.State = "ambiguous"
		return out
	}
	if (counts["task_duplicate"] > 0 || counts["task_skipped"] > 0 || counts["seal_unsupported"] > 0) && counts["seal_enter"] > 0 {
		out.State = "ambiguous"
		return out
	}
	if required("task_offer", "task_abandoned") {
		out.State = "observed_abandonment"
		return out
	}
	if !required("task_offer", "task_sent", "task_received") {
		return out
	}
	switch {
	case required("task_duplicate"):
		out.State = "observed_duplicate"
	case required("task_skipped"):
		out.State = "observed_skip"
	case required("seal_unsupported"):
		out.State = "unsupported"
	case required("seal_enter", "seal_return", "request_post_enter", "request_post_return", "seal_result"):
		out.State = "observed_result"
	case required("seal_enter", "seal_return", "request_post_enter", "request_post_return", "seal_cancel"):
		out.State = "observed_cancellation"
	}
	return out
}
