package check_test

import (
	"encoding/json"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func decidedTimerReplacement(t *testing.T) []rec {
	t.Helper()
	r := loadRecs(t, "round-changes.jsonl")
	decision := -1
	var arm, cancel string
	var gen any
	for i, row := range r {
		if row["kind"] == "STATE" && row["to"] == "Committed" {
			decision = i
			break
		}
		if row["kind"] == "TIMER_ARM" && row["timer"] == "round" {
			arm = seqOf(row)
			gen = row["gen"]
		}
		if row["kind"] == "TIMER_CANCEL" && row["timer"] == "round" {
			cancel = seqOf(row)
		}
	}
	if decision < 0 || arm == "" || cancel == "" {
		t.Fatal("ordinary decision fixture unavailable")
	}
	state := r[decision]
	r = r[:decision+1]
	n, err := strconv.ParseUint(gen.(json.Number).String(), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	// Insert in reverse order after the original decision; decide renumbers records.
	r = insertAfter(t, r, seqOf(state), arm, rec{"gen": json.Number(strconv.FormatUint(n+1, 10)), "step": state["step"], "t_mono_ns": state["t_mono_ns"], "t_wall": state["t_wall"], "view": state["view"]})
	r = insertAfter(t, r, seqOf(state), cancel, rec{"gen": gen, "step": state["step"], "t_mono_ns": state["t_mono_ns"], "t_wall": state["t_wall"], "view": state["view"]})
	return r
}

func TestDecidedTimerReplacementNeedsCause(t *testing.T) {
	wantVerdict(t, decide(t, decidedTimerReplacement(t)), verdict.Fail, "WBFT-SM-050", "WBFT-TIMER-016")
}

func TestDecidedTimerResetWithOptionalBehaviorStaysUndecided(t *testing.T) {
	records := decidedTimerReplacement(t)
	for _, record := range records {
		if record["kind"] == "NODE_START" {
			record["improvements"] = []any{rec{"name": "custom_local_behavior", "source": "node"}}
		}
	}
	results := decide(t, records)
	wantVerdict(t, results, verdict.CannotDecide, "WBFT-SM-050", "WBFT-TIMER-016")
	for _, id := range []string{"WBFT-SM-050", "WBFT-TIMER-016"} {
		if results[id].Reasons[verdict.NotInBuild] == 0 {
			t.Fatal("unknown optional behavior was not retained as unavailable evidence", id)
		}
	}
}
