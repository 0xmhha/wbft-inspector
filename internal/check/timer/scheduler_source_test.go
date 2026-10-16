package timer

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	_ "github.com/0xmhha/wbft-inspector/internal/check/sm"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const schedulerFixture = "../../frames/testdata/scheduler-source"

func schedulerRows(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile(schedulerFixture + "/frames-scheduler-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		var r map[string]any
		if err = json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	return rows
}
func schedulerDump(t *testing.T, rows []map[string]any) *frames.Dump {
	t.Helper()
	dir := t.TempDir()
	var out strings.Builder
	for _, r := range rows {
		raw, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out.Write(raw)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(filepath.Join(dir, "frames-test.jsonl"), []byte(out.String()), 0600); err != nil {
		t.Fatal(err)
	}
	d, err := frames.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	d.SetInput("scheduler")
	return d
}
func operation(rows []map[string]any, n string) map[string]any {
	for _, r := range rows {
		if o, ok := r["timer_operation"].(map[string]any); ok && o["sequence"] == n {
			return r
		}
	}
	panic(n)
}
func metadata(rows []map[string]any, n string) map[string]any {
	return operation(rows, n)["timer_operation"].(map[string]any)
}
func schedulerCheck(t *testing.T, dumps []*frames.Dump, want verdict.Verdict) {
	t.Helper()
	es, err := events.Load([]string{schedulerFixture + "/events.jsonl"})
	if err != nil || len(es.Errors) != 0 {
		t.Fatal(err, es.Errors)
	}
	for _, req := range []string{"WBFT-TIMER-013", "WBFT-SM-030"} {
		c, ok := check.ForRequirement(req)
		if !ok {
			t.Fatal(req)
		}
		var got sink
		if err = c.Run(context.Background(), &check.Inputs{Events: es, Frames: dumps}, &got); err != nil {
			t.Fatal(err)
		}
		found := 0
		for _, i := range got {
			if i.Requirement == req {
				found++
				if i.Verdict != want {
					t.Fatalf("%s: got %s, want %s: %s", req, i.Verdict, want, i.Message)
				}
				if want == verdict.Pass && len(i.Evidence) < 7 {
					t.Fatal("measured source pointers missing", i.Evidence)
				}
				if want == verdict.CannotDecide && i.Reason != verdict.ObserverScope {
					t.Fatal(i.Reason)
				}
			}
		}
		if found != 1 {
			t.Fatal("missing measured instance", got)
		}
	}
}
func TestMeasuredQueueBeforeCancelIsNotAnUncancelledTimer(t *testing.T) {
	rows := schedulerRows(t)
	d := schedulerDump(t, rows)
	if result := frames.Validate(d); len(result.Problems) != 0 {
		t.Fatal(result.Problems)
	}
	schedulerCheck(t, []*frames.Dump{d}, verdict.Pass)
	// The format permits deferred records. Mutex sequence, rather than file
	// order, supplies the scheduler ordering.
	slices.Reverse(rows)
	schedulerCheck(t, []*frames.Dump{schedulerDump(t, rows)}, verdict.Pass)
}
func TestSchedulerSourceRejectsUnprovenCancellation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func([]map[string]any) []map[string]any
	}{

		{"null mono", func(r []map[string]any) []map[string]any { operation(r, "1")["t_mono_ns"] = nil; return r }},
		{"null sequence", func(r []map[string]any) []map[string]any { r[0]["seq"] = nil; return r }},
		{"noncanonical counter", func(r []map[string]any) []map[string]any { metadata(r, "4")["sequence"] = "04"; return r }},
		{"overflow counter", func(r []map[string]any) []map[string]any {
			metadata(r, "4")["sequence"] = "18446744073709551616"
			return r
		}},
		{"missing input origin", func(r []map[string]any) []map[string]any {
			for _, x := range r {
				if x["type"] == "scheduler_step" {
					delete(x, "via")
				}
			}
			return r
		}},
		{"wrong type field", func(r []map[string]any) []map[string]any { operation(r, "4")["entry_t_mono_ns"] = "0"; return r }},
		{"output order contradicts operations", func(r []map[string]any) []map[string]any { metadata(r, "5")["output"] = "99"; return r }},
		{"no declaration", func(r []map[string]any) []map[string]any { return r[1:] }},
		{"truncated", func(r []map[string]any) []map[string]any { return r[:len(r)-1] }},
		{"sequence gap", func(r []map[string]any) []map[string]any { metadata(r, "4")["sequence"] = "40"; return r }},
		{"sequence duplicate", func(r []map[string]any) []map[string]any { metadata(r, "4")["sequence"] = "3"; return r }},
		{"other writer", func(r []map[string]any) []map[string]any {
			for _, x := range r {
				x["run"] = "other-run"
			}
			return r
		}},
		{"other node", func(r []map[string]any) []map[string]any {
			for _, x := range r {
				x["node"] = "0xbb00000000000000000000000000000000000000"
			}
			return r
		}},
		{"other engine", func(r []map[string]any) []map[string]any { operation(r, "4")["engine_run"] = 2; return r }},
		{"other arm", func(r []map[string]any) []map[string]any { metadata(r, "4")["arm_output"] = "9"; return r }},
		{"other timeout", func(r []map[string]any) []map[string]any {
			metadata(r, "4")["timeout_sha256"] = strings.Repeat("f", 64)
			return r
		}},
		{"other generation", func(r []map[string]any) []map[string]any { metadata(r, "4")["generation"] = "99"; return r }},
		{"other view", func(r []map[string]any) []map[string]any { metadata(r, "4")["height"] = "11"; return r }},
		{"other callback owner", func(r []map[string]any) []map[string]any { operation(r, "4")["step"] = 2; return r }},
		{"other callback source", func(r []map[string]any) []map[string]any { metadata(r, "4")["source"] = "dequeue"; return r }},
		{"queue before deadline", func(r []map[string]any) []map[string]any { operation(r, "4")["t_mono_ns"] = 3999999999; return r }},
		{"wrong clock", func(r []map[string]any) []map[string]any {
			for _, x := range r {
				if x["type"] == "scheduler_step" && x["step"] == float64(2) {
					x["entry_t_mono_ns"] = "3000000001"
				}
			}
			return r
		}},
		{"wrong wall", func(r []map[string]any) []map[string]any {
			for _, x := range r {
				if x["type"] == "scheduler_step" && x["step"] == float64(2) {
					x["entry_t_wall"] = "2026-01-01T00:00:03.000000001Z"
				}
			}
			return r
		}},
		{"wrong duration", func(r []map[string]any) []map[string]any {
			metadata(r, "6")["deadline_mono_ns"] = "12000000000"
			return r
		}},
		{"reused position", func(r []map[string]any) []map[string]any {
			operation(r, "4")["journal_offset"] = operation(r, "3")["journal_offset"]
			return r
		}},
		{"missing position", func(r []map[string]any) []map[string]any { delete(operation(r, "4"), "journal_offset"); return r }},
		{"missing source clock", func(r []map[string]any) []map[string]any { delete(operation(r, "4"), "t_mono_ns"); return r }},
		{"unknown field", func(r []map[string]any) []map[string]any { metadata(r, "4")["extra"] = "value"; return r }},
		{"mixed identity", func(r []map[string]any) []map[string]any { operation(r, "4")["run"] = "other-run"; return r }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			schedulerCheck(t, []*frames.Dump{schedulerDump(t, tc.mutate(schedulerRows(t)))}, verdict.CannotDecide)
		})
	}
	t.Run("later FIRE only", func(t *testing.T) { schedulerCheck(t, nil, verdict.CannotDecide) })
	t.Run("duplicate source", func(t *testing.T) {
		d := schedulerDump(t, schedulerRows(t))
		schedulerCheck(t, []*frames.Dump{d, d}, verdict.CannotDecide)
	})
}
func TestMeasuredLiveTimerWithoutCancellationFails(t *testing.T) {
	rows := schedulerRows(t)
	// A valid execution queues the retry AFTER the cancellation request and
	// round arm. That request omits retry, so it remains active at the arm.
	q := operation(rows, "4")
	q["t_mono_ns"] = 4300000000
	q["t_wall"] = "2026-01-01T00:00:04.3Z"
	metadata(rows, "5")["cancel_kinds"] = []string{"round", "future"}
	for _, r := range rows {
		if o, ok := r["timer_operation"].(map[string]any); ok {
			n, _ := strconv.Atoi(o["sequence"].(string))
			switch n {
			case 4:
				o["sequence"] = "6"
			case 5:
				o["sequence"] = "4"
			case 6:
				o["sequence"] = "5"
			}
		}
	}
	d := schedulerDump(t, rows)
	if v := frames.Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	schedulerCheck(t, []*frames.Dump{d}, verdict.Fail)
}

func TestSchedulerSequenceSpansEngineLifecycles(t *testing.T) {
	for _, reset := range []bool{false, true} {
		t.Run(strconv.FormatBool(reset), func(t *testing.T) {
			rows := schedulerRows(t)
			clone := func(r map[string]any) map[string]any {
				b, _ := json.Marshal(r)
				var copy map[string]any
				_ = json.Unmarshal(b, &copy)
				return copy
			}
			next := func(base map[string]any, seq int, kind string) map[string]any {
				r := clone(base)
				r["seq"] = seq + 100
				r["journal_offset"] = seq * 1000
				r["step"] = 4
				r["t_mono_ns"] = 6100000000
				r["t_wall"] = "2026-01-01T00:00:06.1Z"
				o := r["timer_operation"].(map[string]any)
				o["sequence"] = strconv.Itoa(seq)
				o["action"] = kind
				o["source"] = "lifecycle"
				o["output"] = "0"
				return r
			}
			stopped := next(operation(rows, "6"), 9, "cancelled")
			cancelled := next(operation(rows, "5"), 10, "cancel")
			cleared := next(operation(rows, "5"), 11, "clear")
			cleared["timer_operation"].(map[string]any)["cancel_kinds"] = []string{}
			rows = append(rows, stopped, cancelled, cleared)
			if reset {
				op := next(cancelled, 12, "cancel")
				op["engine_run"] = 2
				op["step"] = 1
				op["timer_operation"].(map[string]any)["sequence"] = "1"
				rows = append(rows, op)
			}
			// Replayed WAL steps deliberately have no measured entry. They supply
			// no core operation timing, but must not invalidate other measured steps.
			wal := clone(rows[len(rows)-5])
			wal["type"] = "scheduler_step"
			delete(wal, "timer_operation")
			delete(wal, "entry_t_mono_ns")
			delete(wal, "entry_t_wall")
			wal["engine_run"] = 2
			wal["step"] = 1
			wal["seq"] = 200
			wal["journal_offset"] = 20000
			wal["input_kind"] = "start"
			wal["via"] = "wal"
			rows = append(rows, wal)
			trace := rows[0]["scheduler_trace"].(map[string]any)
			trace["steps"] = "5"
			trace["operations"] = "11"
			want := verdict.Pass
			if reset {
				trace["operations"] = "12"
				want = verdict.CannotDecide
			}
			schedulerCheck(t, []*frames.Dump{schedulerDump(t, rows)}, want)
		})
	}
}
