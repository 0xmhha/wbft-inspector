package check_test

import (
	"context"
	"encoding/json"
	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func restoredClockRecords() []rec {
	common := func(kind string, mono int64) rec {
		return rec{"v": 1, "node": "0x0000000000000000000000000000000000000001", "run": "restored-clock", "t_wall": "2026-01-01T00:00:00Z", "t_mono_ns": mono, "kind": kind, "engine_run": 1}
	}
	start := common("ENGINE_START", 1_000_000_000)
	start["reason"], start["replay"] = "start", map[string]any{"records": 1, "stopped": nil, "replayed": true, "available": true, "enabled": true}
	arm := common("TIMER_ARM", 1_000_100_000)
	arm["view"], arm["timer"], arm["gen"], arm["duration_ms"], arm["rearmed"], arm["deadline_mono_ns"] = map[string]string{"seq": "10", "round": "0"}, "round", 17, 2000, true, int64(3_000_010_000)
	fire := common("TIMER_FIRE", 3_000_011_000)
	fire["view"], fire["timer"], fire["gen"], fire["stale"], fire["step"] = arm["view"], "round", 17, false, 1
	send := common("SEND", fire["t_mono_ns"].(int64))
	send["view"], send["code"], send["cause"], send["step"] = map[string]string{"seq": "10", "round": "1"}, 0x15, "broadcast", 1
	return []rec{start, arm, fire, send}
}

func TestRestoredDeadlineClockChecks(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func([]rec)
		want verdict.Verdict
	}{
		{"logical deadline", func([]rec) {}, verdict.Pass},
		{"legacy missing deadline", func(r []rec) { delete(r[1], "deadline_mono_ns") }, verdict.CannotDecide},
		{"inconsistent origin", func(r []rec) { r[1]["deadline_mono_ns"] = int64(3_100_000_000) }, verdict.CannotDecide},
		{"early expiry", func(r []rec) { r[2]["t_mono_ns"], r[3]["t_mono_ns"] = int64(2_700_000_000), int64(2_700_000_000) }, verdict.Fail},
		{"same tolerance boundary", func(r []rec) { r[2]["t_mono_ns"], r[3]["t_mono_ns"] = int64(3_000_009_999), int64(3_000_009_999) }, verdict.CannotDecide},
	} {
		t.Run(test.name, func(t *testing.T) {
			records := restoredClockRecords()
			test.edit(records)
			results := decide(t, records)
			for _, req := range []string{"WBFT-TIMER-002", "WBFT-TIMER-005", "WBFT-SM-089"} {
				if got, ok := results[req]; !ok || got.Verdict != test.want {
					t.Fatalf("%s: got %+v, want %s", req, got, test.want)
				}
			}
		})
	}
}

func TestRetainedSchedulerClockChecksAndEvidence(t *testing.T) {
	for _, given := range []bool{false, true} {
		records := restoredClockRecords()
		delete(records[1], "deadline_mono_ns")
		first := rec{"v": 1, "node": "0xaa00000000000000000000000000000000000000", "run": "restored-clock", "kind": "NODE_START", "t_mono_ns": int64(999_900_000), "t_wall": "2026-01-01T00:00:00Z"}
		stop := rec{"v": 1, "node": first["node"], "run": first["run"], "kind": "ENGINE_STOP", "engine_run": 1, "t_mono_ns": int64(4_000_003_000), "t_wall": "2026-01-01T00:00:04.000003Z"}
		end := rec{"v": 1, "node": first["node"], "run": first["run"], "kind": "NODE_STOP", "t_mono_ns": int64(4_000_004_000), "t_wall": "2026-01-01T00:00:04.000004Z"}
		records = append(append([]rec{first}, records...), stop, end)
		var raw []byte
		for i, r := range records {
			r["seq"], r["node"] = i, first["node"]
			if r["kind"] == "TIMER_FIRE" || r["kind"] == "SEND" {
				r["t_wall"] = "2026-01-01T00:00:03.000011Z"
			}
			b, err := json.Marshal(r)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(append(raw, b...), '\n')
		}
		file := filepath.Join(t.TempDir(), "events.jsonl")
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		es, err := events.Load([]string{file})
		if err != nil || len(es.Errors) > 0 {
			t.Fatal(err, es.Errors)
		}
		cb, err := os.ReadFile(filepath.Join("..", "..", "testdata", "chain-config.json"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := params.ParseGenesis(cb)
		if err != nil {
			t.Fatal(err)
		}
		in := &check.Inputs{Events: es, Config: cfg, Given: map[check.Kind]bool{check.Events: true, check.ChainConfig: true}, Clock: check.Clock{Model: "shared-host", SchedMs: 100, Margin: 100}}
		want := verdict.CannotDecide
		if given {
			dump, e := frames.Load("../frames/testdata/retained-clock")
			if e != nil {
				t.Fatal(e)
			}
			dump.SetInput("retained")
			in.Frames = []*frames.Dump{dump}
			want = verdict.Pass
		}
		selected := map[string]bool{"WBFT-TIMER-002": true, "WBFT-TIMER-005": true, "WBFT-SM-089": true}
		out := check.Run(context.Background(), in, selected)
		if len(out.Errors) > 0 {
			t.Fatal(out.Errors)
		}
		for req := range selected {
			instances := out.Instances[req]
			if len(instances) != 1 || instances[0].Verdict != want {
				t.Fatalf("%s source=%v: %+v", req, given, instances)
			}
			if given {
				count := 0
				for _, ptr := range instances[0].Evidence {
					if ptr.Input == "retained" {
						count++
					}
				}
				if count != 8 {
					t.Fatalf("%s: original R01 pointers=%d", req, count)
				}
			}
		}
	}
}
