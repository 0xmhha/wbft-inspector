package check_test

import (
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
