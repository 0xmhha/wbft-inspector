package events

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLocalProposalTimerObservations(t *testing.T) {
	lines := `{"v":1,"node":"0xaa","run":"local","seq":0,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"wbft"}
{"v":1,"node":"0xaa","run":"local","seq":1,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":1,"kind":"TIMER_ARM","view":{"seq":"7","round":"1"},"step":1,"engine_run":1,"timer":"round_proposal","duration_ms":1,"gen":1}
{"v":1,"node":"0xaa","run":"local","seq":2,"t_wall":"2026-01-01T00:00:00.001Z","t_mono_ns":1000001,"kind":"TIMER_FIRE","view":{"seq":"7","round":"1"},"step":2,"engine_run":1,"timer":"round_proposal","gen":1,"stale":false}
{"v":1,"node":"0xaa","run":"local","seq":3,"t_wall":"2026-01-01T00:00:00.001Z","t_mono_ns":1000002,"kind":"HEALTH","what":"snapshot_missing_at_local_reproposal","h":"7"}
`
	p := filepath.Join(t.TempDir(), "local.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0600); err != nil {
		t.Fatal(err)
	}
	set, err := Load([]string{p})
	if err != nil || len(set.Errors) != 0 || len(set.UnknownKinds) != 0 || len(set.Runs) != 1 {
		t.Fatal(set, err)
	}
	records := set.Runs[0].Events
	if len(records) != 4 || records[1].Str("timer") != "round_proposal" || records[2].Str("timer") != "round_proposal" || records[3].Str("what") != "snapshot_missing_at_local_reproposal" {
		t.Fatal("local observation vocabulary lost", records)
	}
	if !loadSchema(t).values["timer"]["round_proposal"] || !loadSchema(t).values["what"]["snapshot_missing_at_local_reproposal"] {
		t.Fatal("local observation absent from the pinned producer schema")
	}
}
