package frames

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// This normal local snapshot checks closed metadata shape. It does not
// establish action authenticity, timeout bytes or a physical receive.
func TestLocalProposalSchedulerVocabulary(t *testing.T) {
	base := func(kind string, seq, mono int) map[string]any {
		return map[string]any{"v": 1, "type": kind, "node": "0x" + strings.Repeat("a", 40), "run": "local", "seq": seq, "t_wall": "2020-01-01T00:00:00Z", "t_mono_ns": mono, "journal_segment": 0, "journal_offset": seq}
	}
	declaration := base("scheduler_trace", 1, 0)
	declaration["t_wall"], declaration["clock_source"] = "1970-01-01T00:00:00Z", "unavailable"
	declaration["scheduler_trace"] = SchedulerTrace{Version: "1", Operations: "2", Steps: "0"}
	arm := base("timer_operation", 2, 1)
	arm["engine_run"], arm["step"] = 1, 1
	arm["timer_operation"] = TimerOperation{Sequence: "1", Action: "arm", Source: "core", Output: "1", ArmEngine: "1", ArmStep: "1", ArmOutput: "1", EntryMono: "0", Deadline: "10", TimeoutSHA256: strings.Repeat("a", 64), Timer: "round_proposal", Generation: "1", Height: "7", Round: "1", Kinds: []string{}, Decode: "complete"}
	cancel := base("timer_operation", 3, 2)
	cancel["engine_run"], cancel["step"] = 1, 2
	cancel["timer_operation"] = TimerOperation{Sequence: "2", Action: "cancel", Source: "core", Output: "1", ArmEngine: "0", ArmStep: "0", ArmOutput: "0", EntryMono: "0", Deadline: "0", Kinds: []string{"round", "retry", "future", "round_proposal"}, Decode: "not_applicable"}
	var lines strings.Builder
	for _, row := range []map[string]any{declaration, arm, cancel} {
		raw, err := json.Marshal(row)
		if err != nil {
			t.Fatal(err)
		}
		lines.Write(raw)
		lines.WriteByte('\n')
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "frames-local.jsonl"), []byte(lines.String()), 0600); err != nil {
		t.Fatal(err)
	}
	dump, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sources, problems := SchedulerSources(dump)
	if len(problems) != 0 || len(sources) != 1 || len(sources[0].Operations) != 2 {
		t.Fatal(sources, problems)
	}
	if sources[0].Operations[0].TimerOperation.Timer != "round_proposal" || len(sources[0].Operations[1].TimerOperation.Kinds) != 4 {
		t.Fatal("local timer snapshot vocabulary lost", sources[0].Operations)
	}
}
