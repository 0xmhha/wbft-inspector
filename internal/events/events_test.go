package events

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	lines := `{"v":1,"node":"0xaa","run":"r1","seq":0,"t_wall":"2023-01-01T00:00:00Z","t_mono_ns":0,"kind":"NODE_START","impl":"x"}
{"v":1,"node":"0xaa","run":"r1","seq":1,"t_wall":"2023-01-01T00:00:00Z","t_mono_ns":5,"kind":"ROUND_ENTER","view":{"seq":"1","round":"0"},"step":1}
not json
{"v":2,"node":"0xaa","run":"r1","seq":2,"t_wall":"x","t_mono_ns":6,"kind":"STATE"}
{"v":1,"node":"0xaa","run":"r1","seq":4,"t_wall":"2023-01-01T00:00:01Z","t_mono_ns":9,"kind":"NEW_THING","step":1}
{"v":1,"node":"0xaa","run":"r1","seq":5,"t_wall":"2023-01-01T00:00:01Z","t_mono_ns":9,"kind":"ENGINE_STOP"}
{"v":1,"node":"0xaa","run":"r1","seq":6,"t_wall":"2023-01-01T00:00:01Z","t_mono_ns":9,"kind":"STATE","step":1,"imp":["x"]}
`
	p := filepath.Join(dir, "e.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Runs) != 1 || len(s.Runs[0].Events) != 5 {
		t.Fatalf("runs %d", len(s.Runs))
	}
	// A malformed line, an unsupported version and a gap in seq.
	if len(s.Errors) != 3 {
		t.Fatalf("errors %v", s.Errors)
	}
	if s.UnknownKinds["NEW_THING"] != 1 {
		t.Errorf("unknown kinds %v", s.UnknownKinds)
	}
	if n := s.Nodes["0xaa"]; n.Impl != "x" || !n.Optional {
		t.Errorf("node %+v", n)
	}
	r := s.Runs[0]
	// Step 1 before and after the engine stop are different steps.
	if len(r.StepOf(1)) != 2 || len(r.StepOf(4)) != 1 {
		t.Errorf("steps %v %v", r.StepOf(1), r.StepOf(4))
	}
	if r.Events[1].View.SeqBig().Int64() != 1 || s.Inputs[0].Records != 5 {
		t.Error("view or input count")
	}
}
