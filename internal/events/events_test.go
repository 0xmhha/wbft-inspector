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

// TestDropped: a dropped record that matches a seq gap marks the gap lost
// without an error, one after the last record marks the records lost at
// the end, and a gap without a dropped record, a dropped record that fits
// no gap, one of a run without events and an unknown record type are
// errors.
func TestDropped(t *testing.T) {
	dir := t.TempDir()
	rec := func(run string, seq int) string {
		return `{"v":1,"node":"0xaa","run":"` + run + `","seq":` + itoa(seq) + `,"t_wall":"2023-01-01T00:00:00Z","t_mono_ns":` + itoa(seq) + `,"kind":"STATE"}` + "\n"
	}
	drop := func(run string, from, n int) string {
		return `{"v":1,"type":"dropped","node":"0xaa","run":"` + run + `","count":` + itoa(n) + `,"from_seq":` + itoa(from) + "}\n"
	}
	lines := rec("r1", 0) + rec("r1", 1) + drop("r1", 2, 3) + rec("r1", 5) + rec("r1", 6) + drop("r1", 7, 2) + // explained gap, lost tail
		rec("r2", 0) + rec("r2", 4) + // unexplained gap
		rec("r3", 0) + rec("r3", 1) + rec("r3", 2) + drop("r3", 1, 1) + // fits no gap
		drop("r9", 0, 1) + // no run
		`{"v":1,"type":"other","node":"0xaa","run":"r1"}` + "\n"
	p := filepath.Join(dir, "e.jsonl")
	if err := os.WriteFile(p, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	lost := map[string][]Span{}
	for _, r := range s.Runs {
		lost[r.ID] = r.Lost
	}
	if l := lost["r1"]; len(l) != 2 || l[0] != (Span{2, 4}) || l[1] != (Span{7, 8}) {
		t.Errorf("r1 lost %v", l)
	}
	if l := lost["r2"]; len(l) != 1 || l[0] != (Span{1, 3}) {
		t.Errorf("r2 lost %v", l)
	}
	if l := lost["r3"]; len(l) != 1 || l[0] != (Span{1, 1}) {
		t.Errorf("r3 lost %v", l)
	}
	if len(s.Errors) != 4 {
		t.Fatalf("errors %q", s.Errors)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for ; n > 0; n /= 10 {
		b = append([]byte{byte('0' + n%10)}, b...)
	}
	return string(b)
}
