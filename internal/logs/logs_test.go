package logs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLoadNodeLog reads the log of a wbft node run with every module at
// trace (testdata/node.log: 51 lines, written by wbft's node tests) with the
// profile of that build: every consensus and log settings line becomes an
// event of the profile's kind, marked as read from a log.
func TestLoadNodeLog(t *testing.T) {
	p, err := LoadProfile(filepath.Join("testdata", "wbft-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Load(p, "0xaa", []string{filepath.Join("testdata", "node.log")})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Errors) != 0 || len(s.Runs) != 1 || len(s.UnknownKinds) != 0 {
		t.Fatalf("errors %v, runs %d, unknown %v", s.Errors, len(s.Runs), s.UnknownKinds)
	}
	r := s.Runs[0]
	if !r.FromLog || r.Node != "0xaa" || len(r.Events) != 51 || s.Inputs[0].Records != 51 {
		t.Fatalf("run %+v with %d events", r, len(r.Events))
	}
	kinds := map[string]int{}
	for i, e := range r.Events {
		if !e.FromLog || e.Src != "log" || e.Seq != uint64(i) || e.TWall == "" {
			t.Fatalf("event %d: %+v", i, e)
		}
		kinds[e.Kind]++
	}
	for _, k := range []string{"LOG_CONFIG", "ROUND_ENTER", "TIMER_ARM", "ENGINE_START", "SEND", "MSG_OUTCOME", "COMMIT_RESULT"} {
		if kinds[k] == 0 {
			t.Fatalf("no %s: %v", k, kinds)
		}
	}
	re := r.Events[1]
	if re.Kind != "ROUND_ENTER" || re.View.String() == "" || re.View.Seq != "1" || !re.StepIs(1) || re.Str("cause") != "start" {
		t.Fatalf("round enter %+v", re)
	}
	if lc := r.Events[0]; lc.Kind != "LOG_CONFIG" || lc.Str("level") != "trace" || lc.Has("base_level") {
		t.Fatalf("log config %+v", lc)
	}
}

// TestLoadRejects reports a consensus line the profile does not map, a
// line at another level and a malformed line, and skips other modules'
// lines and the node's other lines.
func TestLoadRejects(t *testing.T) {
	p, err := LoadProfile(filepath.Join("testdata", "wbft-profile.json"))
	if err != nil {
		t.Fatal(err)
	}
	lines := `{"time":"2026-01-01T00:00:00Z","level":"INFO","msg":"something new","module":"consensus.round","h":"1","r":"0"}
{"time":"2026-01-01T00:00:00Z","level":"INFO","msg":"round entered","module":"consensus.round","h":"1","r":"0"}
not json
{"time":"2026-01-01T00:00:00Z","level":"INFO","msg":"peer connected","module":"geth.p2p"}
{"time":"2026-01-01T00:00:00Z","level":"WARN","msg":"event write failed","module":"node"}
{"t":"2026-01-01T00:00:01Z","lvl":"info","msg":"block finalized","module":"consensus.round","number":"1"}
`
	f := filepath.Join(t.TempDir(), "x.log")
	if err := os.WriteFile(f, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := Load(p, "0xbb", []string{f})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Errors) != 3 || !strings.Contains(s.Errors[0], "not in profile") || !strings.Contains(s.Errors[1], "level") {
		t.Fatalf("errors %v", s.Errors)
	}
	if len(s.Runs) != 1 || len(s.Runs[0].Events) != 1 || s.Runs[0].Events[0].Kind != "COMMIT_RESULT" ||
		s.Runs[0].Events[0].TWall != "2026-01-01T00:00:01Z" {
		t.Fatalf("runs %+v", s.Runs)
	}
}

// TestLoadProfileFormat refuses another profile format and two entries
// for one line.
func TestLoadProfileFormat(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"format": `{"format":"other/1","entries":[]}`,
		"dup": `{"format":"wbft-log-profile/1","entries":[{"kind":"A","module":"m","level":"info","msg":"x"},` +
			`{"kind":"B","module":"m","level":"debug","msg":"x"}]}`,
	} {
		f := filepath.Join(dir, name+".json")
		if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(f); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}
