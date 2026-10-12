package logs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLegacyIndependentNormalization(t *testing.T) {
	p, err := LoadProfile("../../profiles/gstable@740526d03.json")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"t":"2026-10-13T00:00:00Z","lvl":"info","msg":"WBFT: start","address":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:01Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"0","next.proposer":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:02Z","lvl":"warn","msg":"WBFT: TIMER CHANGING ROUND","current.sequence":"18446744073709551617","current.round":"0"}
{"t":"2026-10-13T00:00:03Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"1"}
{"t":"2026-10-13T00:00:04Z","lvl":"info","msg":"WBFT: broadcast ROUND-CHANGE message","current.sequence":"18446744073709551617","current.round":"1","msg.code":21,"payload":"NEVER_STORE","data":"NEVER_STORE","err":"NEVER_STORE"}
{"t":"2026-10-13T00:00:05Z","lvl":"info","msg":"WBFT: received F+1 ROUND-CHANGE messages","current.sequence":"18446744073709551617","current.round":"1"}
{"t":"2026-10-13T00:00:06Z","lvl":"info","msg":"WBFT: start new round","next.seq":"18446744073709551617","next.round":"340282366920938463463374607431768211456"}
{"t":"2026-10-13T00:00:07Z","lvl":"trace","msg":"WBFT: post backlog event","msg":"NEVER_STORE"}
{"t":"2026-10-13T00:00:08Z","lvl":"info","msg":"WBFT: stopped","address":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:09Z","lvl":"info","msg":"WBFT: start","address":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:10Z","lvl":"debug","msg":"WBFT: accepted PRE-PREPARE message","address":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:11Z","lvl":"trace","msg":"WBFT:   - candidates[100]","addr":"0x0000000000000000000000000000000000000001"}
{"t":"2026-10-13T00:00:12Z","lvl":"info","msg":"other app"}
{"t":"2026-10-13T00:00:13Z","lvl":"info","msg":"WBFT: UNKNOWN NEVER_STORE"}
`
	path := filepath.Join(t.TempDir(), "node.log")
	_ = os.WriteFile(path, []byte(body), 0600)
	s, err := Load(p, []File{{Node: "node1", Path: path}})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Errors) != 1 || strings.Contains(s.Errors[0], "NEVER_STORE") || len(s.Inputs) != 1 || s.Inputs[0].Records != 12 || len(s.Runs) != 2 {
		t.Fatal(s)
	}
	sum := sha256.Sum256([]byte(body))
	if s.Inputs[0].SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("input hash changed")
	}
	for _, r := range s.Runs {
		if r.Complete || !r.FromLog {
			t.Fatal("invented complete stream")
		}
		for _, e := range r.Events {
			if e.Step != nil || e.TMono != 0 {
				t.Fatal("invented step/clock")
			}
		}
	}
	if s.Runs[0].Events[1].View.Seq != "18446744073709551617" || s.Runs[1].Events[1].View != nil {
		t.Fatal("view truncated or survived restart")
	}
	if s.Runs[0].Events[4].Code() != 21 {
		t.Fatal("message code unavailable")
	}
	obs := Observations(s)
	if len(obs) != 3 {
		t.Fatal(obs)
	}
	kinds := map[string]int{}
	for _, o := range obs {
		kinds[o.Kind] = o.Count
	}
	if kinds["round_change_timeout"] != 1 || kinds["round_change_f_plus_one"] != 1 || kinds["engine_restart"] != 1 {
		t.Fatal(kinds)
	}
	raw, _ := json.Marshal(s)
	if strings.Contains(string(raw), "NEVER_STORE") {
		t.Fatal("raw source values retained")
	}
	from, _ := time.Parse(time.RFC3339, "2026-10-13T00:00:02Z")
	to, _ := time.Parse(time.RFC3339, "2026-10-13T00:00:06Z")
	window, err := LoadWindow(context.Background(), p, []File{{Node: "node1", Path: path}}, Window{From: from, To: to})
	if err != nil || window.Inputs[0].Records != 5 || window.Inputs[0].SHA256 != s.Inputs[0].SHA256 || window.Runs[0].Events[0].Line != 3 {
		t.Fatal(window, err)
	}
	if _, err := LoadWindow(context.Background(), p, []File{{Node: "n", Path: path}}, Window{MaxEvents: 1}); err == nil {
		t.Fatal("event limit ignored")
	}
}

func TestRealG7MetadataExcerpt(t *testing.T) {
	p, err := LoadProfile("../../profiles/gstable@740526d03.json")
	if err != nil {
		t.Fatal(err)
	}
	files := []File{}
	for i := 1; i <= 7; i++ {
		files = append(files, File{Node: fmt.Sprintf("node%d", i), Path: fmt.Sprintf("testdata/g7/node%d.jsonl", i)})
	}
	s, err := Load(p, files)
	if err != nil || len(s.Errors) != 0 {
		t.Fatal(s, err)
	}
	count := 0
	for _, in := range s.Inputs {
		count += in.Records
	}
	if count != 310 {
		t.Fatal(count)
	}
	byHeight := map[string]int{}
	for _, o := range Observations(s) {
		for i := 0; i < len(o.Evidence); i += 2 {
			e := o.Evidence[i]
			byHeight[e.Number+":"+o.Kind]++
		}
	}
	expected := map[string]int{"5542:round_change_timeout": 5, "5542:round_change_f_plus_one": 1, "5565:round_change_timeout": 10}
	if len(byHeight) != len(expected) {
		t.Fatal(byHeight)
	}
	for key, n := range expected {
		if byHeight[key] != n {
			t.Fatal(byHeight)
		}
	}
}

func TestLegacyCauseDoesNotCrossRunHeightOrClock(t *testing.T) {
	fire := &events.Event{Node: "n", Run: "r", Kind: "TIMER_FIRE", TWall: "2026-10-13T00:00:00Z", View: &events.View{Seq: "7", Round: "1"}, F: map[string]json.RawMessage{"timer": json.RawMessage(`"round"`)}}
	enter := *fire
	enter.Kind = "ROUND_ENTER"
	enter.View = &events.View{Seq: "7", Round: "2"}
	enter.TWall = "2026-10-13T00:00:01Z"
	if CorrelatedTrigger(fire, &enter) != "timeout" {
		t.Fatal("missing timer cause")
	}
	for _, change := range []func(*events.Event){func(e *events.Event) { e.Run = "other" }, func(e *events.Event) { e.View = &events.View{Seq: "8", Round: "2"} }, func(e *events.Event) { e.TWall = "2026-10-12T00:00:00Z" }} {
		e := enter
		change(&e)
		if CorrelatedTrigger(fire, &e) != "" {
			t.Fatal("unrelated timer correlated")
		}
	}
}
