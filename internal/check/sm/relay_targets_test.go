package sm

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type relaySink []verdict.Instance

func (s *relaySink) Emit(v verdict.Instance) { *s = append(*s, v) }
func TestRelaySelectionRejectsIncompleteAndOverlappingPeerPartitions(t *testing.T) {
	node := "0x" + strings.Repeat("1", 40)
	peer := "0x" + strings.Repeat("2", 40)
	fields := func(c, t, s []string) map[string]json.RawMessage {
		out := map[string]json.RawMessage{"available": json.RawMessage(`true`), "output_index": json.RawMessage(`1`)}
		for k, v := range map[string][]string{"candidates": c, "targets": t, "suppressed": s} {
			out[k], _ = json.Marshal(v)
		}
		return out
	}
	for _, bad := range []string{"overlap", "missing", "unknown", "duplicate", "null", "self", "index"} {
		p := &events.Event{Node: node, F: fields([]string{peer}, []string{}, []string{peer})}
		switch bad {
		case "overlap":
			p.F = fields([]string{peer}, []string{peer}, []string{peer})
		case "missing":
			p.F = fields([]string{peer}, []string{}, []string{})
		case "unknown":
			p.F["available"] = json.RawMessage(`false`)
		case "duplicate":
			p.F = fields([]string{peer, peer}, []string{}, []string{peer})
		case "null":
			p.F["targets"] = json.RawMessage(`null`)
		case "self":
			p.F = fields([]string{node}, []string{}, []string{node})
		case "index":
			delete(p.F, "output_index")
		}
		if _, ok := relaySelection(p); ok {
			t.Fatal("invalid target proof accepted", bad)
		}
	}
	p := &events.Event{Node: node, F: fields([]string{peer}, []string{}, []string{peer})}
	if targets, ok := relaySelection(p); !ok || targets {
		t.Fatal(targets, ok)
	}
	p.F = fields([]string{}, []string{}, []string{})
	if targets, ok := relaySelection(p); !ok || targets {
		t.Fatal("known empty candidate set lost", targets, ok)
	}
}
func TestRelayOnOKRequiresExactUniqueLossFreeTargetEvidence(t *testing.T) {
	node := "0x" + strings.Repeat("1", 40)
	peer := "0x" + strings.Repeat("2", 40)
	key := "0x" + strings.Repeat("a", 64)
	common := `{"v":1,"node":"` + node + `","run":"r","t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"step":7,"engine_run":1,`
	outcome := common + `"seq":0,"kind":"MSG_OUTCOME","code":19,"dedup_key":"` + key + `","outcome":"ACCEPT","via":"direct"}`
	plan := common + `"seq":1,"kind":"RELAY_TARGETS","code":19,"dedup_key":"` + key + `","available":true,"output_index":1,"candidates":["` + peer + `"],"targets":[],"suppressed":["` + peer + `"]}`
	run := func(rows string) verdict.Verdict {
		t.Helper()
		path := filepath.Join(t.TempDir(), "events.jsonl")
		if err := os.WriteFile(path, []byte(rows+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		set, err := events.Load([]string{path})
		if err != nil {
			t.Fatal(err)
		}
		var sink relaySink
		if err := (relayOnOK{check.Base{ID: "sm.relay_on_ok"}}).Run(context.Background(), &check.Inputs{Events: set}, &sink); err != nil {
			t.Fatal(err)
		}
		if len(sink) != 1 {
			t.Fatal(sink)
		}
		return sink[0].Verdict
	}
	if got := run(outcome + "\n" + plan); got != verdict.Pass {
		t.Fatal(got)
	}
	if got := run(outcome); got != verdict.CannotDecide {
		t.Fatal("missing proof became pass", got)
	}
	selected := strings.Replace(plan, `"targets":[],"suppressed":["`+peer+`"]`, `"targets":["`+peer+`"],"suppressed":[]`, 1)
	if got := run(outcome + "\n" + selected); got != verdict.Fail {
		t.Fatal("selected send without send record accepted", got)
	}
	duplicate := strings.Replace(plan, `"seq":1`, `"seq":2`, 1)
	if got := run(outcome + "\n" + plan + "\n" + duplicate); got != verdict.CannotDecide {
		t.Fatal("ambiguous target plan selected", got)
	}
	gap := strings.Replace(plan, `"seq":1`, `"seq":2`, 1)
	if got := run(outcome + "\n" + gap); got != verdict.CannotDecide {
		t.Fatal("lost source span turned into proof", got)
	}
	wrong := strings.ReplaceAll(plan, key, "0x"+strings.Repeat("b", 64))
	if got := run(outcome + "\n" + wrong); got != verdict.CannotDecide {
		t.Fatal("another payload used as proof", got)
	}
}
