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

func TestBacklogRelayTargetEvidence(t *testing.T) {
	for _, tc := range []struct {
		name string
		want verdict.Verdict
	}{
		{"filtered", verdict.Pass},
		{"empty candidates", verdict.Pass},
		{"selected without send", verdict.Fail},
		{"missing", verdict.CannotDecide},
		{"duplicate", verdict.CannotDecide},
		{"wrong payload", verdict.CannotDecide},
		{"empty payload key", verdict.CannotDecide},
		{"wrong code", verdict.CannotDecide},
		{"other step", verdict.CannotDecide},
		{"other engine", verdict.CannotDecide},
		{"other process", verdict.CannotDecide},
		{"other node", verdict.CannotDecide},
		{"lost records", verdict.CannotDecide},
		{"log input", verdict.CannotDecide},
		{"incomplete partition", verdict.CannotDecide},
		{"unknown availability", verdict.CannotDecide},
		{"reencoded send", verdict.Pass},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := uint64(7)
			key := "0x" + strings.Repeat("a", 64)
			peer := "0x" + strings.Repeat("2", 40)
			fields := func(v map[string]any) map[string]json.RawMessage {
				f := map[string]json.RawMessage{}
				for k, x := range v {
					f[k], _ = json.Marshal(x)
				}
				return f
			}
			outcome := &events.Event{Kind: "MSG_OUTCOME", Step: &step, F: fields(map[string]any{
				"code": 19, "dedup_key": key, "outcome": "ACCEPT", "via": "backlog", "engine_run": 1,
			})}
			plan := &events.Event{Kind: "RELAY_TARGETS", Step: &step, F: fields(map[string]any{
				"code": 19, "dedup_key": key, "engine_run": 1, "available": true, "output_index": 1,
				"candidates": []string{peer}, "targets": []string{}, "suppressed": []string{peer},
			})}
			r := &events.Run{Events: []*events.Event{plan, outcome}}
			switch tc.name {
			case "empty candidates":
				plan.F["candidates"] = json.RawMessage(`[]`)
				plan.F["suppressed"] = json.RawMessage(`[]`)
			case "selected without send":
				plan.F["targets"], plan.F["suppressed"] = plan.F["suppressed"], plan.F["targets"]
			case "missing":
				r.Events = []*events.Event{outcome}
			case "duplicate":
				r.Events = []*events.Event{plan, plan, outcome}
			case "wrong payload":
				plan.F["dedup_key"] = json.RawMessage(`"different"`)
			case "empty payload key":
				delete(plan.F, "dedup_key")
				delete(outcome.F, "dedup_key")
			case "wrong code":
				plan.F["code"] = json.RawMessage(`18`)
			case "other step":
				other := uint64(8)
				plan.Step = &other
			case "other engine":
				r.Events = []*events.Event{plan, {Kind: "ENGINE_STOP"}, outcome}
			case "lost records":
				r.Lost = append(r.Lost, events.Span{})
			case "log input":
				r.FromLog = true
			case "incomplete partition":
				plan.F["suppressed"] = json.RawMessage(`[]`)
			case "unknown availability":
				plan.F["available"] = json.RawMessage(`false`)
			case "reencoded send":
				plan.Kind = "SEND"
				plan.F["cause"] = json.RawMessage(`"relay"`)
				plan.F["dedup_key"] = json.RawMessage(`"reencoded"`)
			}
			var rows []string
			for i, event := range r.Events {
				f := fields(map[string]any{"v": 1, "node": "0x" + strings.Repeat("1", 40), "run": "r", "seq": i, "t_wall": "2026-01-01T00:00:00Z", "t_mono_ns": 0, "kind": event.Kind})
				if event == plan && tc.name == "other process" {
					f["run"] = json.RawMessage(`"other"`)
				}
				if event == plan && tc.name == "other node" {
					f["node"] = json.RawMessage(`"0x3333333333333333333333333333333333333333"`)
				}
				for k, v := range event.F {
					f[k] = v
				}
				if event.Step != nil {
					f["step"], _ = json.Marshal(*event.Step)
				}
				row, err := json.Marshal(f)
				if err != nil {
					t.Fatal(err)
				}
				rows = append(rows, string(row))
			}
			path := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(path, []byte(strings.Join(rows, "\n")+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			set, err := events.Load([]string{path})
			if err != nil || len(set.Errors) > 0 || len(set.Runs) == 0 {
				t.Fatalf("load: %v %+v", err, set)
			}
			for _, loaded := range set.Runs {
				loaded.FromLog, loaded.Lost = r.FromLog, r.Lost
			}
			var sink relaySink
			err = (relayBacklog{}).Run(context.Background(), &check.Inputs{Events: set}, &sink)
			if err != nil || len(sink) != 1 {
				t.Fatalf("err=%v instances=%v", err, sink)
			}
			if tc.want == verdict.CannotDecide && sink[0].Reason != verdict.ObserverScope {
				t.Fatal(sink[0])
			}
			if tc.want != verdict.CannotDecide && len(sink[0].Evidence) != 2 {
				t.Fatal("missing target or send evidence", sink[0])
			}
			if sink[0].Verdict != tc.want {
				t.Fatalf("got %v, want %v: %+v", sink[0].Verdict, tc.want, sink[0])
			}
		})
	}
}
