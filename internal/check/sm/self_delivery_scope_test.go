package sm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func TestSelfDeliveryDoesNotPairAcrossEngineStop(t *testing.T) {
	for _, restart := range []bool{false, true} {
		t.Run(fmt.Sprint("restart=", restart), func(t *testing.T) {
			rows := []map[string]any{
				{"kind": "SEND", "cause": "broadcast", "dedup_key": "same-bytes", "code": 19, "step": 1, "engine_run": 1},
				{"kind": "ENGINE_STOP", "engine_run": 1},
			}
			if restart {
				rows = append(rows, map[string]any{"kind": "ENGINE_START", "engine_run": 2}, map[string]any{"kind": "SEND", "cause": "retry", "dedup_key": "same-bytes", "code": 19, "step": 1, "engine_run": 2})
			}
			rows = append(rows, map[string]any{"kind": "MSG_OUTCOME", "via": "self", "check": "PROCESS", "outcome": "ACCEPT", "dedup_key": "same-bytes", "code": 19, "step": 2, "engine_run": 2})
			var data strings.Builder
			for i, row := range rows {
				row["v"] = 1
				row["node"] = "0x1111111111111111111111111111111111111111"
				row["run"] = "writer"
				row["seq"] = i
				row["t_wall"] = "2026-01-01T00:00:00Z"
				row["t_mono_ns"] = i
				line, err := json.Marshal(row)
				if err != nil {
					t.Fatal(err)
				}
				data.Write(line)
				data.WriteByte('\n')
			}
			path := filepath.Join(t.TempDir(), "events.jsonl")
			if err := os.WriteFile(path, []byte(data.String()), 0600); err != nil {
				t.Fatal(err)
			}
			set, err := events.Load([]string{path})
			if err != nil {
				t.Fatal(err)
			}
			if len(set.Errors) != 0 {
				t.Fatal(set.Errors)
			}
			var sink relaySink
			if err := (selfDelivery{}).Run(context.Background(), &check.Inputs{Events: set}, &sink); err != nil {
				t.Fatal(err)
			}
			got := map[string]verdict.Instance{}
			for _, instance := range sink {
				got[instance.Key] = instance
			}
			first, ok := got["event:writer:0"]
			if !ok || first.Verdict != verdict.CannotDecide || first.Reason != verdict.NotExercised {
				t.Fatalf("stopped engine's send consumed a later self-delivery: %+v", first)
			}
			if restart {
				second, ok := got["event:writer:3"]
				if !ok || second.Verdict != verdict.Pass {
					t.Fatalf("restarted engine's send lost its own self-delivery: %+v", second)
				}
				if len(got) != 2 {
					t.Fatal(got)
				}
			} else if len(got) != 1 {
				t.Fatal(got)
			}
		})
	}
}
