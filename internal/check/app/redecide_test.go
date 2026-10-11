package app

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const (
	blockX = "0x" + "aa00000000000000000000000000000000000000000000000000000000000000"
	blockY = "0x" + "bb00000000000000000000000000000000000000000000000000000000000000"
)

// runOf builds a run from (kind, seq, round, fields) records.
func runOf(id string, recs ...[]any) *events.Run {
	r := &events.Run{Node: "0xaa", ID: id, Input: "in-1"}
	for i, x := range recs {
		e := &events.Event{Input: "in-1", Line: i + 1, Node: "0xaa", Run: id, Seq: uint64(i + 1), Kind: x[0].(string), F: map[string]json.RawMessage{}}
		if x[1] != "" {
			e.View = &events.View{Seq: x[1].(string), Round: x[2].(string)}
		}
		if len(x) > 3 {
			for k, v := range x[3].(map[string]any) {
				raw, _ := json.Marshal(v)
				e.F[k] = raw
			}
		}
		r.Events = append(r.Events, e)
	}
	return r
}

func enter(seq, round, cause string) []any {
	return []any{"ROUND_ENTER", seq, round, map[string]any{"cause": cause}}
}
func handover(num, hash string) []any {
	return []any{"FINALIZE_HANDOVER", "", "", map[string]any{"number": num, "hash": hash}}
}
func result(num, hash string, ok bool) []any {
	return []any{"COMMIT_RESULT", "", "", map[string]any{"number": num, "hash": hash, "ok": ok}}
}
func head(num, hash string) []any {
	return []any{"NEW_HEAD", "", "", map[string]any{"number": num, "hash": hash}}
}

// TestNoRedecideBadBlock covers each way a height can go on after its
// finalized block failed import.
func TestNoRedecideBadBlock(t *testing.T) {
	cases := []struct {
		name   string
		run    *events.Run
		want   verdict.Verdict
		reason verdict.Reason
		msg    string
	}{
		{"round timer", runOf("r1", enter("2", "0", "new_head"), handover("2", blockX), result("2", blockX, false),
			enter("2", "1", "timeout"), handover("2", blockY), result("2", blockY, true), head("2", blockY)),
			verdict.Pass, "", "round 1 (cause timeout)"},
		{"f+1 rule", runOf("r2", enter("2", "0", "new_head"), result("2", blockX, false), enter("2", "1", "f_plus_one")),
			verdict.Pass, "", "cause f_plus_one"},
		{"decided again", runOf("r3", enter("2", "0", "new_head"), result("2", blockX, false), enter("2", "1", "timeout"),
			handover("2", blockX)), verdict.Fail, "", "decided it again"},
		{"became the head", runOf("r4", enter("2", "0", "new_head"), result("2", blockX, false), head("2", blockX)),
			verdict.Fail, "", "became the head"},
		{"round change on the failure", runOf("r5", enter("2", "0", "new_head"), result("2", blockX, false),
			enter("2", "1", "finalize_fail")), verdict.Fail, "", "not by the round timer"},
		{"another block first", runOf("r6", enter("2", "0", "new_head"), result("2", blockX, false), head("2", blockY)),
			verdict.Pass, "", "ended with another block"},
		{"run ends", runOf("r7", enter("2", "0", "new_head"), result("2", blockX, false), enter("2", "0", "timeout")),
			verdict.CannotDecide, verdict.MissingData, "run ends"},
		{"lower head ignored", runOf("r8", enter("2", "1", "timeout"), result("2", blockX, false), head("1", blockX),
			enter("2", "2", "timeout")), verdict.Pass, "", "round 2"},
	}
	c := noRedecideBadBlock{check.Base{ID: "app.no_redecide_bad_block"}}
	for _, tc := range cases {
		var got sink
		in := &check.Inputs{Events: &events.Set{Runs: []*events.Run{tc.run}}}
		if err := c.Run(context.Background(), in, &got); err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Verdict != tc.want || got[0].Reason != tc.reason || !strings.Contains(got[0].Message, tc.msg) {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
	// IMPORT_FAIL of the node's own finalized block is a failure too, and
	// a COMMIT_RESULT of the same block after it is not another instance;
	// an import failure on another path is none.
	var got sink
	in := &check.Inputs{Events: &events.Set{Runs: []*events.Run{runOf("r10", enter("2", "0", "new_head"),
		[]any{"IMPORT_FAIL", "", "", map[string]any{"number": "2", "hash": blockX, "path": "sealed_locally", "recorded_bad": true}},
		result("2", blockX, false),
		[]any{"IMPORT_FAIL", "", "", map[string]any{"number": "3", "hash": blockY, "path": "imported", "recorded_bad": true}},
		enter("2", "1", "timeout"))}}}
	if err := c.Run(context.Background(), in, &got); err != nil || len(got) != 1 || got[0].Verdict != verdict.Pass || got[0].Key != "event:r10:2" {
		t.Fatalf("import failures: %+v %v", got, err)
	}
	// A successful import is no instance.
	got = nil
	in = &check.Inputs{Events: &events.Set{Runs: []*events.Run{runOf("r9", result("2", blockX, true))}}}
	if err := c.Run(context.Background(), in, &got); err != nil || len(got) != 0 {
		t.Fatalf("ok import: %v %v", got, err)
	}
}
