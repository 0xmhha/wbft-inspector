package check

import (
	"encoding/json"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func TestMembershipEvidenceIsScopedToNodeAndWriterRun(t *testing.T) {
	member := &events.Run{Node: "0x1111111111111111111111111111111111111111", ID: "shared-run"}
	member.Events = []*events.Event{
		{Kind: "ROUND_ENTER", View: &events.View{Seq: "7", Round: "0"}},
		{Kind: "SEND", F: map[string]json.RawMessage{"cause": json.RawMessage(`"broadcast"`)}},
	}
	other := &events.Run{Node: "0x2222222222222222222222222222222222222222", ID: member.ID}
	m := Members(&Inputs{Events: &events.Set{Runs: []*events.Run{member, other}}})
	for _, tc := range []struct {
		name string
		run  *events.Run
		seq  string
		want bool
	}{
		{"same node and run", member, "7", true},
		{"other node with reused run ID", other, "7", false},
		{"other writer run", &events.Run{Node: member.Node, ID: "new-run"}, "7", false},
		{"other height", member, "8", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := m.In(tc.run, tc.seq); got != tc.want {
				t.Fatalf("membership=%v, want %v", got, tc.want)
			}
		})
	}
	missing := MissingSend("WBFT-SM-077", &events.Event{Node: other.Node, Run: other.ID}, Step{Run: other}, m, "7", "round-change")
	if missing.Verdict != verdict.CannotDecide || missing.Reason != verdict.ObserverScope {
		t.Fatalf("another node's broadcast proved a missing-send failure: %+v", missing)
	}
}
