package net

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
)

// TestNoRelayCases decides each received frame that ended in DROP_SILENT or
// IGNORE against the relays of its key in the run.
func TestNoRelayCases(t *testing.T) {
	var b recentRun
	frame := func(dir, peer, key, outcome, cause string) *frames.Record {
		r := b.add("frame", dir, peer, key, nil)
		r.Outcome, r.Cause = outcome, cause
		return r
	}
	outcome := func(of *frames.Record, class string) {
		r := b.add("outcome", "", "", "", nil)
		r.Peer, r.DedupKey, r.Of, r.Outcome = nil, "", &of.Seq, class
	}
	frame("in", "pa", "k1", "DROP_SILENT", "")                    // 1 PASS: not relayed
	ig := frame("in", "pa", "k2", "PENDING", "")                  // 2 FAIL: ignored, then relayed
	outcome(ig, "IGNORE")                                         // 3
	frame("out", "pb", "k2", "", "relay")                         // 4
	acc := frame("in", "pa", "k3", "PENDING", "")                 // 5 accepted
	outcome(acc, "ACCEPT")                                        // 6
	frame("in", "pb", "k3", "DROP_SILENT", "")                    // 7 PASS: another copy was accepted
	frame("out", "pc", "k3", "", "relay")                         // 8
	frame("out", "pa", "k4", "", "broadcast")                     // 9 own message
	frame("in", "pa", "k4", "DROP_SILENT", "")                    // 10 PASS: own key
	frame("out", "pb", "k4", "", "relay")                         // 11
	bl := frame("in", "pa", "k5", "PENDING", "")                  // 12 backlog, then accepted: no instance
	outcome(bl, "IGNORE")                                         // 13
	outcome(bl, "ACCEPT")                                         // 14
	frame("out", "pb", "k5", "", "relay")                         // 15
	frame("in", "pa", "k6", "PENDING", "")                        // 16 no outcome: no instance
	frame("in", "pa", "k7", "DISCONNECT", "")                     // 17 not a case of the rule
	frame("out", "pb", "k7", "", "relay")                         // 18
	frame("in", "pa", "k8", "DROP_SILENT", "")                    // 19 FAIL: a relay the cache suppressed
	b.add("send_suppressed", "", "pb", "k8", nil).Cause = "relay" // 20
	var got sink
	c := noRelayCases{check.Base{ID: "net.no_relay_cases"}}
	run := func(recs []*frames.Record) []string {
		got = nil
		if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
			t.Fatal(err)
		}
		var lines []string
		for _, i := range got {
			lines = append(lines, i.Key+" "+string(i.Verdict))
		}
		return lines
	}
	want := []string{"frame:r:1 PASS", "frame:r:2 FAIL", "frame:r:7 PASS", "frame:r:10 PASS", "frame:r:19 FAIL"}
	if l := run(b.recs); strings.Join(l, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(l, "\n"), strings.Join(want, "\n"))
	}
	// A run that lost records cannot rule out an accepted copy.
	b.add("dropped", "", "", "", nil).Peer = nil
	want[1], want[4] = "frame:r:2 CANNOT_DECIDE", "frame:r:19 CANNOT_DECIDE"
	if l := run(b.recs); strings.Join(l, "\n") != strings.Join(want, "\n") {
		t.Fatalf("with lost records\n%s\nwant\n%s", strings.Join(l, "\n"), strings.Join(want, "\n"))
	}
}
