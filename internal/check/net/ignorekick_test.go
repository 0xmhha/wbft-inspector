package net

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
)

// TestNoDisconnectForIgnore fails an IGNORE frame a close by the node
// names, cannot decide one whose final outcome is followed by a close for
// another reason before the next outcome for the peer (even when the peer's
// next frame came in between), and passes the others; closes by the peer or not
// attributed, and frames that did not end in IGNORE, do not count.
func TestNoDisconnectForIgnore(t *testing.T) {
	var b recentRun
	frame := func(peer, key, outcome string) *frames.Record {
		r := b.add("frame", "in", peer, key, nil)
		r.Code, r.Outcome = "0x13", outcome
		return r
	}
	outcome := func(of *frames.Record, class string) {
		r := b.add("outcome", "", "", "", nil)
		r.Peer, r.DedupKey, r.Of, r.Outcome = nil, "", &of.Seq, class
	}
	closed := func(peer, by, cause string, of *frames.Record) {
		r := b.add("conn", "", peer, "", nil)
		r.Event, r.By, r.Cause = "closed", by, cause
		if of != nil {
			r.Of = &of.Seq
		}
	}
	ig := frame("pa", "k1", "PENDING") // 1 FAIL: the node closed the stream for it
	outcome(ig, "IGNORE")              // 2
	closed("pa", "self", "engine_stopped", ig)
	frame("pb", "k2", "IGNORE")        // 4 CANNOT_DECIDE: closed for another reason before pb's next frame
	closed("pb", "self", "other", nil) // 5
	frame("pc", "k3", "IGNORE")        // 6 PASS: the peer closed
	closed("pc", "peer", "", nil)      // 7
	frame("pd", "k4", "IGNORE")        // 8 PASS: not attributed
	closed("pd", "unknown", "", nil)   // 9
	frame("pe", "k5", "IGNORE")        // 10 PASS: the peer's next frame comes first
	frame("pe", "k6", "ACCEPT")        // 11 not IGNORE: no instance
	closed("pe", "self", "other", nil) // 12
	frame("pf", "k7", "IGNORE")        // 13 PASS: closed for queue overflow
	closed("pf", "self", "queue_overflow", nil)
	dc := frame("pg", "k8", "DISCONNECT") // 15 not IGNORE: no instance
	closed("pg", "self", "frame", dc)
	late := frame("ph", "k9", "PENDING") // 17 CANNOT_DECIDE: the peer's next frame came before its outcome
	frame("ph", "k10", "PENDING")        // 18 no outcome: no instance
	outcome(late, "IGNORE")              // 19
	closed("ph", "self", "other", nil)   // 20
	var got sink
	c := noDisconnectForIgnore{check.Base{ID: "net.no_disconnect_for_ignore"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: b.recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict))
	}
	want := []string{"frame:r:1 FAIL", "frame:r:4 CANNOT_DECIDE", "frame:r:6 PASS", "frame:r:8 PASS", "frame:r:10 PASS", "frame:r:13 PASS", "frame:r:17 CANNOT_DECIDE"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}
