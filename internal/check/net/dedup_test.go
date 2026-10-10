package net

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
)

// TestKnownCacheDrop passes a known frame discarded at once or later before
// the core, fails one the node accepted or checked in the core, cannot
// decide one without an outcome, and leaves frames without dedup, with a key
// that was not known, or outside 0x12..0x15 without an instance.
func TestKnownCacheDrop(t *testing.T) {
	const some = "aa00000000000000000000000000000000000000000000000000000000000000"
	yes, no := true, false
	in := func(seq uint64, code, outcome string, known *bool) *frames.Record {
		r := frame(seq, "in", code, some, 4, outcome)
		r.File = "f"
		if known != nil {
			r.Dedup = &frames.Dedup{KnownHit: known, PeerRecentHit: &no}
		}
		return r
	}
	outcome := func(seq, of uint64, class, chk string) *frames.Record {
		return &frames.Record{Input: "in-1", File: "f", Type: "outcome", Node: "0x01", Run: "r", Seq: seq, Of: &of, Outcome: class, Check: chk}
	}
	recs := []*frames.Record{
		in(1, "0x13", "DROP_SILENT", &yes),        // pass: discarded at once
		in(2, "0x13", "PENDING", &yes),            // pass: discarded by the prefilter
		outcome(3, 2, "DROP_SILENT", "prefilter"), //
		in(4, "0x14", "PENDING", &yes),            // fail: accepted by the core
		outcome(5, 4, "ACCEPT", "PROCESS"),        //
		in(6, "0x15", "PENDING", &yes),            // fail: dropped, but checked by the core first
		outcome(7, 6, "IGNORE", "FUTURE"),         //
		outcome(8, 6, "DROP_SILENT", "prefilter"),
		in(9, "0x12", "PENDING", &yes),      // cannot decide: no outcome
		in(10, "0x13", "PENDING", &no),      // not known: no instance
		in(11, "0x13", "PENDING", nil),      // no dedup: no instance
		in(12, "0x11", "DROP_SILENT", &yes), // legacy code: no instance
	}
	var got sink
	c := knownCacheDrop{check.Base{ID: "net.known_cache_drop"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+i.Requirement+" "+string(i.Verdict))
	}
	want := []string{
		"frame:r:1 WBFT-NET-024 PASS", "frame:r:2 WBFT-NET-024 PASS",
		"frame:r:4 WBFT-NET-024 FAIL", "frame:r:6 WBFT-NET-024 FAIL",
		"frame:r:9 WBFT-NET-024 CANNOT_DECIDE",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}
