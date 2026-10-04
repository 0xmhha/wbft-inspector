package net

import (
	"context"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

func frame(seq uint64, dir, code, payload string, size int64, outcome string) *frames.Record {
	return &frames.Record{Input: "in-1", Type: "frame", Node: "0x01", Run: "r", Seq: seq, Dir: dir, Code: code,
		Payload: payload, Size: &size, Outcome: outcome}
}

// TestFrameCodes decides each rule once with a passing and once with a
// failing frame, and leaves frames without a known size or outside the
// decided rows without an instance.
func TestFrameCodes(t *testing.T) {
	const some = "aa00000000000000000000000000000000000000000000000000000000000000"
	big := int64(maxIstanbulMsgLen + 1)
	recs := []*frames.Record{
		frame(1, "out", "0x12", some, 10, ""),                // NET-011 pass
		frame(2, "out", "0x11", some, 10, ""),                // NET-011 fail
		frame(3, "in", "0x13", some, big, "DISCONNECT"),      // NET-013 pass
		frame(4, "in", "0x13", some, big, "PENDING"),         // NET-013 fail
		frame(5, "in", "0x02", some, 3, "DROP_SILENT"),       // NET-020 pass
		frame(6, "in", "0x10", some, 3, "PENDING"),           // NET-020 fail
		frame(7, "in", "0x14", emptySHA256, 0, "DISCONNECT"), // NET-021 pass
		frame(8, "in", "0x14", emptySHA256, 0, "PENDING"),    // NET-021 fail
		frame(9, "in", "0x07", some, 3, "DROP_SILENT"),       // NET-028 pass
		frame(10, "in", "0x07", some, 3, "DISCONNECT"),       // NET-028 fail
		frame(11, "in", "0x07", some, big, "DISCONNECT"),     // NET-013 pass only: a large 0x07 may disconnect
		frame(12, "in", "0x12", "", 0, "DISCONNECT"),         // no payload: size unknown, no instance
		frame(15, "in", "0x12", "", big, "DISCONNECT"),       // no payload but its size: NET-013 pass
		frame(13, "in", "0x12", some, 5, "PENDING"),          // 0x12 row needs the engine state: no instance
		{Input: "in-1", Type: "outcome", Node: "0x01", Run: "r", Seq: 14, Outcome: "ACCEPT"},
	}
	var got sink
	c := frameCodes{check.Base{ID: "net.frame_codes"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+i.Requirement+" "+string(i.Verdict))
		if len(i.Evidence) != 1 || i.Evidence[0].Kind != "frame" || i.Evidence[0].FrameID == "" || i.Source != "in-1" {
			t.Fatalf("instance %+v", i)
		}
	}
	want := []string{
		"frame:r:1 WBFT-NET-011 PASS", "frame:r:2 WBFT-NET-011 FAIL",
		"frame:r:3 WBFT-NET-013 PASS", "frame:r:4 WBFT-NET-013 FAIL",
		"frame:r:5 WBFT-NET-020 PASS", "frame:r:6 WBFT-NET-020 FAIL",
		"frame:r:7 WBFT-NET-021 PASS", "frame:r:8 WBFT-NET-021 FAIL",
		"frame:r:9 WBFT-NET-028 PASS", "frame:r:10 WBFT-NET-028 FAIL",
		"frame:r:11 WBFT-NET-013 PASS",
		"frame:r:15 WBFT-NET-013 PASS",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}
