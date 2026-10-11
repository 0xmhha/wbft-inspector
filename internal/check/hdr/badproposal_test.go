package hdr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// TestBadBlockProposal reads runs of one node, each in its own hour. The
// node recorded the blocks of ppOk and ownDiff as bad at second 1 of
// every hour (one IMPORT_FAIL each, in run r0):
//   - r1: ppOk received after the record and rejected at P2: PASS;
//   - r2: the same rejected at H12, after P2: FAIL;
//   - r3: the same rejected at P1, the type check: PASS;
//   - r4: the same accepted (row 15): FAIL;
//   - r5: the same without a rejection record: OBSERVER_SCOPE;
//   - r6: the node's own ownDiff proposal and its PREPARE for it: FAIL;
//   - r7: ppGas, a block not recorded as bad: no instance (ppDiff carries
//     the block of ownDiff, so it would count).
//
// The records are stamped at the start of every hour, so each run's frames
// come after them. A copy received before the record is left out; without
// the bad-block records no run has an instance.
func TestBadBlockProposal(t *testing.T) {
	p := payloads(t)
	dir := t.TempDir()
	var recs []*frames.Record
	seq := map[string]uint64{}
	hour := func(run string) int {
		n := 0
		for _, c := range run[1:] {
			n = n*10 + int(c-'0')
		}
		return n
	}
	at := func(run string, s int) string {
		return time.Date(2026, 10, 12, hour(run), 0, s, 0, time.UTC).Format(time.RFC3339Nano)
	}
	add := func(r *frames.Record, run string, s int) uint64 {
		seq[run]++
		r.Node, r.Run, r.File, r.Seq, r.TWall = node, run, "frames-"+run+".jsonl", seq[run], at(run, s)
		recs = append(recs, r)
		return r.Seq
	}
	frame := func(run, d, code, name string, s int) uint64 {
		b, err := hex.DecodeString(p[name][1])
		if err != nil {
			t.Fatal(name, err)
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		dp := filepath.Join(dir, "payloads", h[:2])
		if err := os.MkdirAll(dp, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dp, h), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return add(&frames.Record{Type: "frame", Dir: d, Code: code, Payload: h, Outcome: "PENDING"}, run, s)
	}
	outcome := func(run string, of uint64, row int64, s int) {
		add(&frames.Record{Type: "outcome", Of: &of, Row: &row, Check: "PROCESS"}, run, s)
	}
	// The bad-block records come at second 1 of hour 0, before every run.
	var evs []*events.Event
	for i, name := range []string{"ppOk", "ownDiff"} {
		f := map[string]json.RawMessage{}
		for k, v := range map[string]any{"number": "2", "hash": p[name][0], "path": "imported", "recorded_bad": true} {
			raw, _ := json.Marshal(v)
			f[k] = raw
		}
		evs = append(evs, &events.Event{Input: "in-3", Line: i + 1, Node: node, Run: "r0", Seq: uint64(i + 1), TWall: at("r0", 1), Kind: "IMPORT_FAIL", F: f})
	}
	// r0 holds a copy received before the records: left out.
	outcome("r0", frame("r0", "in", "0x12", "ppOk", 0), 15, 0)
	for _, run := range []string{"r1", "r2", "r3", "r4", "r5"} {
		row := int64(13)
		if run == "r4" {
			row = 15
		}
		outcome(run, frame(run, "in", "0x12", "ppOk", 2), row, 2)
	}
	frame("r6", "out", "0x12", "ownDiff", 2)
	frame("r6", "out", "0x13", "ownDiffPrep", 3)
	outcome("r7", frame("r7", "in", "0x12", "ppGas", 2), 13, 2)

	line := 0
	rej := func(run, name, step string) *rejections.Record {
		line++
		ts := at(run, 2)
		t0, _ := time.Parse(time.RFC3339Nano, ts)
		return &rejections.Record{Input: "in-2", Node: node, Line: line, Number: "2", Hash: p[name][0], Step: step, Path: "preprepare", Time: ts, At: t0}
	}
	set := &rejections.Set{Node: node, Records: []*rejections.Record{
		rej("r1", "ppOk", "P2"), rej("r2", "ppOk", "H12"), rej("r3", "ppOk", "P1"), rej("r7", "ppGas", "H13"),
	}}
	c := badBlockProposal{check.Base{ID: "hdr.bad_block_proposal_reject"}}
	in := &check.Inputs{Events: &events.Set{Runs: []*events.Run{{Node: node, ID: "r0", Input: "in-3", Events: evs}}},
		Frames: []*frames.Dump{{Input: "in-1", Dir: dir, Records: recs}}, Rejections: []*rejections.Set{set}}
	var got sink
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict)+" "+string(i.Reason))
	}
	want := []string{"frame:r1:1 PASS ", "frame:r2:1 FAIL ", "frame:r3:1 PASS ", "frame:r4:1 FAIL ",
		"frame:r5:1 CANNOT_DECIDE OBSERVER_SCOPE", "frame:r6:1 FAIL "}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if ev := got[5].Evidence; len(ev) != 3 || ev[1].FrameID != "r6:2" || ev[2].Line != 2 {
		t.Fatalf("own proposal evidence %+v", ev)
	}
	if !strings.Contains(got[1].Message, "after the bad-block check") {
		t.Fatalf("r2: %s", got[1].Message)
	}

	// Without the node's rejections the unmatched proposals lack data.
	got = nil
	in.Rejections = nil
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Reason != verdict.MissingData || got[3].Verdict != verdict.Fail {
		t.Fatalf("without rejections %+v", got)
	}
	// Without bad-block records there is nothing to decide.
	got = nil
	in.Events = &events.Set{}
	if err := c.Run(context.Background(), in, &got); err != nil || len(got) != 0 {
		t.Fatalf("without bad blocks: %d instances, %v", len(got), err)
	}
}
