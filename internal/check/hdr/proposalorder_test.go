package hdr

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// node is the address of key 0x11..11, which signed the own* payloads.
const node = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"

type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

// payloads reads testdata/payloads.txt: name -> (block hash, payload).
func payloads(t *testing.T) map[string][2]string {
	t.Helper()
	b, err := os.ReadFile("testdata/payloads.txt")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][2]string{}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) == 3 && !strings.HasPrefix(l, "#") {
			out[f[0]] = [2]string{"0x" + f[1], f[2]}
		}
	}
	return out
}

// TestProposalOrder reads runs of one node, each in its own hour:
//   - r1: a Difficulty-2 proposal rejected at H4: PASS;
//   - r2: the same rejected at H16, after H4: FAIL;
//   - r3: the same rejected at P4, before H4: PASS;
//   - r4: the same accepted (row 15): FAIL;
//   - r5: the same rejected without a rejection record: OBSERVER_SCOPE;
//   - r6: a valid proposal rejected: no instance;
//   - r7: the node's own Difficulty-2 proposal, sent to two peers, and its
//     PREPARE for it: FAIL;
//   - r8: a proposal with GasUsed above GasLimit whose rejection names no
//     step: MISSING_DATA;
//   - r9: a Difficulty-2 proposal in a run that lost records: MISSING_DATA;
//   - r10: a relay of another validator's proposal: no instance.
func TestProposalOrder(t *testing.T) {
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
		return time.Date(2026, 10, 11, hour(run), 0, s, 0, time.UTC).Format(time.RFC3339Nano)
	}
	add := func(r *frames.Record, run string) uint64 {
		seq[run]++
		r.Node, r.Run, r.File, r.Seq, r.TWall = node, run, "frames-"+run+".jsonl", seq[run], at(run, int(seq[run]))
		recs = append(recs, r)
		return r.Seq
	}
	frame := func(run, d, code, name string) uint64 {
		b, err := hex.DecodeString(p[name][1])
		if err != nil {
			t.Fatal(name, err)
		}
		s := sha256.Sum256(b)
		sum := hex.EncodeToString(s[:])
		dp := filepath.Join(dir, "payloads", sum[:2])
		if err := os.MkdirAll(dp, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dp, sum), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return add(&frames.Record{Type: "frame", Dir: d, Code: code, Payload: sum, Outcome: "PENDING"}, run)
	}
	outcome := func(run string, of uint64, row int64) {
		add(&frames.Record{Type: "outcome", Of: &of, Row: &row, Check: "PROCESS"}, run)
	}
	for _, run := range []string{"r1", "r2", "r3"} {
		outcome(run, frame(run, "in", "0x12", "ppDiff"), 13)
	}
	outcome("r4", frame("r4", "in", "0x12", "ppDiff"), 15)
	outcome("r5", frame("r5", "in", "0x12", "ppDiff"), 13)
	outcome("r6", frame("r6", "in", "0x12", "ppOk"), 13)
	frame("r7", "out", "0x12", "ownDiff")
	frame("r7", "out", "0x12", "ownDiff")
	frame("r7", "out", "0x13", "ownDiffPrep")
	outcome("r8", frame("r8", "in", "0x12", "ppGas"), 13)
	add(&frames.Record{Type: "dropped"}, "r9")
	outcome("r9", frame("r9", "in", "0x12", "ppDiff"), 13)
	frame("r10", "out", "0x12", "ppDiff")

	line := 0
	rej := func(run, name, step string) *rejections.Record {
		line++
		ts := at(run, 1)
		t0, _ := time.Parse(time.RFC3339Nano, ts)
		return &rejections.Record{Input: "in-2", Node: node, Line: line, Number: "2", Hash: p[name][0], Step: step, Path: "preprepare", Time: ts, At: t0}
	}
	set := &rejections.Set{Node: node, Records: []*rejections.Record{
		rej("r1", "ppDiff", "H4"), rej("r2", "ppDiff", "H16"), rej("r3", "ppDiff", "P4"), rej("r6", "ppOk", "H12"),
		rej("r8", "ppGas", ""),
	}}
	var got sink
	c := proposalOrder{check.Base{ID: "hdr.proposal_verify_order"}}
	in := &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Dir: dir, Records: recs}}, Rejections: []*rejections.Set{set}}
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict)+" "+string(i.Reason))
	}
	want := []string{"frame:r1:1 PASS ", "frame:r2:1 FAIL ", "frame:r3:1 PASS ", "frame:r4:1 FAIL ",
		"frame:r5:1 CANNOT_DECIDE OBSERVER_SCOPE", "frame:r7:1 FAIL ", "frame:r8:1 CANNOT_DECIDE MISSING_DATA",
		"frame:r9:2 CANNOT_DECIDE MISSING_DATA"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if !strings.Contains(got[0].Message, "fails H4") || got[0].Evidence[1].Method != "wbft_rejections" || got[5].Evidence[1].FrameID != "r7:3" {
		t.Fatalf("instances %+v", got)
	}

	// Without the node's rejections the unmatched proposal lacks its data.
	got = nil
	in.Rejections = nil
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Reason != verdict.MissingData || got[3].Verdict != verdict.Fail {
		t.Fatalf("without rejections %+v", got)
	}
}
