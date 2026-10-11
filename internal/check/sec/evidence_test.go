package sec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// TestEquivocationReported reads node N's received votes of A and B (both
// signing two digests for (5, 0)) in three runs:
//   - r1, with events at sequence 5: B's pair with its EVIDENCE passes (and
//     the EVIDENCE passes), A's pair without one fails;
//   - r2, without an event run: A's pair is undecided (MISSING_DATA);
//   - r3, with events at sequence 9: A's pair is undecided (outside the
//     tracked sequences), and an EVIDENCE of B whose messages the dump
//     does not hold is undecided (INCONSISTENT_INPUT).
func TestEquivocationReported(t *testing.T) {
	dir := t.TempDir()
	node := "0x00000000000000000000000000000000000000cc"
	addrA, addrB := "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a", "0x1563915e194d8cfba1943570603f7606a3115508"
	d1, d2 := "0x01"+strings.Repeat("00", 31), "0x02"+strings.Repeat("00", 31)
	var recs []*frames.Record
	seq := map[string]uint64{}
	add := func(run, code, payload string, mono int64) {
		b, err := hex.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		r := &frames.Record{Type: "frame", Node: node, Run: run, File: "frames-" + run + ".jsonl", Dir: "in", Code: code, Payload: hex.EncodeToString(s[:]), TMono: mono}
		p := filepath.Join(dir, "payloads", r.Payload[:2])
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, r.Payload), b, 0o644); err != nil {
			t.Fatal(err)
		}
		seq[run]++
		r.Seq = seq[run]
		recs = append(recs, r)
	}
	add("r1", "0x13", prepB5r0d1, 20) // 1
	add("r1", "0x13", prepB5r0d2, 21) // 2 PASS: EVIDENCE of B
	add("r1", "0x13", prepA5r0d1, 22) // 3
	add("r1", "0x13", prepA5r0d2, 23) // 4 FAIL: no EVIDENCE of A
	add("r1", "0x14", commA5r0d1, 24) // 5 one digest: no instance
	add("r2", "0x13", prepA5r0d1, 20) // 1
	add("r2", "0x13", prepA5r0d2, 21) // 2 CANNOT_DECIDE: no event run
	add("r3", "0x13", prepA5r0d1, 20) // 1
	add("r3", "0x13", prepA5r0d2, 21) // 2 CANNOT_DECIDE: the node is at sequence 9

	ev := func(run string, line int, kind, seq, round string, mono int64, f map[string]any) *events.Event {
		raw := map[string]json.RawMessage{}
		for k, v := range f {
			b, _ := json.Marshal(v)
			raw[k] = b
		}
		return &events.Event{Input: "ev", Line: line, Node: node, Run: run, Kind: kind, View: &events.View{Seq: seq, Round: round}, TMono: mono, F: raw}
	}
	outcome := func(run string, src string) *events.Event {
		return ev(run, 2, "MSG_OUTCOME", "5", "0", 15, map[string]any{"source": src, "check": "PROCESS"})
	}
	evidence := map[string]any{"code": 19, "source": addrB, "digest_a": d1, "digest_b": d2}
	r1 := &events.Run{Node: node, ID: "r1", Events: []*events.Event{
		ev("r1", 1, "ROUND_ENTER", "5", "0", 10, nil), outcome("r1", addrA), outcome("r1", addrB),
		ev("r1", 4, "EVIDENCE", "5", "0", 30, evidence)}}
	r3 := &events.Run{Node: node, ID: "r3", Events: []*events.Event{
		ev("r3", 1, "ROUND_ENTER", "9", "0", 10, nil), outcome("r3", addrA),
		ev("r3", 3, "EVIDENCE", "5", "0", 30, evidence)}}
	var got sink
	c := equivocationReported{check.Base{ID: "sec.equivocation_reported"}}
	in := &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Dir: dir, Records: recs}}, Events: &events.Set{Runs: []*events.Run{r1, r3}}}
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict)+" "+string(i.Reason))
	}
	want := []string{"frame:r1:2 PASS ", "frame:r1:4 FAIL ", lines0(got, 2, verdict.Pass),
		"frame:r2:2 CANNOT_DECIDE MISSING_DATA", "frame:r3:2 CANNOT_DECIDE OBSERVER_SCOPE", lines0(got, 5, verdict.CannotDecide)}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if got[2].Evidence[0].Line != 4 || got[5].Reason != verdict.InconsistentInput {
		t.Fatalf("EVIDENCE instances %+v %+v", got[2], got[5])
	}
}

// lines0 formats instance i of got when it is an event instance with v.
func lines0(got sink, i int, v verdict.Verdict) string {
	if i >= len(got) || got[i].Verdict != v || strings.HasPrefix(got[i].Key, "frame:") {
		return "an event instance with " + string(v)
	}
	return got[i].Key + " " + string(got[i].Verdict) + " " + string(got[i].Reason)
}
