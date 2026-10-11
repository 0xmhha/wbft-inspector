package app

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

// Payloads: the wbft-spec PRE-PREPARE vector preprepare_round0 (block H at
// (2, 0)), the same PRE-PREPARE signed by key 0x11..11 (the node of the
// test, as proposer) and PREPAREs for H at (2, 0) and (2, 1) signed by that
// key (generated with wbft 4b241be).
const (
	ppH = "f902c7f902c1f9027b0280f90276f90271a0111111111111111111111111111111111111111111111111111111111111" +
		"1111a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794376ab524a47492d1c8222c67" +
		"c0cff8d5fec34112a02222222222222222222222222222222222222222222222222222222222222222a056e81f171bcc" +
		"55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b99" +
		"6cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000000000000000000000000000000001028406422c4080846553f102b874f872a0" +
		"0000000000000000000000000000000000000000000000000000000000000000b8416243139f0e6b881248e468a6566e" +
		"b5ed9c278bb1b54d8bd46ebe50055bcb92a5435af24253453da96c927a47f9d23f4c19eb2f5b53ead248e93d0182be94" +
		"c4480080c0c080c0c086191a20322000c0a0000000000000000000000000000000000000000000000000000000000000" +
		"00008800000000000000008612309ce54000c0c0b8413a5f2bea6f18e89d704efb5ac54790314b24bdd0ef1121de7ad5" +
		"ec7f68f1199f7da8d2981c15a295929cdd93792580dd29076e34f0e25b8f1b154654c57b13df01c2c0c0"
	ppOwnH = "f902c7f902c1f9027b0280f90276f90271a0111111111111111111111111111111111111111111111111111111111111" +
		"1111a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794376ab524a47492d1c8222c67" +
		"c0cff8d5fec34112a02222222222222222222222222222222222222222222222222222222222222222a056e81f171bcc" +
		"55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b99" +
		"6cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000000000000000000000000000000001028406422c4080846553f102b874f872a0" +
		"0000000000000000000000000000000000000000000000000000000000000000b8416243139f0e6b881248e468a6566e" +
		"b5ed9c278bb1b54d8bd46ebe50055bcb92a5435af24253453da96c927a47f9d23f4c19eb2f5b53ead248e93d0182be94" +
		"c4480080c0c080c0c086191a20322000c0a0000000000000000000000000000000000000000000000000000000000000" +
		"00008800000000000000008612309ce54000c0c0b84148086239f90af10228fb2a74c59844660b8e5e2e9ed80cefdc7a" +
		"ece51754a3e075748f948483b69f46d19812b802fc0eab6f0d1135179fb2ccd225e50a16eea701c2c0c0"
	prepH2r0 = "f869e50280a06284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e81aab841c53c16270d31" +
		"ccf832d2cb6429ff1d8f5addc401ec3c8dcfc132035c0590198f7386c55e9acab16e2e737df4c70377cb8c898b4fc3bd" +
		"63ce4140f5d819ad4efe00"
	prepH2r1 = "f869e50201a06284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e81aab841878acf7d719d" +
		"63d9a6f0781e87b16fa6604e01c706e2d82f7e3ef556ef86c30b081b787a353fc222a5a25a4236f05769bdcd3d30a5fd" +
		"cd8f52f76f35f7c2b5fb00"

	node  = "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	hashH = "0x6284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e"
)

// sink collects emitted instances.
type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

// TestNoPrepareOnInvalid reads runs of one node, each in its own hour:
//   - r1: H rejected at (2, 0), then the node's PREPARE for it: FAIL;
//   - r2: H rejected, then a PREPARE for H at round 1 only: PASS;
//   - r3: H rejected, a later copy accepted, then the PREPARE: PASS;
//   - r4: a rejection of H, but no PRE-PREPARE of it: INCONSISTENT_INPUT;
//   - r5: the same in a run that lost records: MISSING_DATA;
//   - r6: H rejected by row 13 without a rejection record: no instance;
//   - r7: the node's own proposal of H, rejected, sent to two peers and
//     no PREPARE: one PASS;
//   - r8: the same with the node's PREPARE recorded before it: FAIL.
//
// A rejection outside every run and one on the import path give none.
func TestNoPrepareOnInvalid(t *testing.T) {
	dir := t.TempDir()
	var recs []*frames.Record
	seq := map[string]uint64{}
	at := func(run string, s int) string {
		h := map[string]int{"r1": 1, "r2": 2, "r3": 3, "r4": 4, "r5": 5, "r6": 6, "r7": 7, "r8": 8}[run]
		return time.Date(2026, 10, 11, h, 0, s, 0, time.UTC).Format(time.RFC3339Nano)
	}
	add := func(r *frames.Record, run string) *frames.Record {
		seq[run]++
		r.Node, r.Run, r.File, r.Seq, r.TWall = node, run, "frames-"+run+".jsonl", seq[run], at(run, int(seq[run]))
		recs = append(recs, r)
		return r
	}
	frame := func(run, dir_, code, payload string) uint64 {
		b, err := hex.DecodeString(payload)
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		sum := hex.EncodeToString(s[:])
		p := filepath.Join(dir, "payloads", sum[:2])
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, sum), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return add(&frames.Record{Type: "frame", Dir: dir_, Code: code, Payload: sum, Outcome: "PENDING"}, run).Seq
	}
	outcome := func(run string, of uint64, row int64) {
		add(&frames.Record{Type: "outcome", Of: &of, Row: &row, Check: "PROCESS"}, run)
	}
	outcome("r1", frame("r1", "in", "0x12", ppH), 13)
	frame("r1", "out", "0x13", prepH2r0)              // r1:3 FAIL
	outcome("r2", frame("r2", "in", "0x12", ppH), 13) // r2:1 PASS
	frame("r2", "out", "0x13", prepH2r1)
	outcome("r3", frame("r3", "in", "0x12", ppH), 13) // r3:1 PASS
	outcome("r3", frame("r3", "in", "0x12", ppH), 15)
	frame("r3", "out", "0x13", prepH2r0)
	frame("r4", "out", "0x13", prepH2r1)
	add(&frames.Record{Type: "dropped"}, "r5")
	frame("r5", "out", "0x13", prepH2r1)
	outcome("r6", frame("r6", "in", "0x12", ppH), 13)
	frame("r7", "out", "0x12", ppOwnH) // r7:1 PASS
	frame("r7", "out", "0x12", ppOwnH)
	frame("r8", "out", "0x13", prepH2r0) // r8:1 FAIL
	frame("r8", "out", "0x12", ppOwnH)

	rej := func(line int, path, ts string) *rejections.Record {
		at, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			t.Fatal(err)
		}
		return &rejections.Record{Input: "in-2", Node: node, Line: line, Number: "2", Hash: hashH, Step: "P3", Class: "ErrInvalidProposal", Path: path, Time: ts, At: at}
	}
	set := &rejections.Set{Node: node, Records: []*rejections.Record{
		rej(1, "preprepare", at("r1", 1)), rej(2, "preprepare", at("r2", 1)), rej(3, "preprepare", at("r3", 1)),
		rej(4, "preprepare", at("r4", 1)), rej(5, "preprepare", at("r5", 1)),
		rej(6, "preprepare", "2026-01-01T00:00:00Z"), rej(7, "imported", at("r6", 1)),
		rej(8, "preprepare", at("r7", 1)), rej(9, "preprepare", at("r8", 2)),
	}}
	var got sink
	c := noPrepareOnInvalid{check.Base{ID: "app.no_prepare_on_invalid"}}
	in := &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Dir: dir, Records: recs}}, Rejections: []*rejections.Set{set}}
	if err := c.Run(context.Background(), in, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict)+" "+string(i.Reason))
	}
	want := []string{"frame:r1:3 FAIL ", "frame:r2:1 PASS ", "frame:r3:1 PASS ",
		"rejection:in-2:4 CANNOT_DECIDE INCONSISTENT_INPUT", "rejection:in-2:5 CANNOT_DECIDE MISSING_DATA",
		"frame:r7:1 PASS ", "frame:r8:1 FAIL "}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if ev := got[0].Evidence; len(ev) != 3 || ev[1].FrameID != "r1:1" || ev[2].Method != "wbft_rejections" || ev[2].Line != 1 {
		t.Fatalf("FAIL evidence %+v", ev)
	}
}
