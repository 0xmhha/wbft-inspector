package sec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// Votes signed with wbft (codec.SigningPayload, ecdsa.SignData): A by the
// key 0x11..11 (address 0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a), B by the key 0x22..22, for view (5, r)
// with digest 0x0d00..00 and seal 0xaa0d.
const (
	prepA5r0d1 = "f86ae60580a0010000000000000000000000000000000000000000000000000000000000000082aa01b841b3dccbb9eebbb1000bf0c3e06be0fbe746ed37e524943499e4877e67ca30461f247eef3faa8ec59d88f13b7328f4886f5054cdefe0b5561a433f77914992cba001"
	prepA5r0d2 = "f86ae60580a0020000000000000000000000000000000000000000000000000000000000000082aa02b8411756f661888476d757705fa3c3d424ca8eec71ea137822240934fce11c5c01f805ed4fb2acd36df85872b3d341f7d3d970c00b3e1cbc6db91571c0220c6fd71d00"
	prepA5r1d1 = "f86ae60501a0010000000000000000000000000000000000000000000000000000000000000082aa01b841d1674b194f42bd0b2b342dbf25662c185d54dbf948275d6bcd513061a38529a27d35b01e6aa0d1505424ef4fa704b522c322b0567462d20b42133fe9f5637d2601"
	commA5r0d1 = "f86ae60580a0010000000000000000000000000000000000000000000000000000000000000082aa01b8415652fd281403f1bf37ecfa4d4b97ee5d67788f4426af79758e9635f8286e8e782b50746926f46cf42526161465454d727814aa1583c500afd66cf5661fcd117901"
	prepB5r0d1 = "f86ae60580a0010000000000000000000000000000000000000000000000000000000000000082aa01b841a92a1e900eee0e9f246c990e31ca8a9507782d8edf367fad3f7a5bb08ed1cfb47d1a20d70cefd5d9ca4d0a16d4d24269105a969d2b769f9d744575354b6f3c7c00"
	prepB5r0d2 = "f86ae60580a0020000000000000000000000000000000000000000000000000000000000000082aa02b8412a173fb0dc455c301039601b72fb39aba53b840ff13a25562227e30ee9cb1a130007f5c65093386bab0d325bd41feb25aab894d509a65386278397bf1c115ed001"
)

type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

// TestNoDoubleVote fails the second digest node A sent for one view and
// code in a run, passes its other votes and the same vote in a later run,
// and leaves out the relays of B's votes, received frames and frames
// without a payload.
func TestNoDoubleVote(t *testing.T) {
	dir := t.TempDir()
	node := "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"
	var recs []*frames.Record
	add := func(run, dir_, code, payload, cause string) {
		r := &frames.Record{Type: "frame", Node: node, Run: run, File: "frames-" + run + ".jsonl", Dir: dir_, Code: code, Cause: cause}
		if payload != "" {
			b, err := hex.DecodeString(payload)
			if err != nil {
				t.Fatal(err)
			}
			s := sha256.Sum256(b)
			r.Payload = hex.EncodeToString(s[:])
			p := filepath.Join(dir, "payloads", r.Payload[:2])
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, r.Payload), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		n := uint64(1)
		for _, x := range recs {
			if x.Run == run {
				n++
			}
		}
		r.Seq = n
		recs = append(recs, r)
	}
	add("r1", "out", "0x13", prepA5r0d1, "broadcast") // 1 the first digest
	add("r1", "out", "0x13", prepA5r0d1, "broadcast") // 2 the same vote to another peer
	add("r1", "out", "0x13", prepB5r0d1, "relay")     // 3 B's votes: not the node's
	add("r1", "out", "0x13", prepB5r0d2, "relay")     // 4
	add("r1", "out", "0x13", prepA5r0d2, "broadcast") // 5 FAIL: a second digest
	add("r1", "out", "0x14", commA5r0d1, "broadcast") // 6 PASS
	add("r1", "out", "0x13", prepA5r1d1, "broadcast") // 7 PASS: another round
	add("r1", "out", "0x13", "", "broadcast")         // 8 no payload: left out
	add("r1", "in", "0x13", prepA5r0d2, "")           // 9 received: left out
	add("r2", "out", "0x13", prepA5r0d2, "replay")    // 1 PASS: another run
	var got sink
	c := noDoubleVote{check.Base{ID: "sec.no_double_vote"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Dir: dir, Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict))
	}
	want := []string{"frame:r1:5 FAIL", "frame:r1:6 PASS", "frame:r1:7 PASS", "frame:r2:1 PASS"}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if ev := got[0].Evidence; len(ev) != 2 || ev[1].FrameID != "r1:1" {
		t.Fatalf("failure evidence %+v", ev)
	}
}
