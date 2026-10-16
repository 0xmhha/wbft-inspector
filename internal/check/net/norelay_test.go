package net

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
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

func TestNoRelayAcceptsValidatedOwnInputProvenance(t *testing.T) {
	d, err := frames.Load("../../../testdata/frames/own-input")
	if err != nil {
		t.Fatal(err)
	}
	if res := frames.Validate(d); len(res.Problems) != 0 {
		t.Fatal(res.Problems)
	}
	var sent *frames.Record
	for _, r := range d.Records {
		if r.Type == "frame" {
			sent = r
		}
	}
	if sent == nil || sent.OwnMessageOf == nil {
		t.Fatal("fixture lacks real own-input provenance")
	}
	dir := t.TempDir()
	original, err := os.ReadFile("../../../testdata/frames/own-input/frames-own-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	received := map[string]any{"v": 1, "type": "frame", "dir": "in", "outcome": "DROP_SILENT", "seq": 10, "node": sent.Node, "run": sent.Run, "t_wall": sent.TWall, "t_mono_ns": sent.TMono, "peer": *sent.Peer, "code": sent.Code, "wire_code": *sent.WireCode, "size": *sent.Size, "payload_sha256": sent.Payload, "dedup_key": sent.DedupKey}
	line, err := json.Marshal(received)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "frames-own-fixture.jsonl"), append(original, append(line, '\n')...), 0600); err != nil {
		t.Fatal(err)
	}
	payload, err := d.Payload(sent)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Join(dir, "payloads", sent.Payload[:2]), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "payloads", sent.Payload[:2], sent.Payload), payload, 0600); err != nil {
		t.Fatal(err)
	}
	d, err = frames.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if res := frames.Validate(d); len(res.Problems) != 0 {
		t.Fatal("augmented fixture invalid", res.Problems)
	}
	var got sink
	c := noRelayCases{check.Base{ID: "net.no_relay_cases"}}
	if err = c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{d}}, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || string(got[0].Verdict) != "PASS" {
		t.Fatal("own internal input was treated as an ignored peer relay", got)
	}
}
