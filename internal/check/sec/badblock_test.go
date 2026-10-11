package sec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// The digests of the prepA5r0d1 and prepA5r0d2 votes (height 5).
const (
	digest1 = "0x0100000000000000000000000000000000000000000000000000000000000000"
	digest2 = "0x0200000000000000000000000000000000000000000000000000000000000000"
	digest3 = "0x0300000000000000000000000000000000000000000000000000000000000000"
)

// badBlockInputs builds node A's events and frame dump: IMPORT_FAIL
// records (number, hash, second) and sent frames (code, payload, second),
// each second after a fixed start.
type badBlockInputs struct {
	t      *testing.T
	dir    string
	node   string
	evs    []*events.Event
	frames []*frames.Record
}

func newBadBlockInputs(t *testing.T) *badBlockInputs {
	return &badBlockInputs{t: t, dir: t.TempDir(), node: "0x19e7e376e7c213b7e7e7e46cc70a5dd086daff2a"}
}

func at(s int) string {
	return time.Date(2026, 10, 12, 1, 0, s, 0, time.UTC).Format(time.RFC3339Nano)
}

func (b *badBlockInputs) importFail(number, hash string, s int, recordedBad bool) {
	f := map[string]json.RawMessage{}
	for k, v := range map[string]any{"number": number, "hash": hash, "path": "imported", "recorded_bad": recordedBad} {
		raw, _ := json.Marshal(v)
		f[k] = raw
	}
	b.evs = append(b.evs, &events.Event{Input: "in-1", Line: len(b.evs) + 1, Node: b.node, Run: "r1", Seq: uint64(len(b.evs) + 1),
		TWall: at(s), Kind: "IMPORT_FAIL", F: f})
}

func (b *badBlockInputs) frame(typ, code, payload string, s int) {
	r := &frames.Record{Type: typ, Node: b.node, Run: "r1", File: "frames-r1.jsonl", Dir: "out", Code: code, TWall: at(s),
		Seq: uint64(len(b.frames) + 1), Input: "in-2"}
	if payload != "" {
		raw, err := hex.DecodeString(payload)
		if err != nil {
			b.t.Fatal(err)
		}
		sum := sha256.Sum256(raw)
		r.Payload = hex.EncodeToString(sum[:])
		p := filepath.Join(b.dir, "payloads", r.Payload[:2])
		if err := os.MkdirAll(p, 0o755); err != nil {
			b.t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p, r.Payload), raw, 0o644); err != nil {
			b.t.Fatal(err)
		}
	}
	b.frames = append(b.frames, r)
}

func (b *badBlockInputs) run() []verdict.Instance {
	var got sink
	c := noReprepareBadBlock{check.Base{ID: "sec.no_reprepare_bad_block"}}
	in := &check.Inputs{Events: &events.Set{Runs: []*events.Run{{Node: b.node, ID: "r1", Input: "in-1", Events: b.evs}}},
		Frames: []*frames.Dump{{Input: "in-2", Dir: b.dir, Records: b.frames}}}
	if err := c.Run(context.Background(), in, &got); err != nil {
		b.t.Fatal(err)
	}
	return got
}

func lines(got []verdict.Instance) string {
	var l []string
	for _, i := range got {
		l = append(l, fmt.Sprintf("%s %s %s", i.Key, i.Verdict, i.Reason))
	}
	return strings.Join(l, "\n")
}

// TestNoReprepareBadBlock: a vote for a bad block after the record fails,
// a vote before it does not count, and a bad block without votes passes.
// A record that is not bad, a vote at another height and a relay are left
// out; a second record of the same hash is not another instance.
func TestNoReprepareBadBlock(t *testing.T) {
	b := newBadBlockInputs(t)
	b.importFail("5", digest1, 1, true)      // event:r1:1 FAIL: PREPARE and COMMIT after it
	b.importFail("5", digest1, 2, true)      // the same hash again
	b.importFail("5", digest2, 10, true)     // event:r1:3 PASS: its vote came before
	b.importFail("5", digest3, 11, true)     // event:r1:4 PASS: no vote
	b.importFail("6", digest1, 12, false)    // not recorded as bad
	b.frame("frame", "0x13", prepA5r0d2, 3)  // a vote for digest2 before its record
	b.frame("frame", "0x14", commA5r0d1, 4)  // COMMIT for digest1 after its record
	b.frame("frame", "0x13", prepA5r0d1, 5)  // PREPARE for digest1 after its record
	b.frame("frame", "0x13", prepB5r0d1, 6)  // a relay of B's vote
	b.frame("frame", "0x13", prepA5r1d1, 20) // round 1, the same height and digest1: FAIL too
	got := b.run()
	want := "event:r1:1 FAIL \nevent:r1:3 PASS \nevent:r1:4 PASS "
	if lines(got) != want {
		t.Fatalf("instances\n%s\nwant\n%s", lines(got), want)
	}
	if ev := got[0].Evidence; len(ev) != 2 || ev[1].FrameID != "r1:2" || !strings.Contains(got[0].Message, "COMMIT") {
		t.Fatalf("failure: %s, evidence %+v", got[0].Message, ev)
	}
}

// TestNoReprepareBadBlockUndecided: without frames after the record, or
// with a dump that lost records, the bad block is undecided; a vote after
// ten higher bad blocks were recorded may follow a dropped record.
func TestNoReprepareBadBlockUndecided(t *testing.T) {
	b := newBadBlockInputs(t)
	b.frame("frame", "0x13", prepA5r1d1, 1)
	b.importFail("5", digest1, 2, true)
	if got := lines(b.run()); got != "event:r1:1 CANNOT_DECIDE MISSING_DATA" {
		t.Fatalf("no frame after the record: %s", got)
	}
	b.frame("dropped", "", "", 3)
	if got := lines(b.run()); got != "event:r1:1 CANNOT_DECIDE MISSING_DATA" {
		t.Fatalf("a dump that lost records: %s", got)
	}

	b = newBadBlockInputs(t)
	b.importFail("5", digest1, 1, true)
	for i := 0; i < badRetention; i++ {
		b.importFail(fmt.Sprint(10+i), fmt.Sprintf("0x%064x", 100+i), 2+i, true)
	}
	b.frame("frame", "0x13", prepA5r0d1, 30)
	got := b.run()
	if got[0].Key != "event:r1:1" || got[0].Verdict != verdict.CannotDecide || got[0].Reason != verdict.ObserverScope {
		t.Fatalf("after %d higher bad blocks: %s", badRetention, lines(got))
	}
	// With one higher bad block fewer the protection still holds.
	b.evs = b.evs[:len(b.evs)-1]
	if got := b.run(); got[0].Verdict != verdict.Fail {
		t.Fatalf("after %d higher bad blocks: %s", badRetention-1, lines(got))
	}
}
