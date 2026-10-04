package timer

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type sink []verdict.Instance

func (s *sink) Emit(i verdict.Instance) { *s = append(*s, i) }

func peerAddr(i int) string { return fmt.Sprintf("0x%040x", i) }

func keyOf(i int) string { return fmt.Sprintf("0x%064x", i) }

// rec builds a frame dump record: typ is "in", "out" or "sup".
func rec(seq uint64, typ string, peer, key int, cause string) *frames.Record {
	p := peerAddr(peer)
	r := &frames.Record{Input: "in-1", File: "f", Node: "0x01", Run: "r", Seq: seq, Peer: &p, DedupKey: keyOf(key), Cause: cause, Code: "0x15"}
	switch typ {
	case "sup":
		r.Type = "send_suppressed"
	default:
		r.Type, r.Dir = "frame", typ
	}
	return r
}

func runRetry(t *testing.T, recs []*frames.Record) []string {
	t.Helper()
	var got sink
	c := retryWire{check.Base{ID: "timer.retry_wire_suppressed"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, i := range got {
		s := i.Key + " " + string(i.Verdict)
		if i.Reason != "" {
			s += " " + string(i.Reason)
		}
		out = append(out, s)
	}
	return out
}

// TestRetryWire decides each kind of retransmission record.
func TestRetryWire(t *testing.T) {
	for _, tc := range []struct {
		name string
		recs []*frames.Record
		want []string
	}{
		{"suppressed retransmission", []*frames.Record{
			rec(1, "out", 1, 7, "broadcast"), rec(2, "sup", 1, 7, "retry"),
		}, []string{"frame:r:2 PASS"}},
		{"on the wire after a send to the peer", []*frames.Record{
			rec(1, "out", 1, 7, "broadcast"), rec(2, "out", 1, 7, "retry"),
		}, []string{"frame:r:2 FAIL"}},
		{"on the wire after a suppressed send", []*frames.Record{
			rec(1, "sup", 1, 7, "retry"), rec(2, "out", 1, 7, "retry"),
		}, []string{"frame:r:1 PASS", "frame:r:2 FAIL"}},
		{"records out of seq order in the file", []*frames.Record{
			rec(2, "out", 1, 7, "retry"), rec(1, "out", 1, 7, "broadcast"),
		}, []string{"frame:r:2 FAIL"}},
		{"no earlier copy for the peer", []*frames.Record{
			rec(1, "out", 2, 7, "broadcast"), rec(2, "out", 1, 7, "retry"),
		}, []string{"frame:r:2 CANNOT_DECIDE OBSERVER_SCOPE"}},
		{"only received from the peer", []*frames.Record{
			rec(1, "in", 1, 7, ""), rec(2, "out", 1, 7, "retry"),
		}, []string{"frame:r:2 CANNOT_DECIDE OBSERVER_SCOPE"}},
		{"new content", []*frames.Record{
			rec(1, "out", 1, 7, "broadcast"), rec(2, "out", 1, 8, "retry"),
		}, []string{"frame:r:2 CANNOT_DECIDE OBSERVER_SCOPE"}},
		{"not a retransmission", []*frames.Record{
			rec(1, "out", 1, 7, "broadcast"), rec(2, "out", 1, 7, "relay"),
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runRetry(t, tc.recs); strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// TestRetryWireEviction leaves a retransmission undecided when the cache
// could have evicted the key: INMEMORY_MESSAGES other keys of the peer, or
// INMEMORY_PEERS other peers, used since the last copy; one fewer fails.
func TestRetryWireEviction(t *testing.T) {
	build := func(otherKeys, otherPeers int) []*frames.Record {
		recs := []*frames.Record{rec(1, "out", 1, 7, "broadcast")}
		seq := uint64(2)
		for i := range otherKeys {
			recs = append(recs, rec(seq, "in", 1, 1000+i, ""))
			seq++
		}
		for i := range otherPeers {
			recs = append(recs, rec(seq, "out", 100+i, 7, "broadcast"))
			seq++
		}
		return append(recs, rec(seq, "out", 1, 7, "retry"))
	}
	for _, tc := range []struct {
		keys, peers int
		want        string
	}{
		{inmemoryMessages - 1, 0, "FAIL"},
		{inmemoryMessages, 0, "CANNOT_DECIDE"},
		{0, inmemoryPeers - 1, "FAIL"},
		{0, inmemoryPeers, "CANNOT_DECIDE"},
	} {
		got := runRetry(t, build(tc.keys, tc.peers))
		if len(got) != 1 || !strings.Contains(got[0], tc.want) {
			t.Errorf("%d keys, %d peers: %q, want %s", tc.keys, tc.peers, got, tc.want)
		}
	}
}
