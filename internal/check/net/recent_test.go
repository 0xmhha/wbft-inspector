package net

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
)

// recentRun builds the records of one run in seq order.
type recentRun struct{ recs []*frames.Record }

func (b *recentRun) add(typ, dir, peer, key string, hit *bool) *frames.Record {
	p := peer
	r := &frames.Record{Input: "in-1", File: "f", Type: typ, Node: "0x01", Run: "r", Seq: uint64(len(b.recs) + 1), Dir: dir, Peer: &p, DedupKey: key}
	if hit != nil {
		no := false
		r.Dedup = &frames.Dedup{KnownHit: &no, PeerRecentHit: hit}
	}
	b.recs = append(b.recs, r)
	return r
}

func runPeerCache(t *testing.T, recs []*frames.Record) []string {
	t.Helper()
	var got sink
	c := peerCacheBeforeKnown{check.Base{ID: "net.peer_cache_before_known"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict))
	}
	return lines
}

// TestPeerCacheBeforeKnown decides the uses of a peer's cache after a
// checked receipt and leaves the others without an instance.
func TestPeerCacheBeforeKnown(t *testing.T) {
	yes, no := true, false
	var b recentRun
	b.add("frame", "in", "pa", "k1", &no)         // 1 entry
	b.add("send_suppressed", "", "pa", "k1", nil) // 2 PASS
	b.add("frame", "in", "pa", "k1", &yes)        // 3 PASS: found in the cache
	b.add("frame", "out", "pa", "k1", nil)        // 4 FAIL: sent back
	b.add("frame", "in", "pb", "k2", &no)         // 5 entry
	b.add("frame", "in", "pb", "k2", &no)         // 6 FAIL: not found
	b.add("frame", "in", "pc", "k3", nil)         // 7 not checked: no entry
	b.add("frame", "out", "pc", "k3", nil)        // 8 no instance
	b.add("frame", "out", "pd", "k4", nil)        // 9 a send, not a receipt
	b.add("frame", "out", "pd", "k4", nil)        // 10 no instance
	b.add("frame", "in", "pb", "k2", nil)         // 11 receipt not checked: no instance
	b.add("frame", "in", "pe", "k5", &yes)        // 12 entry with a hit the dump does not explain
	b.add("frame", "out", "pe", "k5", nil)        // 13 the send behind the hit, written later: no instance
	b.add("frame", "out", "pe", "k5", nil)        // 14 after a send: WBFT-NET-032, no instance
	b.add("frame", "in", "pf", "k6", &yes)        // 15 entry with an unexplained hit
	b.add("frame", "in", "pf", "k6", &yes)        // 16 PASS: received again, found in the cache
	b.add("frame", "out", "pf", "k6", nil)        // 17 the send behind the first hit: no instance
	got := runPeerCache(t, b.recs)
	want := []string{"frame:r:2 PASS", "frame:r:3 PASS", "frame:r:4 FAIL", "frame:r:6 FAIL", "frame:r:16 PASS"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPeerCacheEviction is undecided once enough other keys of the peer or
// other peers were used to evict the key.
func TestPeerCacheEviction(t *testing.T) {
	no := false
	for _, tc := range []struct {
		keys, peers int
		want        string
	}{
		{check.InmemoryMessages - 1, 0, "FAIL"},
		{check.InmemoryMessages, 0, "CANNOT_DECIDE"},
		{0, check.InmemoryPeers - 1, "FAIL"},
		{0, check.InmemoryPeers, "CANNOT_DECIDE"},
	} {
		var b recentRun
		b.add("frame", "in", "pa", "k", &no)
		for i := 0; i < tc.keys; i++ {
			b.add("frame", "out", "pa", fmt.Sprintf("o%d", i), nil)
		}
		for i := 0; i < tc.peers; i++ {
			b.add("frame", "out", fmt.Sprintf("q%d", i), "x", nil)
		}
		last := b.add("frame", "out", "pa", "k", nil)
		got := runPeerCache(t, b.recs)
		if want := []string{fmt.Sprintf("frame:r:%d %s", last.Seq, tc.want)}; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%d keys, %d peers: %v, want %v", tc.keys, tc.peers, got, want)
		}
	}
}
