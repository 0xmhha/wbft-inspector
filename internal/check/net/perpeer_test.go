package net

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
)

func runPerPeer(t *testing.T, recs []*frames.Record) []string {
	t.Helper()
	var got sink
	c := perPeerSkip{check.Base{ID: "net.per_peer_skip"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{{Input: "in-1", Records: recs}}}, &got); err != nil {
		t.Fatal(err)
	}
	var lines []string
	for _, i := range got {
		lines = append(lines, i.Key+" "+string(i.Verdict))
	}
	return lines
}

// TestPerPeerSkip passes a left-out send and fails a second sent frame of
// a key to a peer, a failed write included, and leaves first sends, keys
// last added by a receipt and other runs without an instance.
func TestPerPeerSkip(t *testing.T) {
	no := false
	var b recentRun
	b.add("frame", "out", "pa", "k1", nil)        // 1 first send: no instance
	b.add("send_suppressed", "", "pa", "k1", nil) // 2 PASS
	failed := b.add("frame", "out", "pa", "k1", nil)
	failed.WriteError = "error"            // 3 FAIL: a second send, whatever its result
	b.add("frame", "out", "pa", "k1", nil) // 4 FAIL: the failed write recorded the key too
	b.add("frame", "out", "pb", "k1", nil) // 5 another peer: first send
	b.add("frame", "in", "pc", "k2", &no)  // 6 receipt
	b.add("frame", "out", "pc", "k2", nil) // 7 WBFT-NET-023's: no instance
	b.add("frame", "out", "pc", "k2", nil) // 8 FAIL
	later := b.add("frame", "out", "pa", "k1", nil)
	later.Run = "r2" // 9 after a restart: no instance
	got := runPerPeer(t, b.recs)
	want := []string{"frame:r:2 PASS", "frame:r:3 FAIL", "frame:r:4 FAIL", "frame:r:8 FAIL"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("instances\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// TestPerPeerEviction is undecided once the earlier send may have been
// evicted.
func TestPerPeerEviction(t *testing.T) {
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
		b.add("frame", "out", "pa", "k", nil)
		for i := 0; i < tc.keys; i++ {
			b.add("frame", "out", "pa", fmt.Sprintf("o%d", i), nil)
		}
		for i := 0; i < tc.peers; i++ {
			b.add("frame", "out", fmt.Sprintf("q%d", i), "x", nil)
		}
		last := b.add("frame", "out", "pa", "k", nil)
		var got []string
		for _, l := range runPerPeer(t, b.recs) {
			if strings.HasPrefix(l, fmt.Sprintf("frame:r:%d ", last.Seq)) {
				got = append(got, l)
			}
		}
		if want := []string{fmt.Sprintf("frame:r:%d %s", last.Seq, tc.want)}; fmt.Sprint(got) != fmt.Sprint(want) {
			t.Errorf("%d keys, %d peers: %v, want %v", tc.keys, tc.peers, got, want)
		}
	}
}
