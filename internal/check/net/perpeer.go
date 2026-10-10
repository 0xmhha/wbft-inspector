package net

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(perPeerSkip{check.Base{ID: "net.per_peer_skip", Reqs: []string{"WBFT-NET-032"},
		Kinds: []check.Kind{check.Frames}}})
}

const reqPerPeerSkip = "WBFT-NET-032"

// perPeerSkip decides WBFT-NET-032 from frame dumps: a node does not send
// the same key to the same peer twice, retransmissions included. A send
// records the key in the peer's recent cache whatever its result, so a
// sent frame counts with or without write_error.
//
// After a sent frame of a key to a peer, while fewer than
// INMEMORY_MESSAGES other keys of the peer and INMEMORY_PEERS other peers
// have been used since (see peerCacheBeforeKnown):
//
//   - a send to the peer left out (send_suppressed) passes;
//   - another sent frame of the key to the peer fails.
//
// When the cache may have evicted the key the instance is undecided. A send
// after a restart is in another run and is not compared. A (peer, key)
// whose last addition is a received frame is WBFT-NET-023's.
type perPeerSkip struct{ check.Base }

func (c perPeerSkip) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		for _, recs := range check.FrameRuns(d) {
			var uses []use
			for _, r := range recs {
				if r.Peer == nil || r.DedupKey == "" || (r.Type != "frame" && r.Type != "send_suppressed") {
					continue
				}
				peer, key := *r.Peer, r.DedupKey
				checked := r.Type == "frame" && r.Dir == "in" && r.Dedup != nil && r.Dedup.PeerRecentHit != nil
				sent := r.Type == "frame" && r.Dir == "out"
				if i := lastUse(uses, peer, key); i >= 0 && !uses[i].entry && (sent || r.Type == "send_suppressed") {
					what, ok := "send to "+peer+" left out", true
					if sent {
						what, ok = "key sent again to "+peer, false
					}
					if keys, peers, gone := evictable(uses[i+1:], peer, key); gone {
						out.Emit(check.FrameInstance(reqPerPeerSkip, r, verdict.CannotDecide, verdict.ObserverScope,
							fmt.Sprintf("%s; %d other keys of the peer and %d other peers were used since the earlier send, so the cache may have evicted it", what, keys, peers)))
					} else {
						emit(out, reqPerPeerSkip, r, ok, what+" after an earlier send of the key to it in the same run")
					}
				}
				uses = append(uses, use{peer: peer, key: key, entry: checked, adds: checked || sent})
			}
		}
	}
	return nil
}
