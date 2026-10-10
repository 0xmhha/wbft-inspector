package net

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(peerCacheBeforeKnown{check.Base{ID: "net.peer_cache_before_known", Reqs: []string{"WBFT-NET-023"},
		Kinds: []check.Kind{check.Frames}}})
}

const reqPeerCache = "WBFT-NET-023"

// peerCacheBeforeKnown decides WBFT-NET-023 from frame dumps: a key
// received from a peer enters that peer's recent cache before the known
// cache is checked, so whether or not the message was a duplicate, the
// node does not send that key back to the peer, and a later copy from the
// peer finds it there.
//
// Only a received frame that carries dedup counts as an entry: the node
// checked it against the caches (a frame it did not queue, or received with
// the engine stopped, did not touch them). After such an entry for (peer,
// key), and with fewer than INMEMORY_MESSAGES other keys of the peer and
// fewer than INMEMORY_PEERS other peers used since (so neither could have
// been evicted; every frame and suppressed send is counted as a use, which
// errs towards undecided):
//
//   - a send to the peer left out (send_suppressed) passes;
//   - a frame with the key written to the peer fails, except the first one
//     after an entry whose peer_recent_hit was true with no earlier
//     addition in the dump: that send was decided before the receipt (the
//     hit shows the key was there) and recorded after it, once written;
//   - a later received frame from the peer with dedup passes when its
//     peer_recent_hit is true and fails otherwise.
//
// When the cache may have evicted the key the instance is undecided. A
// (peer, key) whose latest addition is a send rather than a checked
// receipt has no instance here: a send records the key too, but that is
// WBFT-NET-032.
type peerCacheBeforeKnown struct{ check.Base }

// use is one use of a peer's recent cache in a run.
type use struct {
	peer, key string
	entry     bool // a received frame the node checked against the caches
	adds      bool // the use adds the key: a checked receipt or a send
	// pending is set on an entry whose peer_recent_hit is true although
	// the dump shows no earlier addition of the key: a send decided before
	// the receipt but recorded after it (a sent frame is recorded once
	// written) explains the hit, so the next sent frame is not judged.
	pending bool
}

func (c peerCacheBeforeKnown) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
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
				i := lastUse(uses, peer, key)
				switch {
				case i >= 0 && uses[i].entry && uses[i].pending && sent:
					uses[i].pending = false // the send the hit came from
				case i >= 0 && uses[i].entry:
					judge(r, peer, checked, uses[i+1:], key, out)
				}
				u := use{peer: peer, key: key, entry: checked, adds: checked || sent}
				// A send still unrecorded keeps explaining the hits of
				// later receipts of the key.
				u.pending = checked && *r.Dedup.PeerRecentHit && (i < 0 || uses[i].entry && uses[i].pending)
				uses = append(uses, u)
			}
		}
	}
	return nil
}

// lastUse returns the last use that added key to peer's cache: a
// suppressed send only looks it up, and an unchecked receipt does not
// touch the cache.
func lastUse(uses []use, peer, key string) int {
	for i := len(uses) - 1; i >= 0; i-- {
		if u := uses[i]; u.adds && u.peer == peer && u.key == key {
			return i
		}
	}
	return -1
}

// judge decides record r for peer, whose last use of key was a checked
// receipt followed by since.
func judge(r *frames.Record, peer string, checked bool, since []use, key string, out check.Emitter) {
	var what string
	var ok bool
	switch {
	case r.Type == "send_suppressed":
		what, ok = "send to "+peer+" left out", true
	case r.Dir == "out":
		what, ok = "key sent back on the wire to "+peer, false
	case checked:
		what, ok = fmt.Sprintf("key received again from %s, peer_recent_hit %v", peer, *r.Dedup.PeerRecentHit), *r.Dedup.PeerRecentHit
	default:
		return // a receipt the node did not check
	}
	keys, peers := map[string]bool{}, map[string]bool{}
	for _, u := range since {
		if u.peer == peer && u.key != key {
			keys[u.key] = true
		}
		if u.peer != peer {
			peers[u.peer] = true
		}
	}
	if len(keys) >= check.InmemoryMessages || len(peers) >= check.InmemoryPeers {
		out.Emit(check.FrameInstance(reqPeerCache, r, verdict.CannotDecide, verdict.ObserverScope,
			fmt.Sprintf("%s after receiving the key from it; %d other keys of the peer and %d other peers were used since, so the cache may have evicted it", what, len(keys), len(peers))))
		return
	}
	emit(out, reqPeerCache, r, ok, what+" after receiving the key from it (the peer's recent cache holds it)")
}
