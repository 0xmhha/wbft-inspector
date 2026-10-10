package timer

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(retryWire{check.Base{ID: "timer.retry_wire_suppressed", Reqs: []string{"WBFT-TIMER-024"},
		Kinds: []check.Kind{check.Frames}}})
}

// Sizes of the per-peer recent cache.
const (
	inmemoryPeers    = check.InmemoryPeers
	inmemoryMessages = check.InmemoryMessages
)

// retryWire decides WBFT-TIMER-024 from frame dumps: a ROUND-CHANGE the
// retry timer retransmits goes on the wire only towards peers whose recent
// cache does not hold its key.
//
//   - A retransmission the node left out for a peer (send_suppressed with
//     cause retry) passes.
//   - A retransmission put on the wire (frame out, cause retry) to a peer
//     fails when the run shows the key in that peer's cache: an earlier
//     frame sent to the peer, or a suppressed send to it, with the same
//     dedup key (a send records the key whatever its result, A-07
//     WBFT-NET-032; a received frame is not counted, since it adds the key
//     only while the engine runs), and fewer than INMEMORY_MESSAGES other
//     keys of the peer and fewer than INMEMORY_PEERS other peers used since,
//     counting received frames too, so that neither could have been
//     evicted. Otherwise it is undecided: the dump may start after the
//     earlier copy, or the cache may have evicted it.
type retryWire struct{ check.Base }

const reqRetryWire = "WBFT-TIMER-024"

// touch is a use of a peer's recent cache: a key received from it, sent
// to it, or looked up for it.
type touch struct {
	peer string
	key  string
	sent bool // a send or a suppressed send: the key is certainly in the cache
}

func (c retryWire) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		for _, recs := range check.FrameRuns(d) {
			c.run(recs, out)
		}
	}
	return nil
}

func (c retryWire) run(recs []*frames.Record, out check.Emitter) {
	var touches []touch
	for _, r := range recs {
		if r.Peer == nil || r.DedupKey == "" {
			continue
		}
		peer, key := *r.Peer, r.DedupKey
		switch {
		case r.Type == "send_suppressed" && r.Cause == "retry":
			out.Emit(check.FrameInstance(reqRetryWire, r, verdict.Pass, "", "retransmission left off the wire for "+peer+": its recent cache holds the key"))
		case r.Type == "frame" && r.Dir == "out" && r.Cause == "retry":
			out.Emit(retryOnWire(r, peer, key, touches))
		}
		if r.Type == "frame" || r.Type == "send_suppressed" {
			touches = append(touches, touch{peer, key, r.Type == "send_suppressed" || r.Dir == "out"})
		}
	}
}

// retryOnWire judges a retransmission written to peer against the earlier
// uses of the peer's cache.
func retryOnWire(r *frames.Record, peer, key string, touches []touch) verdict.Instance {
	last := -1
	for i := len(touches) - 1; i >= 0; i-- {
		if t := touches[i]; t.sent && t.peer == peer && t.key == key {
			last = i
			break
		}
	}
	if last < 0 {
		return check.FrameInstance(reqRetryWire, r, verdict.CannotDecide, verdict.ObserverScope,
			"retransmission on the wire to "+peer+"; the dump shows no earlier copy for that peer (it may start after it)")
	}
	keys, peers := map[string]bool{}, map[string]bool{}
	for _, t := range touches[last+1:] {
		if t.peer == peer && t.key != key {
			keys[t.key] = true
		}
		if t.peer != peer {
			peers[t.peer] = true
		}
	}
	if len(keys) >= inmemoryMessages || len(peers) >= inmemoryPeers {
		return check.FrameInstance(reqRetryWire, r, verdict.CannotDecide, verdict.ObserverScope,
			fmt.Sprintf("retransmission on the wire to %s; %d other keys of the peer and %d other peers were used since the last copy, so the cache may have evicted it", peer, len(keys), len(peers)))
	}
	return check.FrameInstance(reqRetryWire, r, verdict.Fail, "",
		fmt.Sprintf("retransmission put on the wire to %s although its recent cache holds the key (last used %d records earlier, %d other keys of the peer since)", peer, len(touches)-last, len(keys)))
}
