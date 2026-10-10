package net

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noDisconnectForIgnore{check.Base{ID: "net.no_disconnect_for_ignore", Reqs: []string{reqNoKick},
		Kinds: []check.Kind{check.Frames}}})
}

const reqNoKick = "WBFT-NET-044"

// noDisconnectForIgnore decides WBFT-NET-044 from frame dumps: a node does
// not disconnect a peer for a message that ended in IGNORE. It reads who
// closed each stream from the closed conn records (by, cause, of).
//
// For each received frame that ended in IGNORE (the class of its outcome,
// or of its outcomes when it waited, as for WBFT-NET-043):
//
//   - a close by the node whose of names the frame fails;
//   - a close by the node with cause other on that peer's stream after the
//     frame's final outcome and before the next outcome decided for a frame
//     of that peer leaves it undecided: why the node closed it is not known
//     (an outcome decided later than the frame, by the runner or the core,
//     comes after the peer's next frames, so the window starts at the
//     outcome);
//   - otherwise it passes. Closes by the peer, or that the dump does not
//     attribute (unknown, or an older dump without by), are not the node's
//     decision and are not counted, so an older dump passes every frame.
type noDisconnectForIgnore struct{ check.Base }

func (c noDisconnectForIgnore) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		for _, recs := range check.FrameRuns(d) {
			c.run(recs, out)
		}
	}
	return nil
}

func (c noDisconnectForIgnore) run(recs []*frames.Record, out check.Emitter) {
	later := map[uint64][]string{}
	cited := map[uint64]*frames.Record{} // received frame seq -> the node's close naming it
	byFrame := map[uint64]*frames.Record{}
	decided := map[uint64]int{} // received frame seq -> index of its last outcome record
	for i, r := range recs {
		switch {
		case r.Type == "frame" && r.Dir == "in":
			byFrame[r.Seq] = r
		case r.Type == "outcome" && r.Of != nil:
			later[*r.Of] = append(later[*r.Of], r.Outcome)
			decided[*r.Of] = i
		case closedBySelf(r) && r.Of != nil:
			cited[*r.Of] = r
		}
	}
	// decides reports the peer of a record that decides a received frame:
	// the frame itself when the receive path decided it, or an outcome.
	decides := func(l *frames.Record) *string {
		switch {
		case l.Type == "frame" && l.Dir == "in" && l.Outcome != "PENDING":
			return l.Peer
		case l.Type == "outcome" && l.Of != nil && byFrame[*l.Of] != nil:
			return byFrame[*l.Of].Peer
		}
		return nil
	}
	for i, r := range recs {
		if r.Type != "frame" || r.Dir != "in" || r.Peer == nil || finalClass(r, later[r.Seq]) != "IGNORE" {
			continue
		}
		if cl := cited[r.Seq]; cl != nil {
			emit(out, reqNoKick, r, false, fmt.Sprintf("received %s ended in IGNORE, and the node closed the stream for it (cause %s)", r.Code, cl.Cause))
			continue
		}
		from := i
		if j, ok := decided[r.Seq]; ok {
			from = j
		}
		var other *frames.Record
		for _, l := range recs[from+1:] {
			if p := decides(l); p != nil && *p == *r.Peer {
				break
			}
			if closedBySelf(l) && l.Peer != nil && *l.Peer == *r.Peer && l.Cause == "other" {
				other = l
				break
			}
		}
		if other != nil {
			out.Emit(check.FrameInstance(reqNoKick, r, verdict.CannotDecide, verdict.ObserverScope,
				fmt.Sprintf("received %s ended in IGNORE; the node then closed the peer's stream for another reason (%q)", r.Code, other.Reason)))
			continue
		}
		emit(out, reqNoKick, r, true, fmt.Sprintf("received %s ended in IGNORE; the node did not close the peer's stream for it", r.Code))
	}
}

func closedBySelf(r *frames.Record) bool {
	return r.Type == "conn" && r.Event == "closed" && r.By == "self"
}

// finalClass is the class a received frame ended in: its own outcome, or,
// when it waited (PENDING), ACCEPT if any of its outcomes is ACCEPT (a
// backlog message processed later) and otherwise its last outcome; "" when
// it waited and has none.
func finalClass(r *frames.Record, outs []string) string {
	if r.Outcome != "PENDING" {
		return r.Outcome
	}
	for _, o := range outs {
		if o == "ACCEPT" {
			return o
		}
	}
	if len(outs) == 0 {
		return ""
	}
	return outs[len(outs)-1]
}
