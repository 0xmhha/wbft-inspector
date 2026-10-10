package net

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noRelayCases{check.Base{ID: "net.no_relay_cases", Reqs: []string{"WBFT-NET-043"},
		Kinds: []check.Kind{check.Frames}}})
}

const reqNoRelay = "WBFT-NET-043"

// noRelayCases decides WBFT-NET-043 from frame dumps: a received message
// that ends in DROP_SILENT or IGNORE is not relayed.
//
// A received frame ends in the class of its own outcome, or, when it waited
// (PENDING), in ACCEPT if any outcome recorded for it is ACCEPT (a backlog
// message processed later, WBFT-NET-041) and otherwise in the class of its
// last outcome; a pending frame without outcomes has no instance.
//
// The relays of a run are matched by key, not by relay_of, which names the
// last received copy and so cannot tell copies apart. A relay is a sent
// frame with cause relay or a relay the peer's recent cache suppressed:
// both show the node chose to relay the key. For each received
// frame that ends in DROP_SILENT or IGNORE:
//
//   - with no relay of its key in the run, it passes;
//   - with a relay of its key, it passes when another received copy of the
//     key ended in ACCEPT or the node sent the key itself with another
//     cause (its own message, which the core gossips after self-delivery);
//     otherwise it fails, or is undecided when the run lost records
//     (dropped) and the accepted copy may be among them.
//
// A relay of re-encoded bytes (WBFT-NET-041) has another key and is not
// matched; DISCONNECT is not a case of this rule.
type noRelayCases struct{ check.Base }

func (c noRelayCases) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		for _, recs := range check.FrameRuns(d) {
			c.run(recs, out)
		}
	}
	return nil
}

func (c noRelayCases) run(recs []*frames.Record, out check.Emitter) {
	later := map[uint64][]string{} // outcomes of each received frame, in order
	relayed, own, accepted := map[string]int{}, map[string]bool{}, map[string]bool{}
	lost := false
	for _, r := range recs {
		switch {
		case r.Type == "dropped":
			lost = true
		case r.Type == "outcome" && r.Of != nil:
			later[*r.Of] = append(later[*r.Of], r.Outcome)
		case r.Type == "send_suppressed" && r.Cause == "relay" && r.DedupKey != "":
			relayed[r.DedupKey]++ // the node chose to relay; the peer's cache held the key
		case r.Type == "frame" && r.Dir == "out" && r.DedupKey != "":
			if r.Cause == "relay" {
				relayed[r.DedupKey]++
			} else if r.Cause != "" {
				own[r.DedupKey] = true
			}
		}
	}
	class := func(r *frames.Record) string {
		if r.Outcome != "PENDING" {
			return r.Outcome
		}
		outs := later[r.Seq]
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
	var ended []*frames.Record
	for _, r := range recs {
		if r.Type != "frame" || r.Dir != "in" || r.DedupKey == "" {
			continue
		}
		switch class(r) {
		case "ACCEPT":
			accepted[r.DedupKey] = true
		case "DROP_SILENT", "IGNORE":
			ended = append(ended, r)
		}
	}
	for _, r := range ended {
		cl, key := class(r), r.DedupKey
		n := relayed[key]
		switch {
		case n == 0:
			emit(out, reqNoRelay, r, true, "received frame ended in "+cl+"; its key was not relayed")
		case accepted[key]:
			emit(out, reqNoRelay, r, true, fmt.Sprintf("received frame ended in %s; its key was relayed %d times after another copy was accepted", cl, n))
		case own[key]:
			emit(out, reqNoRelay, r, true, fmt.Sprintf("received frame ended in %s; its key, relayed %d times, is the node's own message", cl, n))
		case lost:
			out.Emit(check.FrameInstance(reqNoRelay, r, verdict.CannotDecide, verdict.MissingData,
				fmt.Sprintf("received frame ended in %s and its key was relayed %d times; the run lost records, so an accepted copy may be missing", cl, n)))
		default:
			emit(out, reqNoRelay, r, false, fmt.Sprintf("received frame ended in %s, but its key was relayed %d times and no copy of it was accepted", cl, n))
		}
	}
}
