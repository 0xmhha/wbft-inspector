package timer

import (
	"context"
	"fmt"
	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
	"slices"
	"strings"
)

func init() {
	check.Register(retryWire{check.Base{ID: "timer.retry_wire_suppressed", Reqs: []string{"WBFT-TIMER-024"}, Kinds: []check.Kind{check.Frames}}})
}

type retryWire struct{ check.Base }

const reqRetryWire = "WBFT-TIMER-024"
const (
	inmemoryPeers    = check.InmemoryPeers
	inmemoryMessages = check.InmemoryMessages
)

// retryWire uses actual mutex decisions and exact queue attempts. Physical
// frame order cannot establish cache-decision order for asynchronous writes.
func (c retryWire) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, dump := range in.Frames {
		sources, problems := frames.CacheSources(dump)
		if len(problems) > 0 {
			return fmt.Errorf("invalid cache source: %s", strings.Join(problems, "; "))
		}
		sourceStates := map[[3]string]map[[2]string]frames.CacheState{}
		for _, s := range sources {
			r := s.Declaration
			sourceStates[[3]string{r.File, r.Node, r.Run}] = frames.ReplayCache(s)
		}
		for _, records := range check.FrameRuns(dump) {
			for _, r := range records {
				if r.Cause != "retry" || r.Peer == nil || r.DedupKey == "" {
					continue
				}
				if r.Type != "send_suppressed" && (r.Type != "frame" || r.Dir != "out") {
					continue
				}
				states := sourceStates[[3]string{r.File, r.Node, r.Run}]
				out.Emit(retryCacheDecision(r, states))
			}
		}
	}
	return nil
}

func retryCacheDecision(r *frames.Record, states map[[2]string]frames.CacheState) verdict.Instance {
	peer := *r.Peer
	var sourceRecord *frames.Record
	undecided := func(message string) verdict.Instance {
		i := check.FrameInstance(reqRetryWire, r, verdict.CannotDecide, verdict.ObserverScope, message)
		if sourceRecord != nil {
			i.Evidence = append(i.Evidence, check.FramePointer(sourceRecord))
		}
		return i
	}
	emit := func(v verdict.Verdict, message string) verdict.Instance {
		i := check.FrameInstance(reqRetryWire, r, v, "", message)
		if sourceRecord != nil {
			i.Evidence = append(i.Evidence, check.FramePointer(sourceRecord))
		}
		return i
	}
	if states == nil {
		if r.Type == "send_suppressed" {
			return emit(verdict.Pass, "retransmission explicitly left off the wire for "+peer+"; no cache-state or delivery claim")
		}
		return undecided("legacy retransmission has no exact cache decision or enqueue identity; physical frame order does not establish cache order")
	}
	ref := r.CacheDecision
	if r.Type == "frame" {
		a := r.SendAttempt
		if a == nil || a.Available == nil || !*a.Available {
			return undecided("enqueue identity or observer ownership is unavailable")
		}
		ref = a.Decision
	}
	if ref == nil || ref.Available == nil || !*ref.Available {
		return undecided("complete cache-decision source is unavailable")
	}
	state, ok := states[[2]string{ref.Instance, ref.Operation}]
	sourceRecord = state.Record
	if !ok || !state.Known {
		return undecided("cache prefix is incomplete or inconsistent; no cache state inferred from frame time")
	}
	held, candidate := state.Held[peer]
	if !candidate {
		return undecided("peer is not in the observed candidate set of this exact cache decision")
	}
	op := state.Record.CacheOperation
	if r.Type == "send_suppressed" {
		if !held || !state.Consistent || !slices.Contains(op.Suppressed, peer) {
			return undecided("suppression is inconsistent with independent cache replay")
		}
		return emit(verdict.Pass, "exact retransmission decision suppressed "+peer+" while its recent cache held the key")
	}
	if r.WriteResult == "not_attached" {
		return emit(verdict.Pass, "exact queue attempt found no attached stream; no frame was written")
	}
	if held {
		if r.WriteResult != "ok" {
			return undecided("cache held the key but the unsuccessful write does not establish a complete frame on the wire")
		}
		return emit(verdict.Fail, "exact retry attempt wrote to "+peer+" although its cache decision held the key; cache instance "+ref.Instance+", operation "+ref.Operation)
	}
	if !state.Consistent || !slices.Contains(op.Targets, peer) {
		return undecided("physical write contradicts its declared cache target decision")
	}
	return emit(verdict.Pass, "exact retry attempt targeted "+peer+" when independent cache replay found no key; later cache uses do not alter this decision")
}
