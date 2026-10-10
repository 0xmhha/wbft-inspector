package net

import (
	"context"
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(knownCacheDrop{check.Base{ID: "net.known_cache_drop", Reqs: []string{"WBFT-NET-024"},
		Kinds: []check.Kind{check.Frames}}})
}

// knownCacheDrop decides the duplicate row of WBFT-NET-024 from the dedup
// cache hits a node recorded with a received frame (R-01 frame.dedup): a
// consensus frame (0x12..0x15) whose key was already in the known cache is
// discarded (DROP_SILENT) and never reaches the core, that is no outcome of
// the frame comes from check_message (a check other than prefilter).
//
// The outcome is the frame's, or, when the frame waited (PENDING), the
// first outcome recorded for it. A frame without dedup, or whose key was
// not known, has no instance: the other row (a first receipt reaches the
// core) is not decided, since a node's receive queue may still drop or
// replace a message before the core for reasons outside A-07 §5.3.
type knownCacheDrop struct{ check.Base }

func (c knownCacheDrop) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		// The outcomes recorded later for each received frame, in order.
		later := map[[3]string][]*frames.Record{}
		for _, r := range d.Records {
			if r.Type == "outcome" && r.Of != nil {
				k := [3]string{r.File, r.Run, strconv.FormatUint(*r.Of, 10)}
				later[k] = append(later[k], r)
			}
		}
		for _, r := range d.Records {
			if r.Type != "frame" || r.Dir != "in" || r.Dedup == nil || r.Dedup.KnownHit == nil || !*r.Dedup.KnownHit {
				continue
			}
			code, err := strconv.ParseUint(r.Code, 0, 64)
			if err != nil || code < codeFirst || code > codeLast {
				continue
			}
			outs := later[[3]string{r.File, r.Run, strconv.FormatUint(r.Seq, 10)}]
			got := r.Outcome
			if got == "PENDING" {
				if len(outs) == 0 {
					out.Emit(check.FrameInstance("WBFT-NET-024", r, verdict.CannotDecide, verdict.MissingData,
						fmt.Sprintf("received %#x with a known key; no outcome was recorded for it", code)))
					continue
				}
				got = outs[0].Outcome
			}
			core := ""
			for _, o := range outs {
				if o.Check != "prefilter" && o.Check != "" {
					core = o.Check
					break
				}
			}
			ok := got == "DROP_SILENT" && core == ""
			msg := fmt.Sprintf("received %#x with a known key, outcome %s (want DROP_SILENT)", code, got)
			if core != "" {
				msg += ", then checked by the core (" + core + ")"
			}
			emit(out, "WBFT-NET-024", r, ok, msg)
		}
	}
	return nil
}
