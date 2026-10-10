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
// first outcome recorded for it. A frame without dedup has no instance.
//
// The other row: a frame whose key was not known (a first receipt) is
// delivered, that is the receiver took it (PENDING), and its key enters
// the known cache before the core checks it, whatever the core decides.
// The next received frame of the key in the run that the node checked
// (with dedup) must find it known, unless the cache may have evicted it:
// INMEMORY_MESSAGES other keys received or sent since (every frame is
// counted, which errs towards undecided), a received frame without dedup
// since (the engine stopped, and an implementation may clear the cache),
// or records lost after the receipt (dropped; a lost record may be the
// next copy) leave the instance undecided. A first receipt
// with no later copy passes on its delivery alone. Whether the core then
// checks the message is outside the dump: the runner's prefilter may still
// drop it (A-06).
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
		for _, recs := range check.FrameRuns(d) {
			firstReceipts(recs, out)
		}
	}
	return nil
}

// firstReceipts decides the first-receipt row of WBFT-NET-024 in the
// records of one run, in seq order.
func firstReceipts(recs []*frames.Record, out check.Emitter) {
	for i, r := range recs {
		if !checkedReceipt(r) || *r.Dedup.KnownHit || r.DedupKey == "" {
			continue
		}
		if code, err := strconv.ParseUint(r.Code, 0, 64); err != nil || code < codeFirst || code > codeLast {
			continue
		}
		if r.Outcome != "PENDING" {
			emit(out, "WBFT-NET-024", r, false, fmt.Sprintf("received %s with a key not known, outcome %s (want it delivered)", r.Code, r.Outcome))
			continue
		}
		others, unsure, next := map[string]bool{}, "", (*frames.Record)(nil)
		for _, l := range recs[i+1:] {
			switch {
			case l.Type == "dropped":
				unsure = "the run lost records since"
			case l.Type != "frame" || l.DedupKey == "":
			case l.DedupKey != r.DedupKey:
				others[l.DedupKey] = true
			case checkedReceipt(l):
				next = l
			case l.Dir == "in":
				unsure = "a copy received since without dedup (the engine was not running)"
			}
			if next != nil || unsure != "" {
				break
			}
		}
		switch {
		case unsure != "":
			out.Emit(check.FrameInstance("WBFT-NET-024", r, verdict.CannotDecide, verdict.MissingData,
				fmt.Sprintf("received %s with a key not known; %s", r.Code, unsure)))
		case next == nil:
			emit(out, "WBFT-NET-024", r, true, fmt.Sprintf("received %s with a key not known and delivered; no later copy", r.Code))
		case len(others) >= check.InmemoryMessages:
			out.Emit(check.FrameInstance("WBFT-NET-024", r, verdict.CannotDecide, verdict.ObserverScope,
				fmt.Sprintf("received %s with a key not known; %d other keys were used before the next copy (seq %d), so the cache may have evicted it", r.Code, len(others), next.Seq)))
		default:
			emit(out, "WBFT-NET-024", r, *next.Dedup.KnownHit,
				fmt.Sprintf("received %s with a key not known and delivered; the next copy (seq %d) found it known: %v", r.Code, next.Seq, *next.Dedup.KnownHit))
		}
	}
}

// checkedReceipt reports whether r is a received frame the node checked
// against the dedup caches.
func checkedReceipt(r *frames.Record) bool {
	return r.Type == "frame" && r.Dir == "in" && r.Dedup != nil && r.Dedup.KnownHit != nil
}
