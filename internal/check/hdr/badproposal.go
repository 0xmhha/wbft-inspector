package hdr

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(badBlockProposal{check.Base{ID: "hdr.bad_block_proposal_reject", Reqs: []string{reqBadProposal},
		Kinds: []check.Kind{check.Events, check.Frames}}})
}

const reqBadProposal = "WBFT-HDR-061"

// stepBadHash is the step of A-08 §5 that rejects a proposal whose hash is
// recorded as bad (ErrBlacklistedHash); only the type check (P1) comes
// before it.
const stepBadHash = "P2"

// badBlockProposal decides WBFT-HDR-061: a node rejects a proposal whose
// hash it recorded as a bad block, before any other check except the type
// check. The bad blocks are the node's IMPORT_FAIL events with
// recorded_bad (check.BadBlocks); the proposals are the PRE-PREPAREs of
// its frame dump whose block hash is one of them, received after the
// record, and its own such proposals.
//
// One instance per view and block of a run, as for WBFT-HDR-060:
//
//   - the node accepted it (a copy's outcome is row 15, or it sent its
//     PREPARE for that view and block): FAIL;
//   - a rejection record of the block within the run: PASS at P1 or P2,
//     FAIL at a later step, undecided (MISSING_DATA) when it names no
//     known step;
//   - neither: undecided, MISSING_DATA without the node's rejections or
//     when the dump lost records, OBSERVER_SCOPE otherwise (the message
//     checks may have rejected the copy first).
//
// A proposal that came after the node recorded ten bad blocks above the
// block's height is left out, since the record may have been dropped
// (check.BadRetention).
type badBlockProposal struct{ check.Base }

func (c badBlockProposal) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	bad, _ := check.BadBlocks(in)
	if len(bad) == 0 {
		return nil
	}
	byNode := map[string][]*rejections.Record{}
	given := map[string]bool{}
	for _, s := range in.Rejections {
		given[s.Node] = true
		for _, r := range s.Records {
			if r.Path == "preprepare" {
				byNode[r.Node] = append(byNode[r.Node], r)
			}
		}
	}
	for _, d := range in.Frames {
		cache := map[string]*message.Message{}
		for _, recs := range check.FrameRuns(d) {
			if len(recs) == 0 || len(bad[recs[0].Node]) == 0 {
				continue
			}
			node := recs[0].Node
			c.run(d, recs, bad[node], byNode[node], given[node], cache, out)
		}
	}
	return nil
}

type badGroup struct {
	first    *frames.Record
	own      bool
	bad      *check.BadBlock
	accepted *frames.Record
}

func (c badBlockProposal) run(d *frames.Dump, recs []*frames.Record, bad []*check.BadBlock, rejs []*rejections.Record, given bool,
	cache map[string]*message.Message, out check.Emitter) {
	node := recs[0].Node
	byHash := map[string]*check.BadBlock{}
	for _, b := range bad {
		byHash[b.Hash] = b
	}
	groups := map[groupKey]*badGroup{}
	var order []groupKey
	frameGroup := map[uint64]*badGroup{}
	prepares := map[groupKey]*frames.Record{}
	lost := false
	for _, r := range recs {
		switch r.Type {
		case "dropped":
			lost = true
		case "outcome":
			if r.Of == nil || r.Row == nil || *r.Row != rowPreprepareAccept || r.Check == "prefilter" {
				continue
			}
			if g := frameGroup[*r.Of]; g != nil && g.accepted == nil {
				g.accepted = r
			}
		case "frame":
			code, err := strconv.ParseUint(strings.TrimPrefix(r.Code, "0x"), 16, 64)
			if err != nil || (code != message.CodePreprepare && code != message.CodePrepare) {
				continue
			}
			m := check.Decode(d, r, code, cache)
			if m == nil || !m.HasDigest {
				continue
			}
			hash := "0x" + hex.EncodeToString(m.Digest[:])
			b := byHash[hash]
			if b == nil {
				continue
			}
			k := groupKey{view: fmt.Sprintf("(%s, %s)", m.Sequence, m.Round), hash: hash}
			own := "0x"+hex.EncodeToString(m.Signer[:]) == node
			at, err := time.Parse(time.RFC3339Nano, r.TWall)
			if err != nil || !at.After(b.At) || b.Lapsed(bad, at) {
				continue // before the record, or after it may have been dropped
			}
			if code == message.CodePrepare {
				if r.Dir == "out" && own && prepares[k] == nil {
					prepares[k] = r
				}
				continue
			}
			if r.Dir == "out" && !own {
				continue // a relay
			}
			g := groups[k]
			if g == nil {
				g = &badGroup{first: r, own: r.Dir == "out", bad: b}
				groups[k] = g
				order = append(order, k)
			}
			if r.Dir == "in" {
				frameGroup[r.Seq] = g
			}
		}
	}
	first, last, ok := check.WallRange(recs)
	want, _ := header.Order(stepBadHash)
	for _, k := range order {
		g := groups[k]
		if g.accepted == nil {
			if p := prepares[k]; p != nil {
				g.accepted = p
			}
		}
		what := fmt.Sprintf("PRE-PREPARE at %s of block %s, which the node recorded as bad", k.view, k.hash)
		if g.own {
			what = "the node's own " + what
		}
		if g.accepted != nil {
			inst := check.FrameInstance(reqBadProposal, g.first, verdict.Fail, "", what+"; the node accepted it")
			inst.Evidence = append(inst.Evidence, check.FramePointer(g.accepted), check.Pointer(g.bad.Event))
			out.Emit(inst)
			continue
		}
		var rec *rejections.Record
		for _, r := range rejs {
			if r.Hash == k.hash && ok && check.InRun(r, first, last) {
				rec = r
				break
			}
		}
		switch {
		case rec != nil:
			pos, known := header.Order(rec.Step)
			v, reason, msg := verdict.Pass, verdict.Reason(""), what+"; the node rejected it at "+rec.Step
			switch {
			case !known:
				v, reason, msg = verdict.CannotDecide, verdict.MissingData, what+"; the node's rejection names no known step ("+check.RejectionCause(rec)+")"
			case pos > want:
				v, msg = verdict.Fail, what+"; the node rejected it at "+rec.Step+", after the bad-block check ("+stepBadHash+")"
			}
			inst := check.FrameInstance(reqBadProposal, g.first, v, reason, msg)
			inst.Evidence = append(inst.Evidence, check.RejectionPointer(rec), check.Pointer(g.bad.Event))
			out.Emit(inst)
		case !given || lost:
			out.Emit(check.FrameInstance(reqBadProposal, g.first, verdict.CannotDecide, verdict.MissingData,
				what+"; no rejection record of it (the node's rejections were not given, or the dump lost records)"))
		default:
			out.Emit(check.FrameInstance(reqBadProposal, g.first, verdict.CannotDecide, verdict.ObserverScope,
				what+"; no rejection record of it in this run (the message checks may have rejected it first)"))
		}
	}
}
