// Package hdr holds the checkers of the header rules (wbft-spec A-08).
package hdr

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(proposalOrder{check.Base{ID: "hdr.proposal_verify_order", Reqs: []string{reqOrder},
		Kinds: []check.Kind{check.Frames, check.Rejections}}})
}

const reqOrder = "WBFT-HDR-060"

// rowPreprepareAccept is the row of the message-handling outcome table
// (A-05 §16) of a PRE-PREPARE the node accepted.
const rowPreprepareAccept = 15

// proposalOrder decides WBFT-HDR-060 (a node verifies a proposal with the
// steps P1-P7 in order and takes the first failing step as the result)
// for the proposals the inspector can find invalid itself. It reads the
// proposal header of each PRE-PREPARE in a node's frame dump and applies
// the header steps that need nothing but the header (header.FirstFailure:
// H3, H4, H5, H7, H13, H16) and, when the chain configuration gives the
// chain id, H18 (the randao reveal recovers to Coinbase). For a proposal that fails one of them,
// step S, the node must reject it at S or at an earlier step the
// inspector cannot evaluate. It is the R-09 cross-check of the node's
// rejection records with the inspector's own verdict on the proposal.
//
// One instance per view and block of a run: the received copies, and the
// node's own proposal (its first sent PRE-PREPARE of the view, since the
// node delivers it to itself without a frame). A PRE-PREPARE whose
// sequence is not the block number is left out (the message checks reject
// it before verification).
//
//   - The node accepted it (a copy's outcome is row 15, or for its own
//     proposal it sent its PREPARE for it): FAIL.
//   - A rejection record of the block within the run: PASS when its step
//     is S or comes before S, FAIL when it comes after S, and undecided
//     (MISSING_DATA) when it names no known step.
//   - Neither: undecided. MISSING_DATA when the node's rejections were not
//     given or the dump lost records, OBSERVER_SCOPE otherwise (a received
//     copy may have failed the message checks, and a proposal from the
//     future is verified again later).
type proposalOrder struct{ check.Base }

type groupKey struct{ view, hash string }

type group struct {
	first    *frames.Record
	own      bool
	accepted *frames.Record // the copy accepted, or the node's PREPARE for its own proposal
	fail     *header.Failure
}

func (c proposalOrder) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	var chainID *big.Int
	if in.Config != nil {
		chainID = in.Config.ChainID
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
			if len(recs) == 0 {
				continue
			}
			c.run(d, recs, byNode[recs[0].Node], given[recs[0].Node], chainID, cache, out)
		}
	}
	return nil
}

func (c proposalOrder) run(d *frames.Dump, recs []*frames.Record, rejs []*rejections.Record, given bool, chainID *big.Int,
	cache map[string]*message.Message, out check.Emitter) {
	node := recs[0].Node
	groups := map[groupKey]*group{}
	var order []groupKey
	frameGroup := map[uint64]*group{}
	ownPrepares := map[groupKey]*frames.Record{}
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
			k := groupKey{view: fmt.Sprintf("(%s, %s)", m.Sequence, m.Round), hash: "0x" + hex.EncodeToString(m.Digest[:])}
			own := "0x"+hex.EncodeToString(m.Signer[:]) == node
			if code == message.CodePrepare {
				if r.Dir == "out" && own && ownPrepares[k] == nil {
					ownPrepares[k] = r
				}
				continue
			}
			if r.Dir == "out" && !own {
				continue // a relay
			}
			g := groups[k]
			if g == nil {
				h, err := header.Decode(m.Header)
				if err != nil || h.Number.Cmp(m.Sequence) != 0 {
					continue
				}
				g = &group{first: r, own: r.Dir == "out", fail: h.FirstFailure(chainID)}
				groups[k] = g
				order = append(order, k)
			}
			if r.Dir == "in" {
				frameGroup[r.Seq] = g
			}
		}
	}
	first, last, ok := check.WallRange(recs)
	for _, k := range order {
		g := groups[k]
		if g.fail == nil {
			continue
		}
		if g.own && g.accepted == nil {
			g.accepted = ownPrepares[k]
		}
		what := fmt.Sprintf("PRE-PREPARE of block %s at %s fails %s (%s)", k.hash, k.view, g.fail.Step, g.fail.Why)
		if g.own {
			what = "the node's own " + what
		}
		if g.accepted != nil {
			inst := check.FrameInstance(reqOrder, g.first, verdict.Fail, "", what+"; the node accepted it")
			inst.Evidence = append(inst.Evidence, check.FramePointer(g.accepted))
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
			want, _ := header.Order(g.fail.Step)
			v, reason, msg := verdict.Pass, verdict.Reason(""), what+"; the node rejected it at "+rec.Step
			switch {
			case !known:
				v, reason, msg = verdict.CannotDecide, verdict.MissingData, what+"; the node's rejection names no known step ("+check.RejectionCause(rec)+")"
			case pos > want:
				v, msg = verdict.Fail, what+"; the node rejected it at the later step "+rec.Step
			}
			inst := check.FrameInstance(reqOrder, g.first, v, reason, msg)
			inst.Evidence = append(inst.Evidence, check.RejectionPointer(rec))
			out.Emit(inst)
		case !given || lost:
			out.Emit(check.FrameInstance(reqOrder, g.first, verdict.CannotDecide, verdict.MissingData,
				what+"; no rejection record of it (the node's rejections were not given, or the dump lost records)"))
		default:
			out.Emit(check.FrameInstance(reqOrder, g.first, verdict.CannotDecide, verdict.ObserverScope,
				what+"; no rejection record of it in this run (it may have failed the message checks, or been verified later as a future block)"))
		}
	}
}
