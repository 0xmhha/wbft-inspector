// Package app holds the checkers of the application-interface
// requirements (wbft-spec A-09).
package app

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noPrepareOnInvalid{check.Base{ID: "app.no_prepare_on_invalid", Reqs: []string{reqNoPrepare},
		Kinds: []check.Kind{check.Frames, check.Rejections}}})
}

const reqNoPrepare = "WBFT-APP-051"

// rowPreprepareReject and rowPreprepareAccept are the rows of the
// message-handling outcome table (A-05 §16) of a PRE-PREPARE the node
// rejected and accepted.
const (
	rowPreprepareReject = 13
	rowPreprepareAccept = 15
)

// windowSlack widens a run's wall-clock range when rejections are matched
// to it: a rejection is stamped when the proposal is verified, which is
// close to, but not inside, the frame records around it.
const windowSlack = time.Second

// noPrepareOnInvalid decides WBFT-APP-051 from a node's frame dump and its
// rejection records (`wbft_rejections`, R-09): when the application finds
// a proposal invalid (any error but ErrFutureBlock), the node sends no
// PREPARE for it. The rejection records say which proposals failed
// verification; the outcome row of a PRE-PREPARE (A-05 §16 row 13) does
// not, since it also covers a sender that is not the proposer, a sequence
// that is not the block number and a missing justification.
//
// For each run of the dump, the PRE-PREPARE rejections (path preprepare)
// stamped within the run's time range are matched by block hash with the
// PRE-PREPARE frames:
//
//   - each received copy of that block whose outcome is row 13 is an
//     instance: it fails when the node then sent its own PREPARE for that
//     view and block, before a later copy of the same view was accepted
//     (row 15), and passes otherwise;
//   - the node's own proposal of that block (its first sent PRE-PREPARE of
//     the view) is an instance too: the node delivers it to itself without
//     a frame, so the dump has no outcome for it and the rejection record
//     is the only sign. It fails when the run holds the node's PREPARE for
//     that view and block, in any order (a sent frame is recorded after
//     the write, so the PREPARE may come first), and passes otherwise;
//   - a rejection with no such copy in the run is undecided:
//     INCONSISTENT_INPUT, or MISSING_DATA when the dump lost records.
//
// A PREPARE for the same block in a later round is allowed (the proposal
// can be verified again) and is not read. That the round then ends by
// timeout is not decided here.
type noPrepareOnInvalid struct{ check.Base }

// copyOf is a received PRE-PREPARE frame, or the first frame of the
// node's own PRE-PREPARE of a view.
type copyOf struct {
	idx      int
	r        *frames.Record
	view     string
	hash     string
	own      bool
	rejected bool
	accepted bool
}

// vote is a PREPARE the node signed and sent.
type vote struct {
	idx  int
	r    *frames.Record
	view string
	hash string
}

func (c noPrepareOnInvalid) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	byNode := map[string][]*rejections.Record{}
	for _, s := range in.Rejections {
		for _, r := range s.Records {
			if r.Path == "preprepare" {
				byNode[r.Node] = append(byNode[r.Node], r)
			}
		}
	}
	for _, d := range in.Frames {
		cache := map[string]*message.Message{}
		for _, recs := range check.FrameRuns(d) {
			if len(recs) == 0 || len(byNode[recs[0].Node]) == 0 {
				continue
			}
			c.run(d, recs, byNode[recs[0].Node], cache, out)
		}
	}
	return nil
}

func (c noPrepareOnInvalid) run(d *frames.Dump, recs []*frames.Record, rejs []*rejections.Record, cache map[string]*message.Message, out check.Emitter) {
	first, last, ok := wallRange(recs)
	if !ok {
		return
	}
	byHash := map[string][]*rejections.Record{}
	var hashes []string
	for _, r := range rejs {
		if r.At.Before(first.Add(-windowSlack)) || r.At.After(last.Add(windowSlack)) {
			continue
		}
		if byHash[r.Hash] == nil {
			hashes = append(hashes, r.Hash)
		}
		byHash[r.Hash] = append(byHash[r.Hash], r)
	}
	if len(hashes) == 0 {
		return
	}
	node := recs[0].Node
	lost := false
	var copies []*copyOf
	frameAt := map[uint64]*copyOf{}
	var votes []vote
	proposed := map[string]bool{} // views of the node's own PRE-PREPAREs
	for i, r := range recs {
		switch r.Type {
		case "dropped":
			lost = true
		case "outcome":
			if r.Of == nil || r.Row == nil || r.Check == "prefilter" {
				continue
			}
			if x := frameAt[*r.Of]; x != nil {
				x.rejected = x.rejected || *r.Row == rowPreprepareReject
				x.accepted = x.accepted || *r.Row == rowPreprepareAccept
			}
		case "frame":
			code, err := strconv.ParseUint(strings.TrimPrefix(r.Code, "0x"), 16, 64)
			if err != nil {
				continue
			}
			switch {
			case r.Dir == "in" && code == message.CodePreprepare:
				m := check.Decode(d, r, code, cache)
				if m == nil || !m.HasDigest {
					continue
				}
				x := &copyOf{idx: i, r: r, view: viewOf(m), hash: hashOf(m)}
				copies = append(copies, x)
				frameAt[r.Seq] = x
			case r.Dir == "out" && code == message.CodePreprepare:
				m := check.Decode(d, r, code, cache)
				if m == nil || !m.HasDigest || "0x"+hex.EncodeToString(m.Signer[:]) != node || proposed[viewOf(m)] {
					continue
				}
				proposed[viewOf(m)] = true
				copies = append(copies, &copyOf{idx: i, r: r, view: viewOf(m), hash: hashOf(m), own: true, rejected: true})
			case r.Dir == "out" && code == message.CodePrepare:
				m := check.Decode(d, r, code, cache)
				if m == nil || "0x"+hex.EncodeToString(m.Signer[:]) != node {
					continue
				}
				votes = append(votes, vote{idx: i, r: r, view: viewOf(m), hash: hashOf(m)})
			}
		}
	}
	for _, h := range hashes {
		rec := byHash[h][0]
		judged := false
		for _, x := range copies {
			if x.hash != h || !x.rejected {
				continue
			}
			judged = true
			what := fmt.Sprintf("PRE-PREPARE of block %s at %s, rejected (%s)", h, x.view, why(rec))
			if x.own {
				what = "the node's own " + what
			}
			if v := prepareAfter(x, copies, votes); v != nil {
				inst := check.FrameInstance(reqNoPrepare, v.r, verdict.Fail, "", what+"; the node then sent its PREPARE for it")
				inst.Evidence = append(inst.Evidence, check.FramePointer(x.r), pointer(rec))
				out.Emit(inst)
				continue
			}
			inst := check.FrameInstance(reqNoPrepare, x.r, verdict.Pass, "", what+"; the node sent no PREPARE for it")
			inst.Evidence = append(inst.Evidence, pointer(rec))
			out.Emit(inst)
		}
		if judged {
			continue
		}
		reason := verdict.InconsistentInput
		if lost {
			reason = verdict.MissingData
		}
		for _, r := range byHash[h] {
			out.Emit(verdict.Instance{Requirement: reqNoPrepare, Node: r.Node, Key: fmt.Sprintf("rejection:%s:%d", r.Input, r.Line),
				Verdict: verdict.CannotDecide, Reason: reason, Source: r.Input, Evidence: []evidence.Pointer{pointer(r)},
				Message: fmt.Sprintf("rejection of block %s (%s): run %s of the dump holds no PRE-PREPARE of it that the node rejected", h, why(r), recs[0].Run)})
		}
	}
}

// prepareAfter returns the node's first PREPARE for x's view and block
// after x, unless a copy of the same view and block was accepted before
// it. For the node's own proposal it is the first such PREPARE of the run.
func prepareAfter(x *copyOf, copies []*copyOf, votes []vote) *vote {
	for i := range votes {
		v := &votes[i]
		if v.view != x.view || v.hash != x.hash {
			continue
		}
		if x.own {
			return v
		}
		if v.idx < x.idx {
			continue
		}
		for _, y := range copies {
			if y.accepted && y.view == x.view && y.hash == x.hash && y.idx > x.idx && y.idx < v.idx {
				return nil
			}
		}
		return v
	}
	return nil
}

// wallRange returns the first and last wall-clock time of a run.
func wallRange(recs []*frames.Record) (first, last time.Time, ok bool) {
	for _, r := range recs {
		t, err := time.Parse(time.RFC3339Nano, r.TWall)
		if err != nil {
			continue
		}
		if !ok || t.Before(first) {
			first = t
		}
		if !ok || t.After(last) {
			last = t
		}
		ok = true
	}
	return first, last, ok
}

func viewOf(m *message.Message) string {
	return fmt.Sprintf("(%s, %s)", m.Sequence, m.Round)
}

func hashOf(m *message.Message) string { return "0x" + hex.EncodeToString(m.Digest[:]) }

// why describes a rejection record.
func why(r *rejections.Record) string {
	s := "step " + r.Step
	if r.Step == "" {
		s = "step unknown"
	}
	if r.Class != "" {
		s += ", " + r.Class
	}
	return s
}

// pointer returns the evidence pointer of a rejection record.
func pointer(r *rejections.Record) evidence.Pointer {
	return evidence.Pointer{Kind: evidence.KindRPC, Method: "wbft_rejections", Input: r.Input, Node: r.Node, Number: r.Number,
		Hash: r.Hash, Line: r.Line, T: r.Time, Msg: why(r) + ", path " + r.Path}
}
