package sec

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(equivocationReported{check.Base{ID: "sec.equivocation_reported", Reqs: []string{reqReported},
		Kinds: []check.Kind{check.Frames, check.Events}}})
}

const reqReported = "WBFT-SEC-041"

// equivocationReported decides WBFT-SEC-041 from a node's frame dump and
// its event stream of the same run: a node that sees two valid signatures
// of one validator on different digests for one view reports it. It is the
// cross-check of the double-signing evidence a node records (R-08) with
// what the inspector finds in the node's received frames.
//
// From the dump: the received PRE-PREPARE, PREPARE and COMMIT frames,
// grouped by signer, view and code. The signer counts only when the node's
// MSG_OUTCOME records name it as a source (a validator whose signature the
// node verified). For a group with two digests:
//
//   - an EVIDENCE record of the run for that signer, view and code passes;
//   - without one it fails when the node's view, at the frame that brought
//     the second digest, was the group's sequence or next to it (the node
//     tracks the previous, the current and the next sequence); otherwise it
//     is undecided (OBSERVER_SCOPE).
//
// From the events: an EVIDENCE record whose two digests the dump holds for
// that signer, view and code passes; one the dump does not support is
// undecided (INCONSISTENT_INPUT), or MISSING_DATA when the dump lost
// records. A dump run without an event run of the same node and run id
// leaves its groups undecided (MISSING_DATA). The node does not track the
// PREPAREs inside a ROUND-CHANGE or a PRE-PREPARE, so they are not read.
type equivocationReported struct{ check.Base }

type viewKey struct {
	signer, seq, round string
	code               uint64
}

// sighting is the first frame of each digest of one group.
type sighting struct {
	order    []string
	byDigest map[string]*frames.Record
}

func (c equivocationReported) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	runs := map[[2]string]*events.Run{}
	if in.Events != nil {
		for _, r := range in.Events.Runs {
			if !r.FromLog {
				runs[[2]string{r.Node, r.ID}] = r
			}
		}
	}
	for _, d := range in.Frames {
		cache := map[string]*message.Message{}
		for _, recs := range check.FrameRuns(d) {
			if len(recs) == 0 {
				continue
			}
			c.run(d, recs, runs[[2]string{recs[0].Node, recs[0].Run}], cache, out)
		}
	}
	return nil
}

var codeNames = map[uint64]string{message.CodePreprepare: "PRE-PREPARE", message.CodePrepare: "PREPARE", message.CodeCommit: "COMMIT"}

func (c equivocationReported) run(d *frames.Dump, recs []*frames.Record, er *events.Run, cache map[string]*message.Message, out check.Emitter) {
	groups := map[viewKey]*sighting{}
	var order []viewKey
	lost := false
	for _, r := range recs {
		if r.Type == "dropped" {
			lost = true
		}
		if r.Type != "frame" || r.Dir != "in" {
			continue
		}
		code, err := strconv.ParseUint(strings.TrimPrefix(r.Code, "0x"), 16, 64)
		if err != nil || codeNames[code] == "" {
			continue
		}
		m := decode(d, r, code, cache)
		if m == nil || !m.HasDigest {
			continue
		}
		k := viewKey{signer: "0x" + hex.EncodeToString(m.Signer[:]), seq: m.Sequence.String(), round: m.Round.String(), code: code}
		g := groups[k]
		if g == nil {
			g = &sighting{byDigest: map[string]*frames.Record{}}
			groups[k] = g
			order = append(order, k)
		}
		dg := "0x" + hex.EncodeToString(m.Digest[:])
		if _, ok := g.byDigest[dg]; !ok {
			g.byDigest[dg] = r
			g.order = append(g.order, dg)
		}
	}
	if er == nil {
		for _, k := range order {
			if g := groups[k]; len(g.order) > 1 {
				out.Emit(check.FrameInstance(reqReported, g.byDigest[g.order[1]], verdict.CannotDecide, verdict.MissingData,
					fmt.Sprintf("%s signed %s for (%s, %s) with two digests; no event stream of this run to find its EVIDENCE in", k.signer, codeNames[k.code], k.seq, k.round)))
			}
		}
		return
	}
	sources := map[string]bool{}
	reported := map[viewKey]*events.Event{}
	var evs []*events.Event
	for _, e := range er.Events {
		switch {
		case e.Kind == "MSG_OUTCOME" && e.Str("check") != "prefilter":
			if s := e.Str("source"); s != "" {
				sources[s] = true
			}
		case e.Kind == "EVIDENCE" && e.View != nil:
			code, ok := e.Int("code")
			if !ok {
				continue
			}
			k := viewKey{signer: e.Str("source"), seq: e.View.Seq, round: e.View.Round, code: uint64(code)} //nolint:gosec // a message code
			if reported[k] == nil {
				reported[k] = e
			}
			evs = append(evs, e)
		}
	}
	for _, k := range order {
		g := groups[k]
		if len(g.order) < 2 || !sources[k.signer] {
			continue
		}
		second := g.byDigest[g.order[1]]
		what := fmt.Sprintf("%s signed %s for (%s, %s) with %d digests", k.signer, codeNames[k.code], k.seq, k.round, len(g.order))
		if e := reported[k]; e != nil {
			inst := check.FrameInstance(reqReported, second, verdict.Pass, "", what+"; the node recorded EVIDENCE")
			inst.Evidence = append(inst.Evidence, check.Pointer(e))
			out.Emit(inst)
			continue
		}
		if seq := viewAt(er, second.TMono); seq != nil && near(seq, k.seq) {
			inst := check.FrameInstance(reqReported, second, verdict.Fail, "", what+fmt.Sprintf("; the node, at sequence %s, recorded no EVIDENCE", seq))
			inst.Evidence = append(inst.Evidence, check.FramePointer(g.byDigest[g.order[0]]))
			out.Emit(inst)
			continue
		}
		out.Emit(check.FrameInstance(reqReported, second, verdict.CannotDecide, verdict.ObserverScope,
			what+"; the node's view then is unknown or outside the sequences it tracks"))
	}
	for _, e := range evs {
		code, _ := e.Int("code")
		k := viewKey{signer: e.Str("source"), seq: e.View.Seq, round: e.View.Round, code: uint64(code)} //nolint:gosec // a message code
		g := groups[k]
		a, b := strings.ToLower(e.Str("digest_a")), strings.ToLower(e.Str("digest_b"))
		if g != nil && g.byDigest[a] != nil && g.byDigest[b] != nil {
			out.Emit(check.New(reqReported, e, verdict.Pass, "", fmt.Sprintf("EVIDENCE of %s for %s at (%s, %s): the dump holds both messages", k.signer, codeNames[k.code], k.seq, k.round)))
			continue
		}
		reason := verdict.InconsistentInput
		if lost {
			reason = verdict.MissingData
		}
		out.Emit(check.New(reqReported, e, verdict.CannotDecide, reason, fmt.Sprintf("EVIDENCE of %s for %s at (%s, %s): the dump does not hold both messages", k.signer, codeNames[k.code], k.seq, k.round)))
	}
}

// viewAt returns the sequence of the node's last ROUND_ENTER at or before
// the monotonic time t, or nil.
func viewAt(er *events.Run, t int64) *big.Int {
	var seq *big.Int
	for _, e := range er.Events {
		if e.TMono > t {
			break
		}
		if e.Kind == "ROUND_ENTER" && e.View != nil {
			seq = e.View.SeqBig()
		}
	}
	return seq
}

// near reports whether the decimal sequence s is within one of cur.
func near(cur *big.Int, s string) bool {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return false
	}
	d := new(big.Int).Sub(v, cur)
	return d.CmpAbs(big.NewInt(1)) <= 0
}
