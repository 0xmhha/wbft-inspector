package sec

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noReprepareBadBlock{check.Base{ID: "sec.no_reprepare_bad_block", Reqs: []string{reqNoReprepare},
		Kinds: []check.Kind{check.Events, check.Frames}}})
}

const reqNoReprepare = "WBFT-SEC-081"

// noReprepareBadBlock decides WBFT-SEC-081: after a node recorded a block
// at height h as bad, it sends no PREPARE or COMMIT for that block at h.
// The bad-block records are the node's IMPORT_FAIL events with
// recorded_bad; the votes are the PREPARE and COMMIT frames the node signed
// and sent (its frame dump), whose sequence is h and digest the block hash.
//
// One instance per bad block of a node (its first IMPORT_FAIL record of
// the hash):
//
//   - a vote sent after the record fails it, unless the node had recorded
//     ten bad blocks above h by then (the record may have been dropped,
//     so the protection may have ended): that vote leaves the instance
//     undecided (OBSERVER_SCOPE) when there is no failing one;
//   - no such vote passes it when the node's frame dump has records after
//     the bad-block record and lost none; otherwise it is undecided
//     (MISSING_DATA).
//
// The record persists across restarts, so votes of later runs count. Times
// are the node's wall clock in both inputs.
type noReprepareBadBlock struct{ check.Base }

type sentVote struct {
	r    *frames.Record
	at   time.Time
	seq  string
	hash string
	name string
}

func (c noReprepareBadBlock) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	bad, nodes := check.BadBlocks(in)
	votes := map[string][]sentVote{}
	last := map[string]time.Time{} // the node's latest frame record
	lost := map[string]bool{}
	for _, d := range in.Frames {
		cache := map[string]*message.Message{}
		for _, recs := range check.FrameRuns(d) {
			for _, r := range recs {
				if t, err := time.Parse(time.RFC3339Nano, r.TWall); err == nil && t.After(last[r.Node]) {
					last[r.Node] = t
				}
				if r.Type == "dropped" {
					lost[r.Node] = true
				}
				if r.Type != "frame" || r.Dir != "out" {
					continue
				}
				code, err := strconv.ParseUint(strings.TrimPrefix(r.Code, "0x"), 16, 64)
				if err != nil || (code != message.CodePrepare && code != message.CodeCommit) {
					continue
				}
				m := check.Decode(d, r, code, cache)
				if m == nil || "0x"+hex.EncodeToString(m.Signer[:]) != r.Node {
					continue
				}
				at, err := time.Parse(time.RFC3339Nano, r.TWall)
				if err != nil {
					continue
				}
				name := map[uint64]string{message.CodePrepare: "PREPARE", message.CodeCommit: "COMMIT"}[code]
				votes[r.Node] = append(votes[r.Node], sentVote{r: r, at: at, seq: m.Sequence.String(), hash: "0x" + hex.EncodeToString(m.Digest[:]), name: name})
			}
		}
	}
	for _, node := range nodes {
		bs := bad[node]
		for _, b := range bs {
			what := fmt.Sprintf("bad block %s at height %s", b.Hash, b.Number)
			var fail, lapsed *sentVote
			for i := range votes[node] {
				v := &votes[node][i]
				if v.seq != b.Number || v.hash != b.Hash || !v.at.After(b.At) {
					continue
				}
				if b.Lapsed(bs, v.at) {
					if lapsed == nil {
						lapsed = v
					}
					continue
				}
				if fail == nil || v.at.Before(fail.at) {
					fail = v
				}
			}
			switch {
			case fail != nil:
				inst := check.Fail(reqNoReprepare, b.Event, fmt.Sprintf("the node sent %s for the %s after it recorded the block as bad", fail.name, what))
				inst.Evidence = append(inst.Evidence, check.FramePointer(fail.r))
				out.Emit(inst)
			case lapsed != nil:
				inst := check.Undecided(reqNoReprepare, b.Event, verdict.ObserverScope, fmt.Sprintf(
					"the node sent %s for the %s after recording %d bad blocks above it; the record may have been dropped", lapsed.name, what, check.BadRetention))
				inst.Evidence = append(inst.Evidence, check.FramePointer(lapsed.r))
				out.Emit(inst)
			case !last[node].After(b.At) || lost[node]:
				out.Emit(check.Undecided(reqNoReprepare, b.Event, verdict.MissingData,
					fmt.Sprintf("no complete frame dump of the node after it recorded the %s", what)))
			default:
				out.Emit(check.Pass(reqNoReprepare, b.Event, fmt.Sprintf("the node sent no PREPARE or COMMIT for the %s after recording it", what)))
			}
		}
	}
	return nil
}
