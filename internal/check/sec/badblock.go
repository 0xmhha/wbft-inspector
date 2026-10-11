package sec

import (
	"context"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noReprepareBadBlock{check.Base{ID: "sec.no_reprepare_bad_block", Reqs: []string{reqNoReprepare},
		Kinds: []check.Kind{check.Events, check.Frames}}})
}

const reqNoReprepare = "WBFT-SEC-081"

// badRetention is the number of bad-block records the reference keeps:
// the ten highest-numbered (A-09 WBFT-APP-004). The protection of a bad
// block lasts while its record is kept.
const badRetention = 10

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

type badRec struct {
	e    *events.Event
	at   time.Time
	num  string
	hash string
}

type sentVote struct {
	r    *frames.Record
	at   time.Time
	seq  string
	hash string
	name string
}

func (c noReprepareBadBlock) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	bad := map[string][]*badRec{}
	seen := map[[2]string]bool{}
	for _, r := range in.Events.Runs {
		for _, e := range r.Events {
			if e.Kind != "IMPORT_FAIL" {
				continue
			}
			if b, _ := e.Bool("recorded_bad"); !b {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, e.TWall)
			h := strings.ToLower(e.Str("hash"))
			if err != nil || seen[[2]string{e.Node, h}] {
				continue
			}
			seen[[2]string{e.Node, h}] = true
			bad[e.Node] = append(bad[e.Node], &badRec{e: e, at: at, num: e.Str("number"), hash: h})
		}
	}
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
	nodes := make([]string, 0, len(bad))
	for n := range bad { //wbft:unordered sorted below
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	for _, node := range nodes {
		bs := bad[node]
		for _, b := range bs {
			what := fmt.Sprintf("bad block %s at height %s", b.hash, b.num)
			var fail, lapsed *sentVote
			for i := range votes[node] {
				v := &votes[node][i]
				if v.seq != b.num || v.hash != b.hash || !v.at.After(b.at) {
					continue
				}
				if above(bs, b, v.at) >= badRetention {
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
				inst := check.Fail(reqNoReprepare, b.e, fmt.Sprintf("the node sent %s for the %s after it recorded the block as bad", fail.name, what))
				inst.Evidence = append(inst.Evidence, check.FramePointer(fail.r))
				out.Emit(inst)
			case lapsed != nil:
				inst := check.Undecided(reqNoReprepare, b.e, verdict.ObserverScope, fmt.Sprintf(
					"the node sent %s for the %s after recording %d bad blocks above it; the record may have been dropped", lapsed.name, what, badRetention))
				inst.Evidence = append(inst.Evidence, check.FramePointer(lapsed.r))
				out.Emit(inst)
			case !last[node].After(b.at) || lost[node]:
				out.Emit(check.Undecided(reqNoReprepare, b.e, verdict.MissingData,
					fmt.Sprintf("no complete frame dump of the node after it recorded the %s", what)))
			default:
				out.Emit(check.Pass(reqNoReprepare, b.e, fmt.Sprintf("the node sent no PREPARE or COMMIT for the %s after recording it", what)))
			}
		}
	}
	return nil
}

// above counts the bad blocks of the node above b's height recorded by t.
func above(bs []*badRec, b *badRec, t time.Time) int {
	n := 0
	for _, o := range bs {
		if o != b && !o.at.After(t) && check.Cmp(o.num, b.num) > 0 {
			n++
		}
	}
	return n
}
