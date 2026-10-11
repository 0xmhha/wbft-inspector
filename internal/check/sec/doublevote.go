// Package sec holds the checkers of the security requirements (wbft-spec
// A-10) and of the state-machine requirements on signing that need the
// signer of a message.
package sec

import (
	"context"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noDoubleVote{check.Base{ID: "sec.no_double_vote", Reqs: []string{reqNoDoubleVote}, Kinds: []check.Kind{check.Frames}}})
}

const reqNoDoubleVote = "WBFT-SM-083"

// noDoubleVote decides WBFT-SM-083 from frame dumps: within one run, an
// honest node does not send two PREPAREs, or two COMMITs, with different
// digests for one view. It reads the node's own sent frames: for each
// PREPARE and COMMIT the node sent in a run, it recovers the signer from
// the payload and keeps the frames the node signed itself (a relay carries
// another validator's message).
//
// One instance per (run, view, code) the node signed: it fails when the
// run's frames of that view and code carry two digests, and passes
// otherwise. Across runs the property does not hold (WBFT-SM-007), so runs
// are judged apart. A frame recorded without its payload, or whose payload
// does not decode, is left out; a view with only such frames leaves no
// instance.
type noDoubleVote struct{ check.Base }

type voteKey struct {
	seq, round string
	code       uint64
}

func (c noDoubleVote) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		cache := map[string]*message.Message{} // code and payload sha256 -> decoded, nil when it does not decode
		for _, recs := range check.FrameRuns(d) {
			c.run(d, recs, cache, out)
		}
	}
	return nil
}

func (c noDoubleVote) run(d *frames.Dump, recs []*frames.Record, cache map[string]*message.Message, out check.Emitter) {
	first := map[voteKey]*frames.Record{}
	digests := map[voteKey]map[string]*frames.Record{}
	var order []voteKey
	for _, r := range recs {
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
		k := voteKey{seq: m.Sequence.String(), round: m.Round.String(), code: code}
		if digests[k] == nil {
			digests[k] = map[string]*frames.Record{}
			first[k] = r
			order = append(order, k)
		}
		dg := hex.EncodeToString(m.Digest[:])
		if _, ok := digests[k][dg]; !ok {
			digests[k][dg] = r
		}
	}
	for _, k := range order {
		name := map[uint64]string{message.CodePrepare: "PREPARE", message.CodeCommit: "COMMIT"}[k.code]
		ds := digests[k]
		if len(ds) == 1 {
			out.Emit(check.FrameInstance(reqNoDoubleVote, first[k], verdict.Pass, "",
				fmt.Sprintf("the node sent %s for (%s, %s) with one digest in this run", name, k.seq, k.round)))
			continue
		}
		// The first frame with a second digest anchors the failure.
		var second *frames.Record
		for _, r := range ds {
			if r != first[k] && (second == nil || r.Seq < second.Seq) {
				second = r
			}
		}
		inst := check.FrameInstance(reqNoDoubleVote, second, verdict.Fail, "",
			fmt.Sprintf("the node sent %s for (%s, %s) with %d different digests in one run", name, k.seq, k.round, len(ds)))
		inst.Evidence = append(inst.Evidence, check.FramePointer(first[k]))
		out.Emit(inst)
	}
}
