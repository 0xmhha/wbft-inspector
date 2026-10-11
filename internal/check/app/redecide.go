package app

import (
	"context"
	"fmt"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(noRedecideBadBlock{check.Base{ID: "app.no_redecide_bad_block", Reqs: []string{reqNoRedecide},
		Kinds: []check.Kind{check.Events}}})
}

const reqNoRedecide = "WBFT-APP-100"

// noRedecideBadBlock decides WBFT-APP-100 from the event stream: after a
// finalized block fails import, consensus does not decide that block again
// at the same height and continues the height through a ROUND-CHANGE
// started by its round timer.
//
// The failure is an IMPORT_FAIL with path sealed_locally (the node's own
// finalized block failed import) or a COMMIT_RESULT with ok false (the
// application refused the finalized block). One instance per block X and
// height h of a run, at its first such record. The records after it are
// read until the height ends (a NEW_HEAD at h or above) or the run ends:
//
//   - FINALIZE_HANDOVER of X at h, or NEW_HEAD of X at h: FAIL, the block
//     was decided again or became the head;
//   - the first ROUND_ENTER at h above the round of the failure: PASS when
//     its cause is timeout or f_plus_one (the round timer, or the F+1 rule
//     after the peers' timers), FAIL when it is finalize_fail (a round
//     change on the failure itself, not by the round timer);
//   - the height ending with another block before such a round: PASS;
//   - the run ending first: undecided (MISSING_DATA).
//
// The round of the failure is that of the last ROUND_ENTER at h before the
// failure record; without one, any ROUND_ENTER at h after it counts.
type noRedecideBadBlock struct{ check.Base }

func (c noRedecideBadBlock) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, r := range in.Events.Runs {
		seen := map[[2]string]bool{}
		for i, e := range r.Events {
			switch e.Kind {
			case "COMMIT_RESULT":
				if ok, has := e.Bool("ok"); !has || ok {
					continue
				}
			case "IMPORT_FAIL":
				if e.Str("path") != "sealed_locally" {
					continue
				}
			default:
				continue
			}
			k := [2]string{e.Str("number"), strings.ToLower(e.Str("hash"))}
			if seen[k] {
				continue
			}
			seen[k] = true
			out.Emit(c.judge(r, i, e))
		}
	}
	return nil
}

func (c noRedecideBadBlock) judge(r *events.Run, i int, e *events.Event) verdict.Instance {
	h, x := e.Str("number"), strings.ToLower(e.Str("hash"))
	what := fmt.Sprintf("finalized block %s at height %s failed import", x, h)
	round := ""
	for j := i - 1; j >= 0; j-- {
		if p := r.Events[j]; p.Kind == "ROUND_ENTER" && p.View != nil && p.View.Seq == h {
			round = p.View.Round
			break
		}
	}
	var next *events.Event // the first ROUND_ENTER at h above round
	for _, f := range r.Events[i+1:] {
		switch f.Kind {
		case "FINALIZE_HANDOVER":
			if f.Str("number") == h && strings.ToLower(f.Str("hash")) == x {
				return check.Fail(reqNoRedecide, e, what+"; consensus decided it again at the same height", f)
			}
		case "NEW_HEAD":
			if check.Cmp(f.Str("number"), h) < 0 {
				continue
			}
			if f.Str("number") == h && strings.ToLower(f.Str("hash")) == x {
				return check.Fail(reqNoRedecide, e, what+"; it became the head", f)
			}
			if next == nil {
				return check.Pass(reqNoRedecide, e, what+"; the height ended with another block before a round change", f)
			}
			return c.continued(e, next, what)
		case "ROUND_ENTER":
			if next == nil && f.View != nil && f.View.Seq == h && (round == "" || check.Cmp(f.View.Round, round) > 0) {
				next = f
			}
		}
	}
	if next != nil {
		return c.continued(e, next, what)
	}
	return check.Undecided(reqNoRedecide, e, verdict.MissingData, what+"; the run ends before the height continues")
}

// continued judges the first round change at the height after the failure.
func (c noRedecideBadBlock) continued(e, next *events.Event, what string) verdict.Instance {
	cause := next.Str("cause")
	msg := fmt.Sprintf("%s; the height continued in round %s (cause %s)", what, next.View.Round, cause)
	switch cause {
	case "timeout", "f_plus_one":
		return check.Pass(reqNoRedecide, e, msg, next)
	case "finalize_fail":
		return check.Fail(reqNoRedecide, e, msg+", not by the round timer", next)
	}
	return check.Undecided(reqNoRedecide, e, verdict.InconsistentInput, msg+", which is not a round change", next)
}
