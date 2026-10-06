package sm

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	ev := []check.Kind{check.Events}
	check.Register(retryRC{check.Base{ID: "sm.retry_rc", Reqs: []string{"WBFT-SM-077", "WBFT-TIMER-021", "WBFT-TIMER-022"}, Kinds: ev, ReadsLogs: true}})
	check.Register(firstRCCause{check.Base{ID: "sm.first_rc_cause", Reqs: []string{"WBFT-SM-089"}, Kinds: ev}})
}

func isRC(causes ...string) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.IsSend(events.CodeRoundChange, causes...) }
}

func retryArm(x *events.Event) bool {
	return x.Kind == "TIMER_ARM" && x.Str("timer") == events.TimerRetry
}

// retryRC decides WBFT-SM-077, WBFT-TIMER-021 and WBFT-TIMER-022: an expiry
// of the retry timer that remembers round r_c runs the ROUND-CHANGE
// broadcast procedure with target r_c. If the current round is not greater
// than r_c it sends a ROUND-CHANGE (cause retry) and re-arms the retry
// timer; otherwise it sends nothing and re-arms the retry timer for the
// current round.
type retryRC struct{ check.Base }

func (c retryRC) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	targets := map[[3]string]string{} // run, engine run, gen -> remembered round
	member := check.Members(in)
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		run, _ := e.Int("engine_run")
		gen, _ := e.Int("gen")
		k := [3]string{r.ID, fmt.Sprint(run), fmt.Sprint(gen)}
		if retryArm(e) {
			targets[k] = e.Str("target_round")
			return
		}
		if e.Kind != "TIMER_FIRE" || e.Str("timer") != events.TimerRetry || e.Step == nil {
			return
		}
		target := targets[k]
		if target == "" && e.View != nil {
			target = e.View.Round
		}
		if st.View == nil || target == "" {
			for _, req := range []string{"WBFT-SM-077", "WBFT-TIMER-021", "WBFT-TIMER-022"} {
				out.Emit(check.Undecided(req, e, verdict.MissingData, "the current view or the remembered round is unknown"))
			}
			return
		}
		s := check.StepOf(r, i)
		_, send := s.Find(i, isRC("retry", "broadcast"))
		_, arm := s.Find(i, retryArm)
		cur := st.View.Round
		if check.Cmp(cur, target) <= 0 {
			switch {
			case send == nil:
				what := fmt.Sprintf("ROUND-CHANGE for round %s (retry expiry in round %s)", target, cur)
				out.Emit(check.MissingSend("WBFT-SM-077", e, s, member, st.View.Seq, what))
				out.Emit(check.MissingSend("WBFT-TIMER-021", e, s, member, st.View.Seq, what))
			case arm == nil:
				out.Emit(check.Pass("WBFT-SM-077", e, "ROUND-CHANGE re-sent", send))
				out.Emit(check.Fail("WBFT-TIMER-021", e, "ROUND-CHANGE re-sent without re-arming the retry timer", send))
			default:
				out.Emit(check.Pass("WBFT-SM-077", e, "ROUND-CHANGE re-sent", send))
				out.Emit(check.Pass("WBFT-TIMER-021", e, fmt.Sprintf("ROUND-CHANGE re-sent for round %s, retry timer re-armed", target), send, arm))
			}
			return
		}
		// The current round is above r_c (WBFT-TIMER-022).
		switch {
		case send != nil:
			msg := fmt.Sprintf("retry expiry for past round %s sent a ROUND-CHANGE in round %s", target, cur)
			out.Emit(check.Fail("WBFT-SM-077", e, msg, send))
			out.Emit(check.Fail("WBFT-TIMER-022", e, msg, send))
		case arm == nil:
			msg := "retry expiry for a past round did not re-arm the retry timer"
			out.Emit(check.Fail("WBFT-SM-077", e, msg))
			out.Emit(check.Fail("WBFT-TIMER-022", e, msg))
		case arm.Str("target_round") != cur:
			out.Emit(check.Pass("WBFT-SM-077", e, "broadcast procedure ran", arm))
			out.Emit(check.Fail("WBFT-TIMER-022", e, fmt.Sprintf("retry timer re-armed for round %s, current round %s", arm.Str("target_round"), cur), arm))
		default:
			out.Emit(check.Pass("WBFT-SM-077", e, "broadcast procedure ran and sent nothing for a past round", arm))
			out.Emit(check.Pass("WBFT-TIMER-022", e, "no ROUND-CHANGE for past round "+target+", retry re-armed for round "+cur, arm))
		}
	})
	return nil
}

// firstRCCause decides WBFT-SM-089: a node sends a ROUND-CHANGE of its own
// (cause broadcast; retries are cause retry) only when its round timer
// expired at least round_timeout after it was armed (the later of entering
// the round and accepting a PRE-PREPARE in it), when the F+1 rule fired, or
// when its finalize failed (a ROUND-CHANGE in the step of the COMMIT quorum
// without a hand-over of the block). The late-timeout CATCH_UP case is a
// round-timer expiry too.
type firstRCCause struct{ check.Base }

func (c firstRCCause) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-089"
	live := map[*events.Event]*events.Timer{} // round-timer expiries and the live timer they belong to
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Kind == "TIMER_FIRE" && e.Str("timer") == events.TimerRound {
			gen, _ := e.Int("gen")
			if tm := st.Armed[events.TimerRound]; tm != nil && tm.Gen == gen {
				live[e] = tm
			}
			return
		}
		if !e.IsSend(events.CodeRoundChange, "broadcast") || e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		if _, f := s.FindBefore(i, quorum("F_PLUS_ONE")); f != nil {
			out.Emit(check.Pass(req, e, "cause: F+1 rule", f))
			return
		}
		if _, q := s.FindBefore(i, quorum("COMMIT")); q != nil && !s.Has(check.IsKind("FINALIZE_HANDOVER")) {
			out.Emit(check.Pass(req, e, "cause: finalize failed", q))
			return
		}
		_, fire := s.FindBefore(i, func(x *events.Event) bool { return x.Kind == "TIMER_FIRE" && x.Str("timer") == events.TimerRound })
		if fire == nil {
			out.Emit(check.Fail(req, e, "ROUND-CHANGE sent without a round-timer expiry, F+1 rule or finalize failure"))
			return
		}
		tm := live[fire]
		if tm == nil {
			out.Emit(check.Fail(req, e, "ROUND-CHANGE sent on the expiry of a cancelled or superseded round timer", fire))
			return
		}
		d, t := fire.TMono-tm.ArmMono, tm.DurationMs*1_000_000
		switch in.Clock.AtLeast(d, t) {
		case verdict.Pass:
			out.Emit(check.Pass(req, e, fmt.Sprintf("cause: round timer of %s expired after %d ms (timeout %d ms)", tm.View, d/1_000_000, tm.DurationMs), fire))
		case verdict.Fail:
			out.Emit(check.Fail(req, e, fmt.Sprintf("round timer of %s expired after %d ms, before its timeout of %d ms", tm.View, d/1_000_000, tm.DurationMs), fire))
		default:
			out.Emit(check.Undecided(req, e, verdict.ClockUncertainty, fmt.Sprintf("expiry after %d ns is within the clock tolerance of the timeout %d ms", d, tm.DurationMs), fire))
		}
	})
	return nil
}
