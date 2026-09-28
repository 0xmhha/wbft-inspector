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
	check.Register(roundTimerOnEntry{check.Base{ID: "sm.round_timer_on_entry", Reqs: []string{"WBFT-SM-030", "WBFT-TIMER-010"}, Kinds: ev}})
	check.Register(acceptOrder{check.Base{ID: "sm.accept_preprepare_order", Reqs: []string{"WBFT-SM-039", "WBFT-TIMER-012"}, Kinds: ev}})
	check.Register(preparedTransition{check.Base{ID: "sm.prepared_transition", Reqs: []string{"WBFT-SM-043"}, Kinds: ev}})
	check.Register(decideOnCommitQuorum{check.Base{ID: "sm.decide_on_commit_quorum", Reqs: []string{"WBFT-SM-046"}, Kinds: ev}})
	check.Register(timerNotStoppedOnDecide{check.Base{ID: "sm.timer_not_stopped_on_decide", Reqs: []string{"WBFT-SM-050", "WBFT-TIMER-016"}, Kinds: ev}})
	check.Register(fPlusOne{check.Base{ID: "sm.f_plus_one", Reqs: []string{"WBFT-SM-057"}, Kinds: ev}})
}

func roundArm(v *events.View) func(*events.Event) bool {
	return func(x *events.Event) bool {
		return x.Kind == "TIMER_ARM" && x.Str("timer") == events.TimerRound && x.View.Equal(v)
	}
}

func stateTo(to string) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.Kind == "STATE" && x.Str("to") == to }
}

func quorum(what string) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.Kind == "QUORUM" && x.Str("what") == what }
}

// cancelled reports whether the step cancels timer tm explicitly.
func cancelled(s check.Step, tm *events.Timer) bool {
	return s.Has(func(x *events.Event) bool {
		g, _ := x.Int("gen")
		return x.Kind == "TIMER_CANCEL" && x.Str("timer") == tm.Kind && g == tm.Gen
	})
}

// fired reports whether the step records the expiry of timer tm.
func fired(s check.Step, tm *events.Timer) bool {
	return s.Has(func(x *events.Event) bool {
		g, _ := x.Int("gen")
		return x.Kind == "TIMER_FIRE" && x.Str("timer") == tm.Kind && g == tm.Gen
	})
}

// durationCheck compares the duration of a round-timer arm with
// round_timeout(config_at(h), r).
func durationCheck(in *check.Inputs, arm *events.Event) (verdict.Verdict, string) {
	want, _, ok := in.RoundTimeout(arm.View)
	if !ok {
		return verdict.CannotDecide, "no chain configuration; the duration cannot be computed (give --chain-config)"
	}
	got, _ := arm.Int("duration_ms")
	if got != check.DurationMs(want) {
		return verdict.Fail, fmt.Sprintf("round timer of %s armed for %d ms, round_timeout gives %d ms", arm.View, got, check.DurationMs(want))
	}
	return verdict.Pass, fmt.Sprintf("round timer of %s armed for %d ms", arm.View, got)
}

// roundTimerOnEntry decides WBFT-SM-030 and WBFT-TIMER-010: entering a view
// arms the round timer of that view, from the moment of entering, and stops
// the retry and future-proposal timers. Arming replaces an armed round
// timer; retry and future timers armed before the step must be cancelled.
type roundTimerOnEntry struct{ check.Base }

func (c roundTimerOnEntry) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	var tr check.StepStart
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		before := tr.Observe(r, i, st)
		if e.Kind != "ROUND_ENTER" || e.View == nil {
			return
		}
		s := check.StepOf(r, i)
		_, arm := s.Find(i, roundArm(e.View))
		var left []string
		for _, kind := range []string{events.TimerRetry, events.TimerFuture} {
			if tm := before[kind]; tm != nil && !tm.Expired(e.TMono) && !cancelled(s, tm) && !fired(s, tm) {
				left = append(left, fmt.Sprintf("%s timer gen %d", kind, tm.Gen))
			}
		}
		switch {
		case arm == nil:
			msg := "entered " + e.View.String() + " without arming its round timer"
			out.Emit(check.Fail("WBFT-SM-030", e, msg))
			out.Emit(check.Fail("WBFT-TIMER-010", e, msg))
			return
		case len(left) > 0:
			out.Emit(check.Fail("WBFT-SM-030", e, fmt.Sprintf("entered %s but did not stop %v", e.View, left), arm))
		default:
			out.Emit(check.Pass("WBFT-SM-030", e, "round timer armed on entering "+e.View.String(), arm))
		}
		if arm.TMono != e.TMono {
			out.Emit(check.Fail("WBFT-TIMER-010", e, fmt.Sprintf("round timer armed %d ns after entering the view", arm.TMono-e.TMono), arm))
			return
		}
		v, msg := durationCheck(in, arm)
		out.Emit(check.New("WBFT-TIMER-010", e, v, verdict.MissingData, msg, arm))
	})
	return nil
}

// acceptOrder decides WBFT-SM-039 and WBFT-TIMER-012: on accepting a
// PRE-PREPARE the node restarts the round timer with the full duration,
// then sets the proposal, enters Preprepared and broadcasts its PREPARE, in
// this order.
type acceptOrder struct{ check.Base }

func (c acceptOrder) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	member := check.Members(in)
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if e.Kind != "PREPREPARE_ACCEPT" || e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		ai, arm := s.FindBefore(i, roundArm(e.View))
		si, state := s.Find(i, stateTo("Preprepared"))
		_, send := s.Find(si, func(x *events.Event) bool { return x.IsSend(events.CodePrepare, "broadcast") })
		_, early := s.FindBefore(ai, func(x *events.Event) bool { return x.IsSend(events.CodePrepare, "broadcast") })
		switch {
		case arm == nil:
			out.Emit(check.Fail("WBFT-SM-039", e, "PRE-PREPARE accepted without restarting the round timer first"))
		case state == nil:
			out.Emit(check.Fail("WBFT-SM-039", e, "PRE-PREPARE accepted without entering Preprepared", arm))
		case early != nil:
			out.Emit(check.Fail("WBFT-SM-039", e, "PREPARE sent before the round timer was restarted", early, arm))
		case send == nil:
			out.Emit(check.MissingSend("WBFT-SM-039", e, s, member, e.View.Seq, "PREPARE", arm, state))
		default:
			out.Emit(check.Pass("WBFT-SM-039", e, "timer restart, Preprepared, PREPARE in order", arm, state, send))
		}
		if arm == nil {
			out.Emit(check.Fail("WBFT-TIMER-012", e, "round timer not re-armed on accepting the PRE-PREPARE"))
			return
		}
		if arm.TMono != e.TMono {
			out.Emit(check.Fail("WBFT-TIMER-012", e, "round timer re-armed at another moment than the acceptance", arm))
			return
		}
		v, msg := durationCheck(in, arm)
		out.Emit(check.New("WBFT-TIMER-012", e, v, verdict.MissingData, msg, arm))
	})
	return nil
}

// preparedTransition decides WBFT-SM-043: a PREPARE quorum (count >= Q)
// makes the node enter Prepared and broadcast its COMMIT, in this order;
// and Prepared is entered only on a PREPARE quorum.
type preparedTransition struct{ check.Base }

func (c preparedTransition) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-043"
	member := check.Members(in)
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		switch {
		case e.Kind == "QUORUM" && e.Str("what") == "PREPARE":
			n, _ := e.Int("count")
			q, _ := e.Int("quorum")
			si, state := s.Find(i, stateTo("Prepared"))
			_, send := s.Find(si, func(x *events.Event) bool { return x.IsSend(events.CodeCommit, "broadcast") })
			switch {
			case n < q:
				out.Emit(check.Fail(req, e, fmt.Sprintf("PREPARE quorum reported with %d of %d", n, q)))
			case state == nil:
				out.Emit(check.Fail(req, e, "PREPARE quorum without entering Prepared"))
			case send == nil:
				out.Emit(check.MissingSend(req, e, s, member, e.View.Seq, "COMMIT", state))
			default:
				out.Emit(check.Pass(req, e, "Prepared, then COMMIT", state, send))
			}
		case e.Kind == "STATE" && e.Str("to") == "Prepared":
			if _, q := s.FindBefore(i, quorum("PREPARE")); q == nil {
				out.Emit(check.Fail(req, e, "entered Prepared without a PREPARE quorum"))
			}
		}
	})
	return nil
}

// decideOnCommitQuorum decides WBFT-SM-046: a COMMIT quorum (count >= Q)
// runs decide, which enters Committed; and Committed is entered only then.
type decideOnCommitQuorum struct{ check.Base }

func (c decideOnCommitQuorum) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-046"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		switch {
		case e.Kind == "QUORUM" && e.Str("what") == "COMMIT":
			n, _ := e.Int("count")
			q, _ := e.Int("quorum")
			_, state := s.Find(i, stateTo("Committed"))
			switch {
			case n < q:
				out.Emit(check.Fail(req, e, fmt.Sprintf("COMMIT quorum reported with %d of %d", n, q)))
			case state == nil:
				out.Emit(check.Fail(req, e, "COMMIT quorum without deciding (no Committed state)"))
			default:
				out.Emit(check.Pass(req, e, "decided", state))
			}
		case e.Kind == "STATE" && e.Str("to") == "Committed":
			if _, q := s.FindBefore(i, quorum("COMMIT")); q == nil {
				out.Emit(check.Fail(req, e, "entered Committed without a COMMIT quorum"))
			}
		}
	})
	return nil
}

// legitRoundCancel reports whether a round-timer cancel in step s is one of
// the allowed ones: a view change, a PRE-PREPARE acceptance (both re-arm
// the timer) or an engine stop.
func legitRoundCancel(s check.Step) bool {
	return s.Has(func(x *events.Event) bool {
		return x.Kind == "ROUND_ENTER" || x.Kind == "PREPREPARE_ACCEPT" || (x.Kind == "TIMER_ARM" && x.Str("timer") == events.TimerRound)
	}) || s.FollowedByStop()
}

// timerNotStoppedOnDecide decides WBFT-SM-050 and WBFT-TIMER-016: after
// deciding, the round timer of the decided view keeps running until a view
// change, its own expiry or an engine stop.
type timerNotStoppedOnDecide struct{ check.Base }

func (c timerNotStoppedOnDecide) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	emit := func(v verdict.Verdict, reason verdict.Reason, e *events.Event, msg string, more ...*events.Event) {
		out.Emit(check.New("WBFT-SM-050", e, v, reason, msg, more...))
		out.Emit(check.New("WBFT-TIMER-016", e, v, reason, msg, more...))
	}
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Kind != "STATE" || e.Str("to") != "Committed" {
			return
		}
		tm := st.Armed[events.TimerRound]
		if tm == nil {
			emit(verdict.CannotDecide, verdict.InconsistentInput, e, "no round timer armed at the decision")
			return
		}
		for j := i + 1; j < len(r.Events); j++ {
			x := r.Events[j]
			g, _ := x.Int("gen")
			switch {
			case x.Kind == "TIMER_CANCEL" && x.Str("timer") == events.TimerRound && g == tm.Gen:
				if legitRoundCancel(check.StepOf(r, j)) {
					emit(verdict.Pass, "", e, "round timer kept until it was replaced", x)
				} else {
					emit(verdict.Fail, "", e, "round timer cancelled after the decision without a view change or engine stop", x)
				}
				return
			case x.Kind == "TIMER_FIRE" && x.Str("timer") == events.TimerRound && g == tm.Gen:
				emit(verdict.Pass, "", e, "round timer expired after the decision", x)
				return
			case x.Kind == "ROUND_ENTER" || x.Kind == "ENGINE_STOP":
				emit(verdict.Pass, "", e, "round timer running until "+x.Kind, x)
				return
			}
		}
		emit(verdict.CannotDecide, verdict.MissingData, e, "the stream ends after the decision")
	})
	return nil
}

// fPlusOne decides WBFT-SM-057: when the F+1 rule fires the node runs
// start_new_round and then broadcasts a ROUND-CHANGE, and does not evaluate
// the ROUND-CHANGE quorum rule for that message; a view change with the
// cause f_plus_one needs the rule to have fired.
type fPlusOne struct{ check.Base }

func (c fPlusOne) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-057"
	member := check.Members(in)
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		switch {
		case e.Kind == "QUORUM" && e.Str("what") == "F_PLUS_ONE":
			ri, enter := s.Find(i, func(x *events.Event) bool { return x.Kind == "ROUND_ENTER" && x.Str("cause") == "f_plus_one" })
			_, send := s.Find(ri, func(x *events.Event) bool { return x.IsSend(events.CodeRoundChange, "broadcast") })
			_, rcq := s.Find(i, quorum("ROUND_CHANGE"))
			switch {
			case enter == nil:
				out.Emit(check.Fail(req, e, "F+1 rule fired without start_new_round"))
			case rcq != nil:
				out.Emit(check.Fail(req, e, "the ROUND-CHANGE quorum rule was evaluated after the F+1 rule fired", rcq))
			case send == nil:
				out.Emit(check.MissingSend(req, e, s, member, enter.View.Seq, "ROUND-CHANGE", enter))
			default:
				out.Emit(check.Pass(req, e, "start_new_round to "+enter.View.String()+", then ROUND-CHANGE", enter, send))
			}
		case e.Kind == "ROUND_ENTER" && e.Str("cause") == "f_plus_one":
			if _, q := s.FindBefore(i, quorum("F_PLUS_ONE")); q == nil {
				out.Emit(check.Fail(req, e, "view change with cause f_plus_one without the F+1 rule firing"))
			}
		}
	})
	return nil
}
