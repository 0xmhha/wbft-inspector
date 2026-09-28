// Package timer holds the checkers of wbft-spec A-06 (timers) that decide
// from consensus event streams and, for durations, the chain configuration.
package timer

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/spec/timers"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	ev := []check.Kind{check.Events}
	check.Register(roundTimeout{check.Base{ID: "timer.round_timeout", Reqs: []string{"WBFT-TIMER-002", "WBFT-TIMER-005", "WBFT-TIMER-006", "WBFT-TIMER-007"}, Kinds: ev}})
	check.Register(cancelOnArm{check.Base{ID: "timer.cancel_on_arm", Reqs: []string{"WBFT-TIMER-013", "WBFT-TIMER-033"}, Kinds: ev}})
	check.Register(staleExpiry{check.Base{ID: "timer.stale_expiry", Reqs: []string{"WBFT-TIMER-014"}, Kinds: ev}})
	check.Register(expiryActions{check.Base{ID: "timer.expiry_actions", Reqs: []string{"WBFT-TIMER-015", "WBFT-TIMER-017"}, Kinds: ev}})
	check.Register(stopOnEngineStop{check.Base{ID: "timer.stop_on_engine_stop", Reqs: []string{"WBFT-TIMER-018"}, Kinds: ev}})
	check.Register(retryArm{check.Base{ID: "timer.retry_arm", Reqs: []string{"WBFT-TIMER-003", "WBFT-TIMER-020"}, Kinds: ev}})
	check.Register(retryNotCancelOnQuorum{check.Base{ID: "timer.retry_not_cancel_on_quorum", Reqs: []string{"WBFT-TIMER-023"}, Kinds: ev}})
	check.Register(buildNoWait{check.Base{ID: "timer.build_no_wait_r1", Reqs: []string{"WBFT-TIMER-041"}, Kinds: ev}})
}

func isArm(kind string) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.Kind == "TIMER_ARM" && x.Str("timer") == kind }
}

func gen(e *events.Event) int64 { g, _ := e.Int("gen"); return g }

// roundTimeout decides WBFT-TIMER-005 (the round timer of view (h, r) has
// the duration round_timeout(config_at(h), r)), WBFT-TIMER-002 (the
// parameters are those of config_at(h)), and, where their branch applies,
// WBFT-TIMER-006 (capped branch with base > cap: round 0 lasts base) and
// WBFT-TIMER-007 (capped branch that ends below base: cap). Each arm is an
// instance; the declared duration must equal the computed one, and when the
// timer expires while it is live the measured time from arm to expiry must
// match it within the clock tolerance.
type roundTimeout struct{ check.Base }

func (c roundTimeout) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	type arm struct {
		r    *events.Run
		e    *events.Event
		fire *events.Event
	}
	var arms []*arm
	byEvent := map[*events.Event]*arm{}
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		switch {
		case isArm(events.TimerRound)(e) && e.View != nil:
			a := &arm{r: r, e: e}
			arms = append(arms, a)
			byEvent[e] = a
		case e.Kind == "TIMER_FIRE" && e.Str("timer") == events.TimerRound:
			// Only the expiry of the live timer measures its duration.
			if tm := st.Armed[events.TimerRound]; tm != nil && tm.Gen == gen(e) {
				if a := byEvent[r.Events[tm.ArmIndex]]; a != nil {
					a.fire = e
				}
			}
		}
	})
	for _, a := range arms {
		e := a.e
		want, warn, ok := in.RoundTimeout(e.View)
		if !ok {
			for _, req := range c.Reqs {
				out.Emit(check.Undecided(req, e, verdict.MissingData, "no chain configuration; round_timeout cannot be computed (give --chain-config)"))
			}
			continue
		}
		got, _ := e.Int("duration_ms")
		v, reason := verdict.Pass, verdict.Reason("")
		msg := fmt.Sprintf("round timer of %s: %d ms, round_timeout %d ms", e.View, got, check.DurationMs(want))
		var more []*events.Event
		switch {
		case got != check.DurationMs(want):
			v = verdict.Fail
			msg = fmt.Sprintf("round timer of %s armed for %d ms, round_timeout(config_at(%s), %s) is %d ms", e.View, got, e.View.Seq, e.View.Round, check.DurationMs(want))
		case a.fire != nil:
			more = append(more, a.fire)
			d := a.fire.TMono - e.TMono
			switch in.Clock.Timing(d, want) {
			case verdict.Fail:
				v = verdict.Fail
				msg = fmt.Sprintf("round timer of %s expired %d ms after it was armed, round_timeout is %d ms", e.View, d/1_000_000, check.DurationMs(want))
			case verdict.CannotDecide:
				v, reason = verdict.CannotDecide, verdict.ClockUncertainty
				msg = fmt.Sprintf("expiry %d ns after arming is within the clock tolerance of %d ns", d, want)
			default:
				msg += fmt.Sprintf(", expired after %d ms", d/1_000_000)
			}
		}
		out.Emit(check.New("WBFT-TIMER-005", e, v, reason, msg, more...))
		out.Emit(check.New("WBFT-TIMER-002", e, v, reason, msg, more...))
		cfg := in.Config.At(e.View.SeqBig())
		base := int64(cfg.RequestTimeoutMs) * 1_000_000
		limit := int64(cfg.MaxRequestTimeoutSeconds) * 1_000_000_000
		if limit > 0 && base > limit {
			out.Emit(check.New("WBFT-TIMER-006", e, v, reason, msg, more...))
		}
		if warn == timers.WarnCapGuard {
			out.Emit(check.New("WBFT-TIMER-007", e, v, reason, msg, more...))
		}
	}
	return nil
}

// cancelOnArm decides WBFT-TIMER-013 and WBFT-TIMER-033: arming or
// re-arming the round timer cancels the retry timer and the
// future-PRE-PREPARE timer. A retry or future timer that was armed when the
// step began, and did not expire in it, must be cancelled in the step.
type cancelOnArm struct{ check.Base }

func (c cancelOnArm) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	var ss check.StepStart
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		before := ss.Observe(r, i, st)
		if !isArm(events.TimerRound)(e) {
			return
		}
		s := check.StepOf(r, i)
		for _, kind := range []string{events.TimerRetry, events.TimerFuture} {
			tm := before[kind]
			if tm == nil || tm.Expired(e.TMono) || stepHas(s, "TIMER_FIRE", tm) {
				continue // not armed, or its expiry is already queued and cannot be cancelled
			}
			msg := fmt.Sprintf("%s timer gen %d", kind, tm.Gen)
			var inst verdict.Instance
			if _, x := s.Find(-1, match("TIMER_CANCEL", tm)); x != nil {
				inst = check.Pass("", e, msg+" cancelled with the round-timer arm", x)
			} else {
				inst = check.Fail("", e, msg+" still armed after the round timer was armed")
			}
			inst.Requirement = "WBFT-TIMER-013"
			out.Emit(inst)
			if kind == events.TimerFuture {
				inst.Requirement = "WBFT-TIMER-033"
				out.Emit(inst)
			}
		}
	})
	return nil
}

func match(kind string, tm *events.Timer) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.Kind == kind && x.Str("timer") == tm.Kind && gen(x) == tm.Gen }
}

func stepHas(s check.Step, kind string, tm *events.Timer) bool { return s.Has(match(kind, tm)) }

// staleExpiry decides WBFT-TIMER-014: within one run of the core, the
// expiry of a round timer that was cancelled or superseded changes no view
// and sends nothing. Expiries of timers of an earlier engine run are the
// subject of WBFT-TIMER-018.
type staleExpiry struct{ check.Base }

func (c staleExpiry) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-TIMER-014"
	armed := map[[3]string]bool{} // run, engine run, gen of round-timer arms
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		er, _ := e.Int("engine_run")
		k := [3]string{r.ID, fmt.Sprint(er), fmt.Sprint(gen(e))}
		if isArm(events.TimerRound)(e) {
			armed[k] = true
			return
		}
		if e.Kind != "TIMER_FIRE" || e.Str("timer") != events.TimerRound || e.Step == nil {
			return
		}
		if tm := st.Armed[events.TimerRound]; !armed[k] || (tm != nil && tm.Gen == gen(e) && tm.EngineRun == er) {
			return // unknown arm (or one of another engine run), or the live timer
		}
		s := check.StepOf(r, i)
		_, x := s.Find(i, func(x *events.Event) bool {
			return x.Kind == "ROUND_ENTER" || (x.Kind == "SEND" && x.Str("cause") != "relay")
		})
		if x != nil {
			out.Emit(check.Fail(req, e, "expiry of a cancelled or superseded round timer caused "+x.Kind, x))
			return
		}
		out.Emit(check.Pass(req, e, fmt.Sprintf("expiry of superseded round timer gen %d had no effect", gen(e))))
	})
	return nil
}

// expiryActions decides WBFT-TIMER-015 and WBFT-TIMER-017: when the live
// round timer of view (h, r) expires, the node runs start_new_round with
// target r + 1 and then broadcasts a ROUND-CHANGE. If the head has already
// advanced to h, start_new_round takes the CATCH_UP branch and enters
// (h + 1, 0) (WBFT-TIMER-017).
type expiryActions struct{ check.Base }

func (c expiryActions) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	member := check.Members(in)
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Kind != "TIMER_FIRE" || e.Str("timer") != events.TimerRound || e.Step == nil {
			return
		}
		tm := st.Armed[events.TimerRound]
		if tm == nil || tm.Gen != gen(e) || st.View == nil {
			return // not the live timer (WBFT-TIMER-014)
		}
		s := check.StepOf(r, i)
		next := check.Plus(st.View.Round, 1)
		ri, enter := s.Find(i, check.IsKind("ROUND_ENTER"))
		_, send := s.Find(ri, func(x *events.Event) bool { return x.IsSend(events.CodeRoundChange, "broadcast") })
		if enter == nil || enter.Str("requested_round") != next {
			msg := "round-timer expiry in " + st.View.String() + " without start_new_round(" + next + ")"
			out.Emit(check.Fail("WBFT-TIMER-015", e, msg, enter))
			return
		}
		req := "WBFT-TIMER-015"
		if enter.Str("branch") == "CATCH_UP" {
			// The head advanced before the new-head event was processed.
			if enter.View.Round != "0" || check.Cmp(enter.View.Seq, st.View.Seq) <= 0 {
				out.Emit(check.Fail("WBFT-TIMER-017", e, "late expiry entered "+enter.View.String()+", want (h+1, 0)", enter))
				return
			}
			req = "WBFT-TIMER-017"
		}
		var inst verdict.Instance
		if send == nil {
			inst = check.MissingSend("", e, s, member, enter.View.Seq, "ROUND-CHANGE", enter)
		} else {
			inst = check.Pass("", e, "start_new_round("+next+") entered "+enter.View.String()+", then ROUND-CHANGE", enter, send)
		}
		inst.Requirement = "WBFT-TIMER-015"
		out.Emit(inst)
		if req == "WBFT-TIMER-017" {
			inst.Requirement = req
			out.Emit(inst)
		}
	})
	return nil
}

// stopOnEngineStop decides WBFT-TIMER-018: stopping the engine cancels the
// round, retry and future timers, and the node sends nothing while the
// engine is stopped. A timer armed after the cancellations of the stop (the
// reference arms one in that gap and does not cancel it) is allowed.
type stopOnEngineStop struct{ check.Base }

func (c stopOnEngineStop) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-TIMER-018"
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Kind != "ENGINE_STOP" {
			return
		}
		firstCancel := -1
		for j := i - 1; j >= 0; j-- {
			if r.Events[j].Step != nil {
				if _, x := check.StepOf(r, j).Find(-1, check.IsKind("TIMER_CANCEL")); x != nil {
					firstCancel, _ = check.StepOf(r, j).Find(-1, check.IsKind("TIMER_CANCEL"))
				}
				break
			}
		}
		var left []string
		for _, kind := range []string{events.TimerRound, events.TimerRetry, events.TimerFuture} {
			if tm := st.Armed[kind]; tm != nil && (firstCancel < 0 || tm.ArmIndex < firstCancel) {
				left = append(left, fmt.Sprintf("%s gen %d", kind, tm.Gen))
			}
		}
		if len(left) > 0 {
			out.Emit(check.Fail(req, e, fmt.Sprintf("engine stopped with timers still armed: %v", left)))
			return
		}
		for _, x := range r.Events[i+1:] {
			if x.Kind == "ENGINE_START" {
				break
			}
			if x.Kind == "SEND" || x.Kind == "ROUND_ENTER" {
				out.Emit(check.Fail(req, e, x.Kind+" while the engine was stopped", x))
				return
			}
		}
		out.Emit(check.Pass(req, e, "timers cancelled at the stop and nothing sent while stopped"))
	})
	return nil
}

// retryArm decides WBFT-TIMER-020 and WBFT-TIMER-003: every invocation of
// the ROUND-CHANGE broadcast procedure arms a new retry timer (replacing an
// armed one) with duration RT(h) = requestTimeoutSeconds x 1000 ms, no
// doubling and no cap, remembering the current round; every ROUND-CHANGE
// the node sends comes with such an arm in its step.
type retryArm struct{ check.Base }

func (c retryArm) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		switch {
		case isArm(events.TimerRetry)(e):
			target := e.Str("target_round")
			if st.View == nil || target != st.View.Round {
				cur := "unknown"
				if st.View != nil {
					cur = st.View.Round
				}
				msg := fmt.Sprintf("retry timer remembers round %s, current round %s", target, cur)
				out.Emit(check.Fail("WBFT-TIMER-020", e, msg))
				return
			}
			ms, ok := in.RetryTimeoutMs(e.View)
			if !ok {
				msg := "no chain configuration; RT(h) cannot be computed (give --chain-config)"
				out.Emit(check.Undecided("WBFT-TIMER-020", e, verdict.MissingData, msg))
				out.Emit(check.Undecided("WBFT-TIMER-003", e, verdict.MissingData, msg))
				return
			}
			want := check.DurationMs(int64(ms) * 1_000_000)
			got, _ := e.Int("duration_ms")
			if got != want {
				msg := fmt.Sprintf("retry timer of %s armed for %d ms, RT(h) is %d ms", e.View, got, want)
				out.Emit(check.Fail("WBFT-TIMER-020", e, msg))
				out.Emit(check.Fail("WBFT-TIMER-003", e, msg))
				return
			}
			msg := fmt.Sprintf("retry timer of %s: %d ms for round %s", e.View, got, target)
			out.Emit(check.Pass("WBFT-TIMER-020", e, msg))
			out.Emit(check.Pass("WBFT-TIMER-003", e, msg))
		case e.IsSend(events.CodeRoundChange, "broadcast", "retry"):
			if _, a := check.StepOf(r, i).FindBefore(i, isArm(events.TimerRetry)); a == nil {
				out.Emit(check.Fail("WBFT-TIMER-020", e, "ROUND-CHANGE sent without arming the retry timer"))
			}
		}
	})
	return nil
}

// retryNotCancelOnQuorum decides WBFT-TIMER-023: the retry timer is
// cancelled only when the round timer is armed or re-armed, or when the
// engine stops; reaching a PREPARE or COMMIT quorum does not cancel it.
type retryNotCancelOnQuorum struct{ check.Base }

func (c retryNotCancelOnQuorum) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-TIMER-023"
	legit := func(s check.Step) bool { return s.Has(isArm(events.TimerRound)) || s.FollowedByStop() }
	check.Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Step == nil {
			return
		}
		s := check.StepOf(r, i)
		switch {
		case e.Kind == "TIMER_CANCEL" && e.Str("timer") == events.TimerRetry:
			if legit(s) {
				out.Emit(check.Pass(req, e, "retry timer cancelled with a round-timer arm or an engine stop"))
			} else {
				out.Emit(check.Fail(req, e, "retry timer cancelled without a round-timer arm or engine stop"))
			}
		case e.Kind == "QUORUM" && (e.Str("what") == "PREPARE" || e.Str("what") == "COMMIT"):
			tm := st.Armed[events.TimerRetry]
			if tm == nil {
				return
			}
			if _, x := s.Find(-1, match("TIMER_CANCEL", tm)); x != nil && !legit(s) {
				out.Emit(check.Fail(req, e, e.Str("what")+" quorum cancelled the retry timer", x))
				return
			}
			out.Emit(check.Pass(req, e, e.Str("what")+" quorum left the retry timer armed"))
		}
	})
	return nil
}

// buildNoWait decides WBFT-TIMER-041: start_new_round with a requested round
// r >= 1 (including the CATCH_UP case) requests a block build without
// waiting.
type buildNoWait struct{ check.Base }

func (c buildNoWait) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-TIMER-041"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if e.Kind != "ROUND_ENTER" || e.Step == nil || check.Cmp(e.Str("requested_round"), "1") < 0 {
			return
		}
		_, b := check.StepOf(r, i).Find(i, check.IsKind("BUILD_REQUEST"))
		if b == nil {
			out.Emit(check.Fail(req, e, "no build requested on start_new_round("+e.Str("requested_round")+")"))
			return
		}
		if w, _ := b.Int("wait_ms"); w != 0 {
			out.Emit(check.Fail(req, e, fmt.Sprintf("build for round %s waits %d ms", e.Str("requested_round"), w), b))
			return
		}
		out.Emit(check.Pass(req, e, "build for round "+e.Str("requested_round")+" without waiting", b))
	})
	return nil
}
