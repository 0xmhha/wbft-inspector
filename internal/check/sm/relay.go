// Package sm holds the checkers of wbft-spec A-05 (consensus state machine)
// that decide from consensus event streams.
package sm

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(relayOnOK{check.Base{ID: "sm.relay_on_ok", Reqs: []string{"WBFT-SM-011"}, Kinds: []check.Kind{check.Events}}})
	check.Register(relayBacklog{check.Base{ID: "sm.relay_backlog", Reqs: []string{"WBFT-SM-012"}, Kinds: []check.Kind{check.Events}}})
	check.Register(noRelayOnErr{check.Base{ID: "sm.no_relay_on_err", Reqs: []string{"WBFT-SM-013"}, Kinds: []check.Kind{check.Events}}})
	check.Register(selfDelivery{check.Base{ID: "sm.self_delivery", Reqs: []string{"WBFT-SM-014"}, Kinds: []check.Kind{check.Events}}})
	check.Register(disposition{check.Base{ID: "sm.disposition", Reqs: []string{"WBFT-SM-020"}, Kinds: []check.Kind{check.Events}}})
}

// outcome reports whether e is a MSG_OUTCOME of a message that reached the
// core (not dropped by the receive checks before it) through via.
func outcome(e *events.Event, via string) bool {
	return e.Kind == "MSG_OUTCOME" && e.Step != nil && e.Str("check") != "prefilter" && (via == "" || e.Str("via") == via)
}

func relaySend(code int64) func(*events.Event) bool {
	return func(x *events.Event) bool { return x.IsSend(code, "relay") }
}

// relayOnOK decides WBFT-SM-011: a message received from a peer whose
// processing returned OK (outcome ACCEPT) is relayed unchanged.
//
// The event stream records a relay only when at least one target is left
// after the target filtering of A-07 (peers known to hold the message), so
// a missing relay record is undecided, not a failure. A relay of the same
// code in the same step with other bytes (another dedup key) fails: the
// payload must be relayed unchanged.
type relayOnOK struct{ check.Base }

func (c relayOnOK) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-011"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if !outcome(e, "direct") || e.Str("outcome") != "ACCEPT" {
			return
		}
		st := check.StepOf(r, i)
		key := e.Str("dedup_key")
		_, same := st.Find(-1, func(x *events.Event) bool { return x.IsSend(e.Code(), "relay") && x.Str("dedup_key") == key })
		if same != nil {
			out.Emit(check.Pass(req, e, "relayed with the received bytes", same))
			return
		}
		if _, other := st.Find(-1, relaySend(e.Code())); other != nil {
			out.Emit(check.Fail(req, e, "relayed with other bytes than received (dedup key "+other.Str("dedup_key")+", received "+key+")", other))
			return
		}
		out.Emit(check.Undecided(req, e, verdict.ObserverScope, "no relay record; every target may already have held the message (A-07 target filtering)"))
	})
	return nil
}

// relayBacklog decides WBFT-SM-012: a backlog replay whose processing
// returned OK is relayed as rlp_encode(m). The re-encoding may differ from
// the received bytes, so any relay of the code in the step counts.
type relayBacklog struct{ check.Base }

func (c relayBacklog) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-012"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if !outcome(e, "backlog") || e.Str("outcome") != "ACCEPT" {
			return
		}
		if _, s := check.StepOf(r, i).Find(-1, relaySend(e.Code())); s != nil {
			out.Emit(check.Pass(req, e, "backlog replay relayed", s))
			return
		}
		out.Emit(check.Undecided(req, e, verdict.ObserverScope, "no relay record; every target may already have held the message (A-07 target filtering)"))
	})
	return nil
}

// noRelayOnErr decides WBFT-SM-013: a message whose processing returned ERR
// (any outcome but ACCEPT) is not relayed in that step.
type noRelayOnErr struct{ check.Base }

func (c noRelayOnErr) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-013"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if !outcome(e, "") || e.Str("outcome") == "ACCEPT" {
			return
		}
		key := e.Str("dedup_key")
		_, s := check.StepOf(r, i).Find(-1, func(x *events.Event) bool {
			return x.IsSend(e.Code(), "relay") && x.Str("dedup_key") == key
		})
		if s != nil {
			out.Emit(check.Fail(req, e, "a message with outcome "+e.Str("outcome")+" (check "+e.Str("check")+") was relayed", s))
			return
		}
		out.Emit(check.Pass(req, e, "not relayed"))
	})
	return nil
}

// selfDelivery decides WBFT-SM-014: every own message the node broadcasts is
// processed by the node itself through the receive path: a MSG_OUTCOME with
// via "self" and the dedup key of the SEND. Retries repeat the same bytes,
// so sends and self-deliveries of one key are paired in order.
//
// Scheduled events are lost when the engine stops (A-05 Stop), and a stream
// may end before the self-delivery; both leave the instance undecided. A
// send is decided as failed only when the engine went on to process at
// least minLaterSteps further inputs without the self-delivery.
type selfDelivery struct{ check.Base }

const minLaterSteps = 10

func (c selfDelivery) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-014"
	if in.Events == nil {
		return nil
	}
	for _, r := range in.Events.Runs {
		pending := map[string][]int{}
		for i, e := range r.Events {
			switch {
			case e.Kind == "SEND" && (e.Str("cause") == "broadcast" || e.Str("cause") == "retry") && e.Str("dedup_key") != "":
				k := e.Str("dedup_key")
				pending[k] = append(pending[k], i)
			case e.Kind == "MSG_OUTCOME" && e.Str("via") == "self":
				k := e.Str("dedup_key")
				if q := pending[k]; len(q) > 0 {
					pending[k] = q[1:]
					out.Emit(check.Pass(req, r.Events[q[0]], "processed through the receive path (check "+e.Str("check")+")", e))
				}
			}
		}
		for _, q := range pending {
			for _, i := range q {
				out.Emit(unmatched(req, r, i))
			}
		}
	}
	return nil
}

func unmatched(req string, r *events.Run, i int) verdict.Instance {
	e := r.Events[i]
	steps := map[uint64]bool{}
	for j := i + 1; j < len(r.Events); j++ {
		x := r.Events[j]
		if x.Kind == "ENGINE_STOP" {
			return check.Undecided(req, e, verdict.NotExercised, "the engine stopped before the scheduled self-delivery was processed", x)
		}
		if x.Step != nil && *x.Step != *e.Step {
			steps[*x.Step] = true
		}
	}
	if len(steps) >= minLaterSteps {
		return check.Fail(req, e, fmt.Sprintf("never processed by the node itself; the engine processed %d further inputs", len(steps)))
	}
	return check.Undecided(req, e, verdict.MissingData, "the stream ends before a self-delivery of the message")
}

// disposition decides WBFT-SM-020: after check_message a FUTURE message goes
// to the backlog and returns ERR; an EXTRA_SEAL message goes to
// add_extra_seal and returns its result (store or ignore: OK, reject: ERR);
// an OLD, INVALID or TOO_FAR message is discarded with ERR. PROCESS is
// decided by the handler checks.
type disposition struct{ check.Base }

func (c disposition) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	const req = "WBFT-SM-020"
	check.Walk(in, func(r *events.Run, i int, _ *events.State) {
		e := r.Events[i]
		if !outcome(e, "") {
			return
		}
		st := check.StepOf(r, i)
		class, res, src := e.Str("check"), e.Str("outcome"), e.Str("source")
		sameMsg := func(kind string) func(*events.Event) bool {
			return func(x *events.Event) bool {
				return x.Kind == kind && x.Str("source") == src && (kind != "BACKLOG" || x.Code() == e.Code())
			}
		}
		switch class {
		case "FUTURE":
			_, b := st.Find(-1, func(x *events.Event) bool {
				return sameMsg("BACKLOG")(x) && (x.Str("op") == "push" || x.Str("op") == "drop")
			})
			switch {
			case b == nil:
				out.Emit(check.Fail(req, e, "FUTURE message not given to the backlog"))
			case res != "IGNORE":
				out.Emit(check.Fail(req, e, "FUTURE message returned outcome "+res+", want IGNORE (ERR)", b))
			default:
				out.Emit(check.Pass(req, e, "added to the backlog (op "+b.Str("op")+")", b))
			}
		case "EXTRA_SEAL":
			_, x := st.Find(-1, sameMsg("EXTRA_SEAL"))
			if x == nil {
				out.Emit(check.Fail(req, e, "EXTRA_SEAL message not given to add_extra_seal"))
				return
			}
			want := "ACCEPT"
			if x.Str("op") == "reject" {
				want = "IGNORE"
			}
			if res != want {
				out.Emit(check.Fail(req, e, "add_extra_seal "+x.Str("op")+" returned outcome "+res+", want "+want, x))
				return
			}
			out.Emit(check.Pass(req, e, "extra seal "+x.Str("op"), x))
		case "OLD", "INVALID", "TOO_FAR":
			_, b := st.Find(-1, func(x *events.Event) bool { return sameMsg("BACKLOG")(x) && x.Str("op") == "push" })
			_, x := st.Find(-1, sameMsg("EXTRA_SEAL"))
			switch {
			case res != "IGNORE":
				out.Emit(check.Fail(req, e, class+" message returned outcome "+res+", want IGNORE (discarded)"))
			case b != nil:
				out.Emit(check.Fail(req, e, class+" message added to the backlog", b))
			case x != nil:
				out.Emit(check.Fail(req, e, class+" message stored as an extra seal", x))
			default:
				out.Emit(check.Pass(req, e, "discarded"))
			}
		}
	})
	return nil
}
