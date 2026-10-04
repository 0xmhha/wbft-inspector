package check

import (
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/timers"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// Base implements Name, Requirements and Needs of a checker.
type Base struct {
	ID    string
	Reqs  []string
	Kinds []Kind
}

// Name returns the checker name.
func (b Base) Name() string { return b.ID }

// Requirements returns the requirements the checker decides.
func (b Base) Requirements() []string { return b.Reqs }

// Needs returns the input kinds the checker needs.
func (b Base) Needs() []Kind { return b.Kinds }

// Pointer returns the evidence pointer of an event record.
func Pointer(e *events.Event) evidence.Pointer {
	msg := e.Kind
	if e.View != nil {
		msg += " " + e.View.String()
	}
	if e.Step != nil {
		msg += fmt.Sprintf(" step %d", *e.Step)
	}
	return evidence.Pointer{Kind: evidence.KindEvent, Input: e.Input, Node: e.Node, Line: e.Line, T: e.TWall, Msg: msg}
}

// Key returns the stable instance key of an event record.
func Key(e *events.Event) string { return fmt.Sprintf("event:%s:%d", e.Run, e.Seq) }

// New returns an instance anchored at event e, with e and more as evidence.
func New(req string, e *events.Event, v verdict.Verdict, reason verdict.Reason, msg string, more ...*events.Event) verdict.Instance {
	ev := []evidence.Pointer{Pointer(e)}
	for _, m := range more {
		if m != nil && m != e {
			ev = append(ev, Pointer(m))
		}
	}
	if v != verdict.CannotDecide {
		reason = ""
	}
	return verdict.Instance{Requirement: req, Node: e.Node, Key: Key(e), Verdict: v, Reason: reason, Message: msg, Source: e.Input, Evidence: ev}
}

// Pass, Fail and Undecided are shorthands of New.
func Pass(req string, e *events.Event, msg string, more ...*events.Event) verdict.Instance {
	return New(req, e, verdict.Pass, "", msg, more...)
}

// Fail returns a FAIL instance anchored at e.
func Fail(req string, e *events.Event, msg string, more ...*events.Event) verdict.Instance {
	return New(req, e, verdict.Fail, "", msg, more...)
}

// Undecided returns a CANNOT_DECIDE instance anchored at e.
func Undecided(req string, e *events.Event, reason verdict.Reason, msg string, more ...*events.Event) verdict.Instance {
	return New(req, e, verdict.CannotDecide, reason, msg, more...)
}

// Step is the events of one step of a run, in record order.
type Step struct {
	Run *events.Run
	Idx []int
}

// StepOf returns the step of event i (empty when i belongs to no step).
func StepOf(r *events.Run, i int) Step { return Step{Run: r, Idx: r.StepOf(i)} }

// Find returns the first event of the step after record index from that
// satisfies pred, or nil. Use from = -1 to search the whole step.
func (s Step) Find(from int, pred func(*events.Event) bool) (int, *events.Event) {
	for _, j := range s.Idx {
		if j > from && pred(s.Run.Events[j]) {
			return j, s.Run.Events[j]
		}
	}
	return -1, nil
}

// FindBefore returns the last event before record index to that satisfies
// pred, or nil.
func (s Step) FindBefore(to int, pred func(*events.Event) bool) (int, *events.Event) {
	j, found := -1, (*events.Event)(nil)
	for _, k := range s.Idx {
		if k < to && pred(s.Run.Events[k]) {
			j, found = k, s.Run.Events[k]
		}
	}
	return j, found
}

// Has reports whether an event of the step satisfies pred.
func (s Step) Has(pred func(*events.Event) bool) bool {
	_, e := s.Find(-1, pred)
	return e != nil
}

// First returns the record index of the first event of the step.
func (s Step) First() int {
	if len(s.Idx) == 0 {
		return -1
	}
	return s.Idx[0]
}

// Last returns the record index of the last event of the step.
func (s Step) Last() int {
	if len(s.Idx) == 0 {
		return -1
	}
	return s.Idx[len(s.Idx)-1]
}

// IsKind returns a predicate that matches records of a kind.
func IsKind(kind string) func(*events.Event) bool {
	return func(e *events.Event) bool { return e.Kind == kind }
}

// Refused reports whether the step records that the signer refused to sign
// (then an own message is legitimately not sent).
func (s Step) Refused() bool {
	return s.Has(func(e *events.Event) bool {
		if e.Kind != "HEALTH" {
			return false
		}
		w := e.Str("what")
		return w == "privval_refusal" || w == "sign_floor_skip"
	})
}

// FollowedByStop reports whether an ENGINE_STOP record follows the step
// before any record of another step.
func (s Step) FollowedByStop() bool {
	last := s.Last()
	if last < 0 {
		return false
	}
	for j := last + 1; j < len(s.Run.Events); j++ {
		e := s.Run.Events[j]
		if e.Kind == "ENGINE_STOP" {
			return true
		}
		if e.Step != nil {
			return false
		}
	}
	return false
}

// Cmp compares two decimal strings as integers (-1, 0, 1); malformed
// values compare as 0.
func Cmp(a, b string) int {
	x, ok1 := new(big.Int).SetString(a, 10)
	y, ok2 := new(big.Int).SetString(b, 10)
	if !ok1 || !ok2 {
		return 0
	}
	return x.Cmp(y)
}

// Plus returns the decimal string a + n.
func Plus(a string, n int64) string {
	x, ok := new(big.Int).SetString(a, 10)
	if !ok {
		return ""
	}
	return x.Add(x, big.NewInt(n)).String()
}

// Walk calls f for every event of every run with the state before the
// event, then applies the event to the state.
func Walk(in *Inputs, f func(r *events.Run, i int, st *events.State)) {
	if in.Events == nil {
		return
	}
	for _, r := range in.Events.Runs {
		st := events.NewState()
		for i := range r.Events {
			f(r, i, st)
			st.Apply(r, i)
		}
	}
}

// Timing is the three-way comparison of a measured duration d with an
// expected duration t (nanoseconds), both taken from one node's monotonic
// clock: PASS within [t, t + sched], FAIL beyond the margin, otherwise
// CANNOT_DECIDE with CLOCK_UNCERTAINTY.
func (c Clock) Timing(d, t int64) verdict.Verdict {
	sched := int64(c.SchedMs * 1e6)
	margin := int64(c.Margin * 1e6)
	lo, hi := t, t+sched
	switch {
	case d >= lo && d <= hi:
		return verdict.Pass
	case d < lo-margin || d > hi+margin:
		return verdict.Fail
	}
	return verdict.CannotDecide
}

// AtLeast is the one-sided version of Timing: d must not be below t.
func (c Clock) AtLeast(d, t int64) verdict.Verdict {
	margin := int64(c.Margin * 1e6)
	switch {
	case d >= t:
		return verdict.Pass
	case d < t-margin:
		return verdict.Fail
	}
	return verdict.CannotDecide
}

// RoundTimeout returns round_timeout(config_at(h), r) in nanoseconds and the
// warning of the reference for view v, or ok = false without a chain
// configuration or a view.
func (in *Inputs) RoundTimeout(v *events.View) (ns int64, warn string, ok bool) {
	if in.Config == nil || v == nil || v.SeqBig() == nil || v.RoundBig() == nil {
		return 0, "", false
	}
	c := in.Config.At(v.SeqBig())
	ns, warn = timers.RoundTimeout(c.RequestTimeoutMs, c.MaxRequestTimeoutSeconds, v.RoundBig())
	return ns, warn, true
}

// RetryTimeoutMs returns RT(h) in milliseconds for the sequence of v.
func (in *Inputs) RetryTimeoutMs(v *events.View) (uint64, bool) {
	if in.Config == nil || v == nil || v.SeqBig() == nil {
		return 0, false
	}
	return in.Config.At(v.SeqBig()).RequestTimeoutMs, true
}

// DurationMs is time.Duration.Milliseconds of a nanosecond count
// (truncation toward zero), the unit of duration_ms in TIMER_ARM.
func DurationMs(ns int64) int64 { return ns / 1_000_000 }

// StepStart keeps the timers that were armed when the current step began.
// Observe must see every record of a run in order (as in Walk).
type StepStart struct {
	armed map[string]*events.Timer
}

// Observe records the state before event i when i is the first record of
// its step, and returns the timers armed at the start of the step of i.
func (t *StepStart) Observe(r *events.Run, i int, st *events.State) map[string]*events.Timer {
	if StepOf(r, i).First() == i {
		t.armed = make(map[string]*events.Timer, len(st.Armed))
		for kind, tm := range st.Armed {
			t.armed[kind] = tm
		}
	}
	return t.armed
}

// Member tells whether a node showed itself to be a validator in a
// sequence: it broadcast an own message while its view was in that
// sequence. The event stream carries no validator set, so a missing own
// message is decided only for nodes that were seen to be members.
type Member map[[2]string]bool

// Members scans the runs of the inputs.
func Members(in *Inputs) Member {
	m := Member{}
	Walk(in, func(r *events.Run, i int, st *events.State) {
		e := r.Events[i]
		if e.Kind == "SEND" && (e.Str("cause") == "broadcast" || e.Str("cause") == "retry") && st.View != nil {
			m[[2]string{r.ID, st.View.Seq}] = true
		}
	})
	return m
}

// In reports whether the node of run r broadcast in sequence seq.
func (m Member) In(r *events.Run, seq string) bool { return m[[2]string{r.ID, seq}] }

// MissingSend returns the instance for an own message that a step should
// contain but does not: undecided when the signer refused or when the node
// was not seen to be a validator in the sequence, and a failure otherwise.
func MissingSend(req string, e *events.Event, s Step, m Member, seq, what string, more ...*events.Event) verdict.Instance {
	switch {
	case s.Refused():
		return Undecided(req, e, verdict.ObserverScope, "the signer refused the "+what, more...)
	case !m.In(s.Run, seq):
		return Undecided(req, e, verdict.ObserverScope, "no "+what+" send recorded and the node sent no own message in sequence "+seq+" (it may not be a validator)", more...)
	}
	return Fail(req, e, "no "+what+" sent", more...)
}

// FramePointer returns the evidence pointer of a frame dump record.
func FramePointer(r *frames.Record) evidence.Pointer {
	p := evidence.Pointer{Kind: evidence.KindFrame, Input: r.Input, Node: r.Node, Line: r.Line, T: r.TWall,
		FrameID: fmt.Sprintf("%s:%d", r.Run, r.Seq), Direction: r.Dir, Code: r.Code, PayloadSHA256: r.Payload}
	if r.Peer != nil {
		p.Peer = *r.Peer
	}
	return p
}

// FrameInstance returns an instance anchored at a frame dump record.
func FrameInstance(req string, r *frames.Record, v verdict.Verdict, reason verdict.Reason, msg string) verdict.Instance {
	if v != verdict.CannotDecide {
		reason = ""
	}
	return verdict.Instance{Requirement: req, Node: r.Node, Key: fmt.Sprintf("frame:%s:%d", r.Run, r.Seq), Verdict: v, Reason: reason,
		Message: msg, Source: r.Input, Evidence: []evidence.Pointer{FramePointer(r)}}
}
