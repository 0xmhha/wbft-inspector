package events

// Timer kinds of TIMER_ARM, TIMER_CANCEL and TIMER_FIRE.
const (
	TimerRound  = "round"
	TimerRetry  = "retry"
	TimerFuture = "future"
)

// Message codes of the istanbul sub-protocol (A-01 §4.1).
const (
	CodePreprepare  = 0x12
	CodePrepare     = 0x13
	CodeCommit      = 0x14
	CodeRoundChange = 0x15
)

// Timer is an armed timer as the stream reports it.
type Timer struct {
	Kind       string
	Gen        int64
	EngineRun  int64
	View       *View
	DurationMs int64
	ArmMono    int64
	ArmIndex   int    // index of the TIMER_ARM record in the run
	Target     string // target_round of a retry timer
	Rearmed    bool   // armed again after a restart (not by a step)
}

// Expired reports whether the timer's deadline has passed at monotonic
// time t. Its expiry is then queued, or about to be, and can no longer be
// cancelled; only a later TIMER_FIRE record shows it being processed.
func (t *Timer) Expired(at int64) bool { return t.ArmMono+t.DurationMs*1_000_000 <= at }

// State follows one run: the current view, whether the engine runs, and
// the timers that are armed (armed and neither cancelled nor fired).
type State struct {
	View      *View
	Running   bool
	EngineRun int64
	Armed     map[string]*Timer
	// Superseded holds round timers replaced by a newer arm without a
	// cancel record, by generation.
	Superseded map[int64]*Timer
	// Fired holds the generation of fired round timers.
	Fired map[int64]bool
}

// NewState returns the state at the start of a run.
func NewState() *State {
	return &State{Armed: map[string]*Timer{}, Superseded: map[int64]*Timer{}, Fired: map[int64]bool{}}
}

// Apply updates the state with event i of run r.
func (s *State) Apply(r *Run, i int) {
	e := r.Events[i]
	switch e.Kind {
	case "ROUND_ENTER":
		if e.View != nil {
			s.View = e.View
		}
	case "ENGINE_START":
		s.Running = true
		if n, ok := e.Int("engine_run"); ok {
			s.EngineRun = n
		}
	case "ENGINE_STOP":
		s.Running = false
	case "TIMER_ARM":
		t := &Timer{Kind: e.Str("timer"), View: e.View, ArmMono: e.TMono, ArmIndex: i, Target: e.Str("target_round")}
		t.Gen, _ = e.Int("gen")
		t.EngineRun, _ = e.Int("engine_run")
		t.DurationMs, _ = e.Int("duration_ms")
		t.Rearmed, _ = e.Bool("rearmed")
		if old := s.Armed[t.Kind]; old != nil && t.Kind == TimerRound {
			s.Superseded[old.Gen] = old
		}
		s.Armed[t.Kind] = t
		if t.Rearmed && t.Kind == TimerRound && e.View != nil {
			// After a restart that replayed the write-ahead log the core
			// resumes in the view of its re-armed round timer without a
			// ROUND_ENTER record.
			s.View = e.View
		}
	case "TIMER_CANCEL":
		k := e.Str("timer")
		gen, _ := e.Int("gen")
		if t := s.Armed[k]; t != nil && t.Gen == gen {
			delete(s.Armed, k)
			if k == TimerRound {
				s.Superseded[gen] = t
			}
		}
	case "TIMER_FIRE":
		k := e.Str("timer")
		gen, _ := e.Int("gen")
		if t := s.Armed[k]; t != nil && t.Gen == gen {
			delete(s.Armed, k)
		}
		if k == TimerRound {
			s.Fired[gen] = true
		}
	}
}

// Code returns the message code of a SEND, MSG_OUTCOME or BACKLOG record.
func (e *Event) Code() int64 {
	c, _ := e.Int("code")
	return c
}

// IsSend reports whether e is a SEND of the code with one of the causes.
func (e *Event) IsSend(code int64, causes ...string) bool {
	if e.Kind != "SEND" || e.Code() != code {
		return false
	}
	if len(causes) == 0 {
		return true
	}
	c := e.Str("cause")
	for _, x := range causes {
		if c == x {
			return true
		}
	}
	return false
}
