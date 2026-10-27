// Package check holds the checker registry and runs the checkers.
//
// A checker decides one or more requirements. Checkers register themselves
// with Register from an init function of their package; the command imports
// those packages. Another build can add checkers the same way, by compiling
// in a package that registers them (for example with go build -overlay),
// without any change to the code of this repository.
package check

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/headers"
	"github.com/0xmhha/wbft-inspector/internal/rejections"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/syncobs"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// Kind is a kind of input.
type Kind string

// Input kinds.
const (
	SyncObservations Kind = "sync_observations" // typed downloader notification files
	Events           Kind = "events"            // consensus event streams
	Frames           Kind = "frames"            // frame dumps (R-01)
	ChainConfig      Kind = "chain_config"      // genesis chain configuration
	Rejections       Kind = "rejections"        // the nodes' rejected blocks and proposals (R-09)
	Headers          Kind = "headers"
)

// Clock is the clock model of a check: the tolerance of time comparisons
// between two records of one node (see Clock.Timing).
type Clock struct {
	Model   string // shared-host, ntp or unknown
	SkewMs  float64
	SchedMs float64 // upper bound of timer callback and event loop delay
	Margin  float64 // extra margin, milliseconds
}

// Inputs is what the checkers read. A checker must be deterministic: no
// wall clock, no randomness and no network; everything comes from Inputs.
type Inputs struct {
	SyncObservations []*syncobs.Source // independently recorded typed notifications
	Headers          *headers.Range
	Events           *events.Set       // nil when no event stream was given
	Frames           []*frames.Dump    // frame dumps, in the order given
	Rejections       []*rejections.Set // per node, in the order given
	Config           *params.Config    // nil when no chain configuration was given
	Clock            Clock
	Given            map[Kind]bool
}

// LogReader is implemented by a checker that can say whether it judges runs
// read from logs (events.Run.FromLog). Only a checker that uses no
// monotonic time judges them, and only a complete log run (events.Run.
// Complete). For a log run it did not read, a checker gets CANNOT_DECIDE
// instances: NEEDS_NODE_FEATURE (it needs the event stream's monotonic
// time) or LOG_LEVEL (the log may miss records).
type LogReader interface {
	JudgesLogs() bool
}

// Emitter receives instance verdicts.
type Emitter interface {
	Emit(verdict.Instance)
}

// Checker decides one or more requirements.
type Checker interface {
	// Name is the checker name of the catalog, e.g. "timer.round_timeout".
	Name() string
	// Requirements lists the requirement IDs it emits verdicts for.
	Requirements() []string
	// Needs lists the input kinds without which it cannot run at all.
	Needs() []Kind
	// Run decides the instances found in the inputs.
	Run(ctx context.Context, in *Inputs, out Emitter) error
}

var (
	mu       sync.Mutex
	checkers = map[string]Checker{}
)

// Register adds a checker. It panics if the name is taken or if another
// checker already emits one of its requirements.
func Register(c Checker) {
	mu.Lock()
	defer mu.Unlock()
	if _, dup := checkers[c.Name()]; dup {
		panic(fmt.Sprintf("check: checker %s registered twice", c.Name()))
	}
	for _, o := range checkers {
		for _, a := range o.Requirements() {
			for _, b := range c.Requirements() {
				if a == b {
					panic(fmt.Sprintf("check: %s and %s both decide %s", o.Name(), c.Name(), a))
				}
			}
		}
	}
	checkers[c.Name()] = c
}

// All returns the registered checkers sorted by name.
func All() []Checker {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Checker, 0, len(checkers))
	for _, c := range checkers {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

// ForRequirement returns the checker that decides a requirement.
func ForRequirement(id string) (Checker, bool) {
	for _, c := range All() {
		for _, r := range c.Requirements() {
			if r == id {
				return c, true
			}
		}
	}
	return nil, false
}

// Explainer decides whether a failed instance on a node that declared
// optional behaviours is explained by those behaviours. The public build has
// none. It knows only the behaviours of PublicBehaviours: a failure on a
// node that declares only those stays a failure unless the requirement is
// one they change. Any other failure on such a node becomes CANNOT_DECIDE
// with the reason NOT_IN_BUILD, because the public build cannot tell which
// requirements the behaviour changes. A build that can tell registers an
// Explainer.
type Explainer interface {
	// Explain returns true and a note when the behaviours of the node
	// explain the difference; the instance then becomes an observation.
	Explain(node *events.NodeInfo, in verdict.Instance) (bool, Observation)
}

// Observation is a finding that is not a verdict (report "observations").
type Observation struct {
	Kind         string
	Labels       []string
	Requirements []string
	Checker      string
	Node         string
	Note         string
	Instance     verdict.Instance
}

var explainer Explainer

// SetExplainer installs an Explainer.
func SetExplainer(e Explainer) {
	mu.Lock()
	defer mu.Unlock()
	explainer = e
}

func currentExplainer() Explainer {
	mu.Lock()
	defer mu.Unlock()
	return explainer
}

// Outcome is the result of running the checkers.
type Outcome struct {
	// Instances by requirement ID.
	Instances map[string][]verdict.Instance
	// Ran lists the checkers that ran; Missing the ones that could not run,
	// with the input kinds they lacked.
	Ran     map[string]bool
	Missing map[string][]Kind
	// Errors are checker failures (not verdicts).
	Errors       []string
	Observations []Observation
}

type collector struct {
	retry *retryPolicyIndex
	c     Checker
	want  map[string]bool
	out   *Outcome
	errs  *[]string
}

func (k *collector) Emit(i verdict.Instance) {
	if !k.want[i.Requirement] {
		*k.errs = append(*k.errs, fmt.Sprintf("checker %s emitted %s, which it does not declare", k.c.Name(), i.Requirement))
		return
	}
	i = k.retry.gate(i)
	k.out.Instances[i.Requirement] = append(k.out.Instances[i.Requirement], i)
}

// Run runs the checkers that decide any of the selected requirements.
func Run(ctx context.Context, in *Inputs, selected map[string]bool) *Outcome {
	out := &Outcome{Instances: map[string][]verdict.Instance{}, Ran: map[string]bool{}, Missing: map[string][]Kind{}}
	retry := newRetryPolicyIndex(in)
	for _, c := range All() {
		use := false
		for _, r := range c.Requirements() {
			if selected[r] {
				use = true
			}
		}
		if !use {
			continue
		}
		var lack []Kind
		for _, k := range c.Needs() {
			if !in.Given[k] {
				lack = append(lack, k)
			}
		}
		if len(lack) > 0 {
			out.Missing[c.Name()] = lack
			continue
		}
		want := map[string]bool{}
		for _, r := range c.Requirements() {
			want[r] = true
		}
		col := &collector{retry: retry, c: c, want: want, out: out, errs: &out.Errors}
		cin, skipped := forChecker(in, c)
		if cin.Events != nil && len(cin.Events.Runs) == 0 && len(skipped) > 0 {
			// Only log runs this checker does not judge.
			for _, r := range skipped {
				skipLogRun(c, r, col)
			}
			out.Ran[c.Name()] = true
			continue
		}
		for _, r := range skipped {
			skipLogRun(c, r, col)
		}
		if err := safeRun(ctx, c, cin, col); err != nil {
			out.Errors = append(out.Errors, fmt.Sprintf("checker %s: %v", c.Name(), err))
			continue
		}
		out.Ran[c.Name()] = true
	}
	applyLost(in, out)
	applyOptional(in, out)
	return out
}

// applyLost turns a FAIL anchored at an event of a run that lost records
// (events.Run.Lost: the node's writer dropped them) into CANNOT_DECIDE
// MISSING_DATA: the lost records may hold what the checker found missing,
// or change the state it reconstructed. A FAIL anchored elsewhere (frames,
// rejections) is left to its checker, which reads the frame dump's own
// dropped records.
func applyLost(in *Inputs, out *Outcome) {
	if in.Events == nil {
		return
	}
	lost := map[string][]events.Span{}
	for _, r := range in.Events.Runs {
		if len(r.Lost) > 0 {
			lost[r.Node+"/"+r.ID] = r.Lost
		}
	}
	if len(lost) == 0 {
		return
	}
	for req, insts := range out.Instances {
		for i, x := range insts {
			run, ok := eventRun(x.Key)
			if x.Verdict != verdict.Fail || !ok {
				continue
			}
			spans := lost[x.Node+"/"+run]
			if len(spans) == 0 {
				continue
			}
			n := uint64(0)
			for _, sp := range spans {
				n += sp.To - sp.From + 1
			}
			x.Verdict, x.Reason = verdict.CannotDecide, verdict.MissingData
			x.Message = fmt.Sprintf("run %s lost %d event records (first seq %d); they may explain the difference: %s", run, n, spans[0].From, x.Message)
			insts[i] = x
		}
		out.Instances[req] = insts
	}
}

// eventRun returns the run of an instance key of an event record
// ("event:<run>:<seq>", Key).
func eventRun(key string) (string, bool) {
	rest, ok := strings.CutPrefix(key, "event:")
	if !ok {
		return "", false
	}
	i := strings.LastIndexByte(rest, ':')
	if i < 0 {
		return "", false
	}
	return rest[:i], true
}

// forChecker returns the inputs of checker c: without the log runs it does
// not judge, which it returns.
func forChecker(in *Inputs, c Checker) (*Inputs, []*events.Run) {
	if in.Events == nil {
		return in, nil
	}
	lr, ok := c.(LogReader)
	judges := ok && lr.JudgesLogs()
	var keep, skipped []*events.Run
	for _, r := range in.Events.Runs {
		if r.FromLog && (!judges || !r.Complete) {
			skipped = append(skipped, r)
		} else {
			keep = append(keep, r)
		}
	}
	if len(skipped) == 0 {
		return in, nil
	}
	set := *in.Events
	set.Runs = keep
	cin := *in
	cin.Events = &set
	return &cin, skipped
}

// skipLogRun emits, for each requirement of c, a CANNOT_DECIDE instance
// for log run r that c did not read.
func skipLogRun(c Checker, r *events.Run, e Emitter) {
	why, reason := "the checker measures monotonic time, which only the event stream carries", verdict.NeedsNodeFeature
	if lr, ok := c.(LogReader); ok && lr.JudgesLogs() {
		why, reason = "the log does not show both consensus modules at trace from its start, so records may be missing", verdict.LogLevel
	}
	for _, req := range c.Requirements() {
		e.Emit(verdict.Instance{Requirement: req, Node: r.Node, Key: "logrun:" + r.ID, Verdict: verdict.CannotDecide,
			Reason: reason, Message: fmt.Sprintf("log run %s (%s) not judged: %s", r.ID, r.Input, why)})
	}
}

func safeRun(ctx context.Context, c Checker, in *Inputs, e Emitter) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("panic: %v", p)
		}
	}()
	return c.Run(ctx, in, e)
}

// PublicBehaviours are the optional behaviours a public wbft node always
// declares, its local defaults, with the requirements whose verdict
// they change:
//   - one_round0_proposal: the proposer sends no second PRE-PREPARE in a
//     round-0 view, where the reference does on a second request
//     (WBFT-SM-032 and the MAY of WBFT-SM-082).
//   - bad_block_release_mark: the core marks a ROUND-CHANGE whose prepared
//     pair the bad-block rule released, for the node's signer only; the
//     messages are those of the reference.
//
// Parent-epoch lookup follows the requested parent chain rather than a
// canonical index. Its declaration changes canonical-first lookup rules.
// Integer thresholds and checked proposer configuration declare only the
// corresponding numeric and missing-policy requirement changes.
//
// A refusal of the node's signer is not a behaviour of this list: the
// node records it (HEALTH privval_refusal, sign_floor_skip) and the
// checkers do not count the message it did not send.
var PublicBehaviours = map[string][]string{
	"round_change_retry":      {"WBFT-TIMER-003", "WBFT-TIMER-020", "WBFT-TIMER-024", "WBFT-NET-023", "WBFT-NET-032"},
	"one_round0_proposal":     {"WBFT-SM-032", "WBFT-SM-082"},
	"bad_block_release_mark":  nil,
	"parent_epoch_lookup":     {"WBFT-HDR-071", "WBFT-APP-003"},
	"integer_quorum":          {"WBFT-VAL-002", "WBFT-VAL-003"},
	"checked_proposer_policy": {"WBFT-PARAM-032", "WBFT-PARAM-034"},
}

// publicOnly reports whether the node declares only behaviours of
// PublicBehaviours, and whether one of them changes requirement req.
func publicOnly(node *events.NodeInfo, req string) (only, changes bool) {
	if node.Unnamed {
		return false, false
	}
	for _, b := range node.Behaviours {
		reqs, ok := PublicBehaviours[b]
		if !ok {
			return false, false
		}
		if slices.Contains(reqs, req) {
			changes = true
		}
	}
	return true, changes
}

// applyOptional handles failures on nodes that declared optional
// behaviours (see Explainer).
func applyOptional(in *Inputs, out *Outcome) {
	if in.Events == nil {
		return
	}
	ex := currentExplainer()
	for req, insts := range out.Instances {
		kept := insts[:0]
		for _, x := range insts {
			node := retryOptionalNode(in, x)
			if x.Verdict != verdict.Fail || node == nil || !node.Optional {
				kept = append(kept, x)
				continue
			}
			if ex != nil {
				if ok, obs := ex.Explain(node, x); ok {
					obs.Instance = x
					out.Observations = append(out.Observations, obs)
					continue
				}
			}
			if only, changes := publicOnly(node, req); only && !changes {
				kept = append(kept, x)
				continue
			}
			x.Verdict, x.Reason = verdict.CannotDecide, verdict.NotInBuild
			x.Message = "the node declares optional behaviours; this build cannot tell whether they explain the difference: " + x.Message
			kept = append(kept, x)
		}
		out.Instances[req] = kept
	}
}
