// Package verdict defines verdicts, the reason codes of CANNOT_DECIDE and
// the rule that aggregates instance verdicts into a requirement verdict.
//
// A checker does not decide a requirement at once. It decides every instance
// the requirement applies to (a timer, a message, a view) and the
// requirement verdict is aggregated from those instances:
//
//   - any FAIL instance makes the requirement FAIL;
//   - otherwise at least one PASS instance makes it PASS, and the undecided
//     instances are counted in the coverage;
//   - otherwise (all instances undecided, or no instance) it is
//     CANNOT_DECIDE, with the most frequent reason as the representative
//     reason, or NOT_EXERCISED when there was no instance.
package verdict

import (
	"sort"

	"github.com/0xmhha/wbft-inspector/internal/evidence"
)

// Verdict is the result of a requirement or of one instance.
type Verdict string

// Verdicts. NOT_RUN is not a verdict but a record that a check was not run
// (not selected, or no input of the kinds it needs).
const (
	Pass         Verdict = "PASS"
	Fail         Verdict = "FAIL"
	CannotDecide Verdict = "CANNOT_DECIDE"
	NotRun       Verdict = "NOT_RUN"
)

// Reason is the reason code of a CANNOT_DECIDE verdict; it tells the user
// what else to provide.
type Reason string

// Reason codes.
const (
	MissingData       Reason = "MISSING_DATA"       // input for that node or range not given
	MissingAncestor   Reason = "MISSING_ANCESTOR"   // parent, epoch header or validator set missing
	ArchiveRequired   Reason = "ARCHIVE_REQUIRED"   // state pruned on a non-archive node
	NotExercised      Reason = "NOT_EXERCISED"      // the situation did not occur in the input
	ClockUncertainty  Reason = "CLOCK_UNCERTAINTY"  // the measurement lies within the clock tolerance band
	ObserverScope     Reason = "OBSERVER_SCOPE"     // the observer cannot see that link or decision
	LogLevel          Reason = "LOG_LEVEL"          // the log line is below the configured level
	ImplProfile       Reason = "IMPL_PROFILE"       // no event mapping for the implementation under test
	RPCUnavailable    Reason = "RPC_UNAVAILABLE"    // RPC method not available
	NeedsNodeFeature  Reason = "NEEDS_NODE_FEATURE" // the node must provide an observation feature
	VectorOnly        Reason = "VECTOR_ONLY"        // leaves no evidence on a running chain
	InconsistentInput Reason = "INCONSISTENT_INPUT" // inputs contradict each other
	NotInBuild        Reason = "NOT_IN_BUILD"       // this build has no checker for the requirement ID
)

// Reasons lists every reason code in the order of the report schema.
var Reasons = []Reason{MissingData, MissingAncestor, ArchiveRequired, NotExercised, ClockUncertainty,
	ObserverScope, LogLevel, ImplProfile, RPCUnavailable, NeedsNodeFeature, VectorOnly, InconsistentInput, NotInBuild}

// Instance is the verdict of one application of a requirement.
type Instance struct {
	Requirement string
	Node        string
	Key         string // stable instance key, e.g. "timer:<run>:round:12"
	Verdict     Verdict
	Reason      Reason // for CANNOT_DECIDE
	Message     string
	Step        string // spec step, if any
	Expected    any
	Actual      any
	Source      string // input id
	Evidence    []evidence.Pointer
}

// Limits of the samples kept in a requirement result.
const (
	MaxViolations = 100
	MaxUndecided  = 20
)

// Result is the aggregate of the instances of one requirement.
type Result struct {
	Verdict             Verdict
	Reason              Reason // representative reason of CANNOT_DECIDE
	Detail              string
	Instances           int
	Pass                int
	Fail                int
	CannotDecide        int
	Reasons             map[Reason]int
	Sources             []string
	Violations          []Instance
	ViolationsTruncated int
	Undecided           []Instance
}

// Aggregate applies the aggregation rule. The instances are sorted by node
// and key first, so the samples do not depend on the order of emission.
func Aggregate(in []Instance) Result {
	insts := append([]Instance(nil), in...)
	sort.SliceStable(insts, func(i, j int) bool {
		if insts[i].Node != insts[j].Node {
			return insts[i].Node < insts[j].Node
		}
		return insts[i].Key < insts[j].Key
	})
	r := Result{Instances: len(insts), Reasons: map[Reason]int{}}
	sources := map[string]bool{}
	for _, x := range insts {
		if x.Source != "" {
			sources[x.Source] = true
		}
		switch x.Verdict {
		case Pass:
			r.Pass++
		case Fail:
			r.Fail++
			if len(r.Violations) < MaxViolations {
				r.Violations = append(r.Violations, x)
			} else {
				r.ViolationsTruncated++
			}
		default:
			r.CannotDecide++
			reason := x.Reason
			if reason == "" {
				reason = MissingData
			}
			r.Reasons[reason]++
			if len(r.Undecided) < MaxUndecided {
				r.Undecided = append(r.Undecided, x)
			}
		}
	}
	for s := range sources {
		r.Sources = append(r.Sources, s)
	}
	sort.Strings(r.Sources)
	switch {
	case r.Fail > 0:
		r.Verdict = Fail
	case r.Pass > 0:
		r.Verdict = Pass
	case r.Instances == 0:
		r.Verdict, r.Reason = CannotDecide, NotExercised
		r.Detail = "no instance of the requirement occurred in the input"
	default:
		r.Verdict, r.Reason = CannotDecide, representative(r.Reasons)
		for _, x := range r.Undecided {
			if x.Reason == r.Reason || (x.Reason == "" && r.Reason == MissingData) {
				r.Detail = x.Message
				break
			}
		}
	}
	return r
}

// representative returns the most frequent reason; ties go to the reason
// that comes first in the schema order.
func representative(m map[Reason]int) Reason {
	best, n := Reason(""), -1
	for _, c := range Reasons {
		if m[c] > n {
			best, n = c, m[c]
		}
	}
	return best
}
