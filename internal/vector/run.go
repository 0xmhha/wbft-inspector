package vector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// Case results.
const (
	ResultPass        = "PASS"
	ResultFail        = "FAIL"
	ResultUnsupported = "UNSUPPORTED"
	ResultError       = "ERROR"   // the adapter exited or broke the protocol
	ResultTimeout     = "TIMEOUT" // the adapter exceeded the time limit
)

// Options configure a run.
type Options struct {
	Dir          string
	Impls        [][]string // adapter commands, in the order the user gave
	Select       Selection
	CaseTimeout  time.Duration // pure and chain cases
	StepsTimeout time.Duration // steps cases
	SpecCommit   string
	RunnerName   string
	RunnerVer    string
}

// CaseResult is the result of one case.
type CaseResult struct {
	Path         string   `json:"path"`
	Kind         string   `json:"kind,omitempty"`
	Impl         string   `json:"impl,omitempty"`
	Requirements []string `json:"requirements,omitempty"`
	ExpectFail   bool     `json:"expect_fail"`
	Result       string   `json:"result"`
	// Passed says whether the case passed. A case without expected.yaml
	// passes when the operation fails, also by an exit (ERROR) or a
	// timeout (TIMEOUT, reported apart, WBFT-VEC-049).
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
	Diff   string `json:"diff,omitempty"`
}

// Totals counts case results.
type Totals struct {
	Cases       int `json:"cases"`
	Pass        int `json:"pass"`
	Fail        int `json:"fail"`
	Unsupported int `json:"unsupported"`
	Error       int `json:"error"`
	Timeout     int `json:"timeout"`
	// TimeoutPassed counts the cases without expected.yaml that passed by
	// exceeding the time limit (WBFT-VEC-049).
	TimeoutPassed int `json:"timeout_passed"`
}

// AdapterInfo is the hello of one adapter.
type AdapterInfo struct {
	InputID string
	Cmd     []string
	Hello   Hello
}

// Outcome is the result of a run.
type Outcome struct {
	Totals          Totals
	Cases           []CaseResult
	Unaccessed      []string
	Adapters        []AdapterInfo
	Diagnostic      bool
	Instances       map[string][]verdict.Instance // by requirement ID
	CasesByReq      map[string][]string
	HandlersByReq   map[string]map[string]bool
	InvalidVectors  []string
	AdapterRestarts int
}

// Failed reports whether any case failed.
func (o *Outcome) Failed() bool {
	for _, c := range o.Cases {
		if !c.Passed && c.Result != ResultUnsupported {
			return true
		}
	}
	return false
}

type slot struct {
	info AdapterInfo
	a    *adapter
}

// Run runs the selected cases of the vector directory against the
// adapters. It returns an error only when the run cannot proceed at all
// (no vectors, an adapter that does not start or speaks another protocol).
func Run(ctx context.Context, o Options) (*Outcome, error) {
	cases, unaccessed, err := Load(o.Dir, o.Select)
	if err != nil {
		return nil, err
	}
	out := &Outcome{Unaccessed: unaccessed, Instances: map[string][]verdict.Instance{}, CasesByReq: map[string][]string{},
		HandlersByReq: map[string]map[string]bool{}}
	runner := map[string]string{"name": o.RunnerName, "version": o.RunnerVer}
	var slots []*slot
	defer func() {
		for _, s := range slots {
			if s.a != nil {
				s.a.close()
			}
		}
	}()
	for i, cmd := range o.Impls {
		a, err := startAdapter(cmd, runner, o.SpecCommit)
		if err != nil {
			return nil, err
		}
		s := &slot{info: AdapterInfo{InputID: fmt.Sprintf("impl-%d", i+1), Cmd: cmd, Hello: a.hello}, a: a}
		slots = append(slots, s)
		out.Adapters = append(out.Adapters, s.info)
		if len(a.hello.Improvements) > 0 {
			out.Diagnostic = true
		}
	}
	id := 0
	for _, c := range cases {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		res := CaseResult{Path: c.Path, Kind: c.Kind, Requirements: c.Requirements, ExpectFail: !c.HasExpected()}
		if c.Problem != "" {
			res.Result, res.Detail = ResultFail, "invalid vector: "+c.Problem
			res.ExpectFail = false
			out.InvalidVectors = append(out.InvalidVectors, c.Path)
			out.add(res, c)
			continue
		}
		res.Result, res.Detail = ResultUnsupported, "no adapter lists the handler"
		handler := c.Runner + "/" + c.Handler
		limit := o.CaseTimeout
		if c.Kind == "steps" {
			limit = o.StepsTimeout
		}
		for _, s := range slots {
			if !contains(s.info.Hello.Handlers, handler) {
				continue
			}
			if s.a == nil {
				if err := out.restart(s, runner, o.SpecCommit); err != nil {
					res.Result, res.Detail, res.Impl = ResultError, "adapter restart failed: "+err.Error(), s.info.InputID
					break
				}
			}
			id++
			ans, kind, detail := s.a.do(id, c, limit)
			res.Impl = s.info.InputID
			if kind != exchOK {
				s.a.kill()
				s.a = nil
				res.Result, res.Detail = ResultError, detail
				if kind == exchTimeout {
					res.Result = ResultTimeout
				}
				// A case without expected.yaml passes when the operation
				// fails, also by an exit or a timeout (WBFT-VEC-048).
				res.Passed = !c.HasExpected()
				break
			}
			if ans.Status == "unsupported" {
				res.Result, res.Detail = ResultUnsupported, "every adapter listing the handler answered unsupported"
				continue
			}
			decide(c, ans, &res)
			break
		}
		out.add(res, c)
	}
	return out, nil
}

func (out *Outcome) restart(s *slot, runner map[string]string, specCommit string) error {
	a, err := startAdapter(s.info.Cmd, runner, specCommit)
	if err != nil {
		return err
	}
	s.a = a
	out.AdapterRestarts++
	return nil
}

// decide applies WBFT-VEC-047 and WBFT-VEC-048 to an answer.
func decide(c *Case, ans answer, res *CaseResult) {
	if !c.HasExpected() {
		if ans.Status == "error" {
			res.Result, res.Passed, res.Detail = ResultPass, true, "failed as expected"
			return
		}
		res.Result, res.Detail = ResultFail, "the operation succeeded; the case expects it to fail"
		return
	}
	if ans.Status != "ok" {
		res.Result, res.Detail = ResultFail, "status "+ans.Status
		if ans.ErrorClass != "" || ans.Message != "" {
			res.Detail += " (" + strings.TrimSpace(ans.ErrorClass+" "+ans.Message) + ")"
		}
		return
	}
	var got any
	d := json.NewDecoder(bytes.NewReader(ans.Output))
	d.UseNumber()
	if len(ans.Output) == 0 || d.Decode(&got) != nil {
		res.Result, res.Detail = ResultFail, "status ok without an output object"
		return
	}
	if diff := compare("output", c.Expected, got); diff != "" {
		res.Result, res.Diff = ResultFail, diff
		return
	}
	res.Result, res.Passed = ResultPass, true
}

// compare returns the first difference between the expected value and the
// output, or "" when they are equal: the same keys at every level, lists of
// the same length and order, equal strings, booleans and nulls. A JSON
// number never equals an expected decimal string.
func compare(at string, want, got any) string {
	switch w := want.(type) {
	case map[string]any:
		g, ok := got.(map[string]any)
		if !ok {
			return fmt.Sprintf("%s: want an object, got %s", at, show(got))
		}
		keys := map[string]bool{}
		for k := range w {
			keys[k] = true
		}
		for k := range g {
			keys[k] = true
		}
		var ks []string
		for k := range keys {
			ks = append(ks, k)
		}
		sort.Strings(ks)
		for _, k := range ks {
			wv, wok := w[k]
			gv, gok := g[k]
			switch {
			case !gok:
				return fmt.Sprintf("%s.%s: missing", at, k)
			case !wok:
				return fmt.Sprintf("%s.%s: unexpected key", at, k)
			}
			if d := compare(at+"."+k, wv, gv); d != "" {
				return d
			}
		}
		return ""
	case []any:
		g, ok := got.([]any)
		if !ok {
			return fmt.Sprintf("%s: want a list, got %s", at, show(got))
		}
		if len(g) != len(w) {
			return fmt.Sprintf("%s: want %d items, got %d", at, len(w), len(g))
		}
		for i := range w {
			if d := compare(fmt.Sprintf("%s[%d]", at, i), w[i], g[i]); d != "" {
				return d
			}
		}
		return ""
	default:
		if !reflect.DeepEqual(want, got) {
			return fmt.Sprintf("%s: want %s, got %s", at, show(want), show(got))
		}
		return ""
	}
}

func show(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	if len(b) > 120 {
		return string(b[:120]) + "..."
	}
	return string(b)
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// add records a case result: totals, and one instance per requirement the
// case lists (not for invalid vectors and not in a diagnostic run, whose
// differences need the mapping of enabled optional behaviours).
func (out *Outcome) add(res CaseResult, c *Case) {
	out.Cases = append(out.Cases, res)
	out.Totals.Cases++
	switch {
	case res.Result == ResultUnsupported:
		out.Totals.Unsupported++
	case res.Result == ResultTimeout:
		out.Totals.Timeout++
		if res.Passed {
			out.Totals.TimeoutPassed++
		}
	case res.Passed:
		out.Totals.Pass++
	case res.Result == ResultError:
		out.Totals.Error++
	default:
		out.Totals.Fail++
	}
	if c.Problem != "" || out.Diagnostic {
		return
	}
	for _, req := range c.Requirements {
		out.CasesByReq[req] = append(out.CasesByReq[req], c.Path)
		if out.HandlersByReq[req] == nil {
			out.HandlersByReq[req] = map[string]bool{}
		}
		out.HandlersByReq[req][c.Runner+"/"+c.Handler] = true
		inst := verdict.Instance{Requirement: req, Key: "vector:" + c.Path, Source: res.Impl, Message: res.Detail,
			Evidence: []evidence.Pointer{{Kind: evidence.KindVector, VectorPath: c.Path, Input: res.Impl}}}
		switch {
		case res.Result == ResultUnsupported:
			inst.Verdict, inst.Reason = verdict.CannotDecide, verdict.ImplProfile
			inst.Message = "no adapter supports " + c.Runner + "/" + c.Handler
		case res.Passed:
			inst.Verdict = verdict.Pass
		default:
			inst.Verdict = verdict.Fail
			if res.Diff != "" {
				inst.Message = res.Diff
			}
			if inst.Message == "" {
				inst.Message = res.Result
			}
		}
		out.Instances[req] = append(out.Instances[req], inst)
	}
}

// IsProtocolError reports whether err is a usage error of the protocol.
func IsProtocolError(err error) bool { return errors.Is(err, ErrProtocolName) }
