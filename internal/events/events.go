// Package events reads consensus event streams: JSON Lines files with one
// event per line, in the event vocabulary shared by nodes and the inspector
// (NODE_START, ROUND_ENTER, TIMER_ARM, SEND, MSG_OUTCOME, ...). The wbft node
// and its simulator write this format (format version 1).
//
// Every record has the common fields v, node, run, seq, t_wall, t_mono_ns and
// kind, optionally view, step, imp and src; the kind-specific fields follow
// at the top level. A run is one process of one node; seq increases by one
// per record within a run, and t_mono_ns is the monotonic clock of that
// process. step numbers the inputs of one engine run.
package events

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// FormatVersion is the event format this package reads.
const FormatVersion = 1

// View is the view field: sequence and round as decimal strings.
type View struct {
	Seq   string `json:"seq"`
	Round string `json:"round"`
}

// SeqBig returns the sequence, or nil if it is not a decimal number.
func (v *View) SeqBig() *big.Int { return dec(v.Seq) }

// RoundBig returns the round, or nil if it is not a decimal number.
func (v *View) RoundBig() *big.Int { return dec(v.Round) }

// String returns "(seq, round)".
func (v *View) String() string {
	if v == nil {
		return "(none)"
	}
	return "(" + v.Seq + ", " + v.Round + ")"
}

// Equal reports whether two views are the same.
func (v *View) Equal(w *View) bool {
	if v == nil || w == nil {
		return v == w
	}
	return v.Seq == w.Seq && v.Round == w.Round
}

func dec(s string) *big.Int {
	b, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil
	}
	return b
}

// Event is one record.
type Event struct {
	Input string // input id of the file
	Line  int    // 1-based line in the file
	Node  string
	Run   string
	Seq   uint64
	TWall string
	TMono int64
	Kind  string
	View  *View
	Step  *uint64
	Imp   []string
	Src   string
	F     map[string]json.RawMessage // kind-specific fields
	// FromLog marks an event read from a log line (package logs): TMono is
	// not a monotonic time, Seq numbers the mapped lines, and a record the
	// node did not log at its level is missing without a gap.
	FromLog bool
}

// Str returns a string field, or "".
func (e *Event) Str(k string) string {
	var s string
	if raw, ok := e.F[k]; ok {
		_ = json.Unmarshal(raw, &s)
	}
	return s
}

// Int returns an integer field.
func (e *Event) Int(k string) (int64, bool) {
	raw, ok := e.F[k]
	if !ok {
		return 0, false
	}
	var n json.Number
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if d.Decode(&n) != nil {
		return 0, false
	}
	v, err := n.Int64()
	return v, err == nil
}

// Bool returns a boolean field.
func (e *Event) Bool(k string) (bool, bool) {
	raw, ok := e.F[k]
	if !ok {
		return false, false
	}
	var b bool
	if json.Unmarshal(raw, &b) != nil {
		return false, false
	}
	return b, true
}

// Big returns a field written as a decimal string (block numbers, rounds).
func (e *Event) Big(k string) *big.Int { return dec(e.Str(k)) }

// Has reports whether the field is present.
func (e *Event) Has(k string) bool { _, ok := e.F[k]; return ok }

// IsNull reports whether the field is present with the value null.
func (e *Event) IsNull(k string) bool {
	raw, ok := e.F[k]
	return ok && string(raw) == "null"
}

// StepIs reports whether the event belongs to step s.
func (e *Event) StepIs(s uint64) bool { return e.Step != nil && *e.Step == s }

// Ref returns a short reference for messages: "<input>:<line>".
func (e *Event) Ref() string { return fmt.Sprintf("%s:%d", e.Input, e.Line) }

// Run is the records of one process of one node, in seq order.
type Run struct {
	Node   string
	ID     string
	Input  string
	Events []*Event
	// FromLog marks a run read from a log file: see Event.FromLog.
	FromLog bool
	groups  map[groupKey][]int
	seg     []int // engine segment of each event
}

type groupKey struct {
	seg  int
	step uint64
}

// Input describes one input file.
type Input struct {
	ID        string
	Path      string
	SHA256    string
	Records   int
	FirstWall string
	LastWall  string
	Nodes     []string
}

// NodeInfo is what the streams say about a node.
type NodeInfo struct {
	Address string
	Impl    string
	// Optional reports that the node declared optional behaviours: a
	// non-empty NODE_START "improvements" list or an "imp" field on any
	// record. The public build cannot tell which requirements they change.
	Optional bool
}

// Set is the event streams of one check.
type Set struct {
	Inputs []Input
	Runs   []*Run
	Nodes  map[string]*NodeInfo
	Errors []string
	// UnknownKinds counts records of kinds this build does not know.
	UnknownKinds map[string]int
}

// Known kinds of the event vocabulary.
var Known = map[string]bool{
	"NODE_START": true, "NODE_STOP": true, "ENGINE_START": true, "ENGINE_STOP": true, "ROUND_ENTER": true,
	"STATE": true, "TIMER_ARM": true, "TIMER_CANCEL": true, "TIMER_FIRE": true, "PREPREPARE_ACCEPT": true,
	"PROPOSAL_DEFERRED": true, "QUORUM": true, "SEND": true, "BACKLOG": true, "EXTRA_SEAL": true,
	"BUILD_REQUEST": true, "PROPOSAL_SUBMITTED": true, "FINALIZE_HANDOVER": true, "NEW_HEAD": true,
	"IMPORT_FAIL": true, "MSG_OUTCOME": true, "EVIDENCE": true, "COMMIT_RESULT": true, "LOG_CONFIG": true,
	"HEALTH": true,
}

var common = map[string]bool{"v": true, "node": true, "run": true, "seq": true, "t_wall": true,
	"t_mono_ns": true, "kind": true, "view": true, "step": true, "imp": true, "src": true}

// Expand turns the arguments of --events into files: a directory stands for
// its *.jsonl files in name order.
func Expand(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !st.IsDir() {
			out = append(out, p)
			continue
		}
		es, err := os.ReadDir(p)
		if err != nil {
			return nil, err
		}
		var names []string
		for _, e := range es {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".jsonl") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, filepath.Join(p, n))
		}
	}
	return out, nil
}

// Load reads event files. Input ids are in-1, in-2, ... in the order of
// files. Malformed lines are reported in Set.Errors and skipped.
func Load(files []string) (*Set, error) {
	s := &Set{Nodes: map[string]*NodeInfo{}, UnknownKinds: map[string]int{}}
	runs := map[[2]string]*Run{}
	for i, path := range files {
		id := fmt.Sprintf("in-%d", i+1)
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		in, err := s.read(f, id, path, runs)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		s.Inputs = append(s.Inputs, in)
	}
	for _, r := range runs {
		sort.SliceStable(r.Events, func(i, j int) bool { return r.Events[i].Seq < r.Events[j].Seq })
		for i := 1; i < len(r.Events); i++ {
			if r.Events[i].Seq == r.Events[i-1].Seq {
				s.Errors = append(s.Errors, fmt.Sprintf("%s: run %s repeats seq %d", r.Events[i].Ref(), r.ID, r.Events[i].Seq))
			} else if r.Events[i].Seq != r.Events[i-1].Seq+1 {
				s.Errors = append(s.Errors, fmt.Sprintf("%s: run %s skips from seq %d to %d (records missing)", r.Events[i].Ref(), r.ID, r.Events[i-1].Seq, r.Events[i].Seq))
			}
		}
		r.index()
		s.Runs = append(s.Runs, r)
	}
	sort.Slice(s.Runs, func(i, j int) bool {
		a, b := s.Runs[i], s.Runs[j]
		if a.Node != b.Node {
			return a.Node < b.Node
		}
		fa, fb := a.Events[0].TWall, b.Events[0].TWall
		if fa != fb {
			return fa < fb
		}
		return a.ID < b.ID
	})
	return s, nil
}

func (s *Set) read(r io.Reader, id, path string, runs map[[2]string]*Run) (Input, error) {
	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(r, h), 1<<20)
	in := Input{ID: id, Path: path}
	nodes := map[string]bool{}
	for no := 1; ; no++ {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if e := s.parse(line, id, no); e != nil {
				in.Records++
				if in.FirstWall == "" || e.TWall < in.FirstWall {
					in.FirstWall = e.TWall
				}
				if e.TWall > in.LastWall {
					in.LastWall = e.TWall
				}
				nodes[e.Node] = true
				k := [2]string{e.Node, e.Run}
				run := runs[k]
				if run == nil {
					run = &Run{Node: e.Node, ID: e.Run, Input: id}
					runs[k] = run
				}
				run.Events = append(run.Events, e)
				s.note(e)
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return in, err
		}
	}
	in.SHA256 = hex.EncodeToString(h.Sum(nil))
	for n := range nodes {
		in.Nodes = append(in.Nodes, n)
	}
	sort.Strings(in.Nodes)
	return in, nil
}

func (s *Set) parse(line []byte, id string, no int) *Event {
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(line))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: not a JSON object: %v", id, no, err))
		return nil
	}
	if t, ok := m["type"]; ok && m["kind"] == nil {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: record of type %s (records were dropped by the writer; the checks treat the stream as complete)", id, no, t))
		return nil
	}
	e := &Event{Input: id, Line: no, F: map[string]json.RawMessage{}}
	var v int
	bad := func(field string) *Event {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: missing or malformed field %s", id, no, field))
		return nil
	}
	if json.Unmarshal(m["v"], &v) != nil {
		return bad("v")
	}
	if v != FormatVersion {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: format version %d is not supported (want %d)", id, no, v, FormatVersion))
		return nil
	}
	if json.Unmarshal(m["node"], &e.Node) != nil || e.Node == "" {
		return bad("node")
	}
	if json.Unmarshal(m["run"], &e.Run) != nil || e.Run == "" {
		return bad("run")
	}
	if json.Unmarshal(m["seq"], &e.Seq) != nil {
		return bad("seq")
	}
	if json.Unmarshal(m["kind"], &e.Kind) != nil || e.Kind == "" {
		return bad("kind")
	}
	_ = json.Unmarshal(m["t_wall"], &e.TWall)
	if json.Unmarshal(m["t_mono_ns"], &e.TMono) != nil {
		return bad("t_mono_ns")
	}
	if raw, ok := m["view"]; ok {
		var vw View
		if json.Unmarshal(raw, &vw) != nil || dec(vw.Seq) == nil || dec(vw.Round) == nil {
			return bad("view")
		}
		e.View = &vw
	}
	if raw, ok := m["step"]; ok {
		var st uint64
		if json.Unmarshal(raw, &st) != nil {
			return bad("step")
		}
		e.Step = &st
	}
	if raw, ok := m["imp"]; ok {
		_ = json.Unmarshal(raw, &e.Imp)
	}
	if raw, ok := m["src"]; ok {
		_ = json.Unmarshal(raw, &e.Src)
	}
	for k, raw := range m {
		if !common[k] {
			e.F[k] = raw
		}
	}
	return e
}

func (s *Set) note(e *Event) {
	if !Known[e.Kind] {
		s.UnknownKinds[e.Kind]++
	}
	n := s.Nodes[e.Node]
	if n == nil {
		n = &NodeInfo{Address: e.Node}
		s.Nodes[e.Node] = n
	}
	if len(e.Imp) > 0 {
		n.Optional = true
	}
	if e.Kind == "NODE_START" {
		if impl := e.Str("impl"); impl != "" {
			n.Impl = impl
		}
		if raw, ok := e.F["improvements"]; ok {
			var list []json.RawMessage
			if json.Unmarshal(raw, &list) == nil && len(list) > 0 {
				n.Optional = true
			}
		}
	}
}

// Add adds a run read elsewhere (package logs) with its input; its events
// are in order.
func (s *Set) Add(in Input, r *Run) {
	s.Inputs = append(s.Inputs, in)
	for _, e := range r.Events {
		s.note(e)
	}
	r.index()
	s.Runs = append(s.Runs, r)
}

// index assigns engine segments and step groups. A segment ends with an
// ENGINE_STOP record; step numbers restart in the next engine run.
func (r *Run) index() {
	r.groups = map[groupKey][]int{}
	r.seg = make([]int, len(r.Events))
	seg := 0
	for i, e := range r.Events {
		r.seg[i] = seg
		if e.Step != nil {
			k := groupKey{seg, *e.Step}
			r.groups[k] = append(r.groups[k], i)
		}
		if e.Kind == "ENGINE_STOP" {
			seg++
		}
	}
}

// StepOf returns the indices of the events of the step of event i, in
// order, or nil when event i belongs to no step.
func (r *Run) StepOf(i int) []int {
	e := r.Events[i]
	if e.Step == nil {
		return nil
	}
	return r.groups[groupKey{r.seg[i], *e.Step}]
}

// Segment returns the engine segment of event i.
func (r *Run) Segment(i int) int { return r.seg[i] }
