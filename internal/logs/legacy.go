package logs

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

// Legacy logs have no complete-stream declaration, step, monotonic clock or
// transport outcome. Only observable facts are normalized; missing fields
// are never filled with invented timer generations or message bytes.
func loadLegacy(ctx context.Context, p *Profile, files []File, w Window) (*events.Set, error) {
	if w.From.IsZero() != w.To.IsZero() || (!w.From.IsZero() && w.To.Before(w.From)) {
		return nil, errors.New("invalid log time window")
	}
	limit := w.MaxEvents
	if limit == 0 {
		limit = 200000
	}
	if limit < 1 || limit > 1000000 {
		return nil, errors.New("log event limit must be 1..1000000")
	}
	s := &events.Set{Nodes: map[string]*events.NodeInfo{}, UnknownKinds: map[string]int{}}
	total := 0
	for i, lf := range files {
		id := fmt.Sprintf("log-%d", i+1)
		f, err := os.Open(lf.Path)
		if err != nil {
			return nil, err
		}
		in, runs, diagnostics, err := legacyRead(ctx, p, f, id, lf.Node, lf.Path, w, limit-total)
		f.Close()
		if err != nil {
			return nil, err
		}
		total += in.Records
		s.Inputs = append(s.Inputs, in)
		s.Errors = append(s.Errors, diagnostics...)
		for _, run := range runs {
			// Set.Add indexes engine boundaries and nodes; the input itself is added once.
			s.Add(in, run)
			s.Inputs = s.Inputs[:len(s.Inputs)-1]
		}
		if info := s.Nodes[lf.Node]; info != nil {
			info.Impl = p.ID
			for _, r := range runs {
				for _, e := range r.Events {
					if a := e.Str("address"); addressRE.MatchString(a) {
						if info.Address == lf.Node {
							info.Address = a
						} else if !strings.EqualFold(info.Address, a) {
							info.Address = ""
						}
					}
				}
			}
		}
	}
	return s, nil
}

func legacyRead(ctx context.Context, p *Profile, r io.Reader, id, node, path string, w Window, limit int) (events.Input, []*events.Run, []string, error) {
	in := events.Input{ID: id, Path: path, Nodes: []string{node}}
	h := sha256.New()
	scan := bufio.NewScanner(io.TeeReader(r, h))
	scan.Buffer(make([]byte, 64<<10), 4<<20)
	runs := []*events.Run{}
	var run *events.Run
	var view *events.View
	generation := 0
	previousStart, lastStart := 0, 0
	unknown, malformed := 0, 0
	line := 0
	for scan.Scan() {
		line++
		if err := ctx.Err(); err != nil {
			return in, nil, nil, err
		}
		raw := bytes.TrimSpace(scan.Bytes())
		if len(raw) == 0 {
			continue
		}
		m, err := legacyObject(raw)
		if err != nil {
			malformed++
			continue
		}
		msg := text(m["msg"])
		if !strings.HasPrefix(msg, "WBFT: ") {
			continue
		}
		entry, ok := p.byLine[[2]string{msg, ""}]
		if !ok {
			for _, e := range p.Entries {
				if e.pattern != nil && e.pattern.MatchString(msg) {
					entry, ok = e, true
					break
				}
			}
		}
		lv := text(m["lvl"])
		if lv == "" {
			lv = text(m["level"])
		}
		if !ok || levels[lv] != entry.Level {
			unknown++
			continue
		}
		wall, err := time.Parse(time.RFC3339Nano, text(m["t"]))
		if err != nil {
			malformed++
			continue
		}
		if entry.Kind == "ENGINE_STOP" {
			view = nil
		}
		if entry.Kind == "ENGINE_START" && msg == "WBFT: start" && m["address"] != nil {
			generation++
			previousStart, lastStart = lastStart, line
			view = nil
			run = nil
		}
		v := legacyView(entry.Kind, m, view)
		if entry.Kind == "ROUND_ENTER" && v != nil {
			copy := *v
			view = &copy
		}
		if !w.From.IsZero() && (wall.Before(w.From) || wall.After(w.To)) {
			continue
		}
		if in.Records >= limit {
			return in, nil, nil, errors.New("legacy log window exceeds event limit; narrow the window")
		}
		if run == nil {
			run = &events.Run{Node: node, ID: id + ":" + strconv.Itoa(generation), Input: id, FromLog: true, Complete: false}
			runs = append(runs, run)
		}
		e := &events.Event{Node: node, Run: run.ID, Input: id, Line: line, Seq: uint64(len(run.Events)), Kind: entry.Kind, View: v, TWall: wall.UTC().Format(time.RFC3339Nano), FromLog: true, Src: "log", F: legacyFields(m)}
		if entry.Kind == "ENGINE_START" && msg == "WBFT: start" && m["address"] != nil && previousStart > 0 {
			e.F["previous_engine_start_line"] = json.RawMessage(strconv.Itoa(previousStart))
		}
		for k, v := range entry.Fields {
			e.F[k] = jsonString(v)
		}
		if code := number(m["msg.code"]); code != "" {
			e.F["code"] = json.RawMessage(code)
		}
		if entry.Kind == "STATE" {
			if state := text(m["new.state"]); state != "" {
				e.F["state"] = jsonString(state)
			}
		}
		run.Events = append(run.Events, e)
		in.Records++
		if in.FirstWall == "" {
			in.FirstWall = e.TWall
		}
		in.LastWall = e.TWall
	}
	if err := scan.Err(); err != nil {
		return in, nil, nil, errors.New("log read failed or line exceeds 4MiB")
	}
	in.SHA256 = hex.EncodeToString(h.Sum(nil))
	diagnostics := []string{}
	if unknown > 0 || malformed > 0 {
		diagnostics = append(diagnostics, fmt.Sprintf("%s: unknown consensus phrases %d; malformed records %d", id, unknown, malformed))
	}
	return in, runs, diagnostics, nil
}
func legacyView(kind string, m map[string]json.RawMessage, current *events.View) *events.View {
	h, r := "current.sequence", "current.round"
	if kind == "ROUND_ENTER" {
		h, r = "next.seq", "next.round"
	}
	if a, b := number(m[h]), number(m[r]); a != "" && b != "" {
		return &events.View{Seq: a, Round: b}
	}
	if kind == "NEW_HEAD" {
		if n := number(m["number"]); n != "" {
			v := &events.View{Seq: n}
			if current != nil && current.Seq == n {
				v.Round = current.Round
			}
			return v
		}
	}
	if current != nil && kind != "ENGINE_STOP" && m["address"] != nil {
		v := *current
		return &v
	}
	return nil
}
func text(raw json.RawMessage) string { var s string; _ = json.Unmarshal(raw, &s); return s }

var decimalRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,155})$`)
var addressRE = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)
var hashRE = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

func number(raw json.RawMessage) string {
	s := text(raw)
	if s == "" {
		s = string(raw)
	}
	if decimalRE.MatchString(s) {
		return s
	}
	return ""
}
func jsonString(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
func legacyFields(m map[string]json.RawMessage) map[string]json.RawMessage {
	out := map[string]json.RawMessage{}
	for _, k := range []string{"address", "author", "source", "from", "msg.source", "next.proposer", "old.proposer", "addr"} {
		if s := text(m[k]); addressRE.MatchString(s) {
			out[k] = jsonString(strings.ToLower(s))
		}
	}
	for _, k := range []string{"hash", "block.hash", "proposal.hash", "lastProposal.hash", "digest"} {
		if s := text(m[k]); hashRE.MatchString(s) {
			out[k] = jsonString(strings.ToLower(s))
		}
	}
	for _, k := range []string{"current.sequence", "current.round", "msg.sequence", "msg.round", "next.seq", "next.round", "number", "round", "sequence", "quorum", "prepares.count", "commits.count", "F"} {
		if n := number(m[k]); n != "" {
			out[k] = jsonString(n)
		}
	}
	return out
}

// First envelope msg wins: geth can add another msg in logger context.
// Other duplicate keys and trailing values are rejected without echoing bytes.
func legacyObject(raw []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	m := map[string]json.RawMessage{}
	for d.More() {
		t, err = d.Token()
		if err != nil {
			return nil, err
		}
		k, ok := t.(string)
		if !ok {
			return nil, errors.New("bad key")
		}
		var v json.RawMessage
		if err = d.Decode(&v); err != nil {
			return nil, err
		}
		if m[k] != nil {
			if k == "msg" {
				continue
			}
			return nil, errors.New("duplicate key")
		}
		m[k] = v
	}
	if _, err = d.Token(); err != nil {
		return nil, err
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, errors.New("trailing value")
	}
	return m, nil
}

// CorrelatedTrigger links positive observations only. It makes no assertion
// that an absent line proves a missing send, timeout or transport action.
func CorrelatedTrigger(prior, current *events.Event) string {
	if prior == nil || prior.View == nil || current.View == nil || prior.Run != current.Run || prior.Node != current.Node || prior.View.Seq != current.View.Seq {
		return ""
	}
	a, e1 := time.Parse(time.RFC3339Nano, prior.TWall)
	b, e2 := time.Parse(time.RFC3339Nano, current.TWall)
	if e1 != nil || e2 != nil || b.Before(a) {
		return ""
	}
	before, after := prior.View.RoundBig(), current.View.RoundBig()
	if before == nil || after == nil || after.Cmp(before) <= 0 {
		return ""
	}
	if prior.Kind == "TIMER_FIRE" && prior.Str("timer") == "round" {
		target := new(big.Int).Add(before, big.NewInt(1))
		if after.Cmp(target) == 0 {
			return "timeout"
		}
	}
	if prior.Kind == "QUORUM" && prior.Str("what") == "F_PLUS_ONE" {
		return "f_plus_one"
	}
	return ""
}

func legacyDefault(key, value string) bool {
	values := map[string]string{"phase": "PRE-PREPARE|PREPARE|COMMIT|ROUND-CHANGE", "cause": "broadcast", "action": "handle", "outcome": "ACCEPT", "what": "PREPARE|COMMIT|ROUND_CHANGE|F_PLUS_ONE", "timer": "round|retry", "path": "sealed_locally"}
	for _, v := range strings.Split(values[key], "|") {
		if v != "" && v == value {
			return true
		}
	}
	return false
}
