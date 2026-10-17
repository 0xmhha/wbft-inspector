package frames

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"slices"
	"strconv"
	"time"
)

type SchedulerTrace struct {
	Version    string `json:"version"`
	Operations string `json:"operations"`
	Steps      string `json:"steps"`
}

// TimerOperation is closed metadata; full encoded timeout bytes stay local.
type TimerOperation struct {
	Sequence      string   `json:"sequence"`
	Action        string   `json:"action"`
	Source        string   `json:"source"`
	Output        string   `json:"output"`
	ArmEngine     string   `json:"arm_engine_run"`
	ArmStep       string   `json:"arm_step"`
	ArmOutput     string   `json:"arm_output"`
	EntryMono     string   `json:"arm_entry_mono_ns"`
	Deadline      string   `json:"deadline_mono_ns"`
	TimeoutSHA256 string   `json:"timeout_sha256,omitempty"`
	Timer         string   `json:"timer,omitempty"`
	Generation    string   `json:"generation,omitempty"`
	Height        string   `json:"height,omitempty"`
	Round         string   `json:"round,omitempty"`
	Kinds         []string `json:"cancel_kinds"`
	Decode        string   `json:"decode"`
}

type SchedulerSource struct {
	Declaration *Record
	Operations  []*Record
	Steps       []*Record
	Records     []*Record
}

func decodeSchedulerFields(fields map[string]json.RawMessage, r *Record) error {
	names := []string{"entry_t_mono_ns", "entry_t_wall"}
	if slices.Contains([]string{"scheduler_trace", "scheduler_step", "timer_operation"}, r.Type) {
		names = append(names, commonFields...)
	}
	for _, name := range names {
		if b, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
			return fmt.Errorf("null scheduler field %s", name)
		}
	}
	for name, target := range map[string]any{"scheduler_trace": &r.SchedulerTrace, "timer_operation": &r.TimerOperation} {
		b, ok := fields[name]
		if !ok {
			continue
		}
		if bytes.Equal(bytes.TrimSpace(b), []byte("null")) || !uniqueFields(b) {
			return fmt.Errorf("invalid %s metadata", name)
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(target); err != nil {
			return err
		}
		if d.Decode(new(any)) != io.EOF {
			return fmt.Errorf("trailing scheduler metadata")
		}
	}
	return nil
}

func SchedulerDecimal(s string) bool {
	n, ok := new(big.Int).SetString(s, 10)
	return ok && n.Sign() >= 0 && n.String() == s
}
func SchedulerUint(s string) (uint64, bool) {
	n, e := strconv.ParseUint(s, 10, 64)
	return n, e == nil && strconv.FormatUint(n, 10) == s
}
func SchedulerMono(s string) (int64, bool) {
	n, e := strconv.ParseInt(s, 10, 64)
	return n, e == nil && n >= 0 && strconv.FormatInt(n, 10) == s
}

// SchedulerSources checks source shape and snapshot counts. A consumer must
// additionally replay operation order and bind it to the event's own step.
func SchedulerSources(d *Dump) ([]SchedulerSource, []string) {
	groups := map[[3]string]*SchedulerSource{}
	identities := map[string][2]string{}
	var order [][3]string
	problems := slices.Clone(d.Malformed)
	add := func(r *Record, msg string) { problems = append(problems, r.Where()+": "+msg) }
	for _, r := range d.Records {
		if id, ok := identities[r.File]; ok && id != [2]string{r.Node, r.Run} {
			add(r, "mixed scheduler file identity")
		} else {
			identities[r.File] = [2]string{r.Node, r.Run}
		}
		k := [3]string{r.File, r.Node, r.Run}
		g := groups[k]
		if g == nil {
			g = &SchedulerSource{}
			groups[k] = g
			order = append(order, k)
		}
		g.Records = append(g.Records, r)
		if r.Type == "scheduler_trace" {
			if g.Declaration != nil {
				add(r, "duplicate scheduler declaration")
			}
			g.Declaration = r
		}
		if r.Type == "timer_operation" {
			g.Operations = append(g.Operations, r)
		}
		if r.Type == "scheduler_step" || r.Type == "own_input" {
			g.Steps = append(g.Steps, r)
		}
		if r.SchedulerTrace != nil && r.Type != "scheduler_trace" || r.TimerOperation != nil && r.Type != "timer_operation" {
			add(r, "scheduler metadata on another record type")
		}
	}
	var result []SchedulerSource
	for _, key := range order {
		g := groups[key]
		if g.Declaration == nil {
			if len(g.Operations) > 0 {
				add(g.Operations[0], "scheduler operations lack declaration")
			}
			for _, r := range g.Steps {
				if r.Type == "scheduler_step" {
					add(r, "scheduler step lacks declaration")
				}
			}
			continue
		}
		dc := g.Declaration
		tr := dc.SchedulerTrace
		if tr == nil {
			add(dc, "missing scheduler declaration")
			continue
		}
		ops, o := SchedulerUint(tr.Operations)
		steps, s := SchedulerUint(tr.Steps)
		if tr.Version != "1" || !o || !s || ops != uint64(len(g.Operations)) || steps != uint64(len(g.Steps)) {
			add(dc, "scheduler snapshot counts or version differ")
		}
		if dc.ClockSource != "unavailable" || dc.TMono != 0 || dc.TWall != "1970-01-01T00:00:00Z" {
			add(dc, "declaration invents a measured clock")
		}
		seqs := map[uint64]bool{}
		positions := map[[2]uint64]bool{}
		stepIDs := map[[2]uint64]bool{}
		for _, r := range g.Records {
			if seqs[r.Seq] {
				add(r, "duplicate scheduler source sequence")
			}
			seqs[r.Seq] = true
			if r.Type == "dropped" {
				add(r, "scheduler source has a gap")
			}
			isStep := r.Type == "scheduler_step" || r.Type == "own_input"
			if r.Type != "scheduler_trace" && r.Type != "timer_operation" && !isStep {
				continue
			}
			for _, name := range commonFields {
				if !r.Has(name) {
					add(r, "missing scheduler field "+name)
				}
			}
			if r.Seq == 0 || r.V != 1 || !addressPattern.MatchString(r.Node) || r.Run == "" {
				add(r, "invalid scheduler source identity")
			}
			if r.JournalSegment == nil || r.JournalOffset == nil || *r.JournalOffset < 0 {
				add(r, "scheduler source position missing")
			} else {
				p := [2]uint64{*r.JournalSegment, uint64(*r.JournalOffset)}
				if positions[p] {
					add(r, "duplicate scheduler source position")
				}
				positions[p] = true
			}
			allowed := []string{"v", "type", "node", "run", "seq", "t_wall", "t_mono_ns", "journal_segment", "journal_offset"}
			switch r.Type {
			case "scheduler_trace":
				allowed = append(allowed, "scheduler_trace", "clock_source")
				if r.SyncTrace != nil {
					allowed = append(allowed, "sync_trace")
				}
				if r.CacheTrace != nil {
					allowed = append(allowed, "cache_trace")
				}
			case "timer_operation":
				allowed = append(allowed, "engine_run", "step", "timer_operation")
			case "scheduler_step":
				allowed = append(allowed, "engine_run", "step", "input_kind", "via", "entry_t_mono_ns", "entry_t_wall")
			}
			if r.Type != "own_input" {
				for k := range r.present {
					if !slices.Contains(allowed, k) {
						add(r, "unknown scheduler field "+k)
					}
				}
			}
			if r.Type == "scheduler_trace" {
				continue
			}
			if r.EngineRun == nil || r.Step == nil {
				add(r, "scheduler engine/step missing")
				continue
			}
			if r.TMono < 0 {
				add(r, "negative scheduler clock")
			}
			if _, err := time.Parse(time.RFC3339Nano, r.TWall); err != nil {
				add(r, "invalid measured scheduler wall clock")
			}
			if isStep {
				if r.InputKind == "" || r.Via == "" {
					add(r, "missing scheduler input origin")
				}
				k := [2]uint64{*r.EngineRun, *r.Step}
				if stepIDs[k] {
					add(r, "duplicate scheduler engine/step")
				}
				stepIDs[k] = true
				if (r.EntryMono == nil) != (r.EntryWall == "") {
					add(r, "partial scheduler entry clock")
				}
				if r.EntryMono != nil {
					n, ok := SchedulerMono(*r.EntryMono)
					if !ok || n > r.TMono {
						add(r, "invalid scheduler entry clock")
					}
					if _, err := time.Parse(time.RFC3339Nano, r.EntryWall); err != nil {
						add(r, "invalid scheduler entry wall clock")
					}
				}
				continue
			}
			op := r.TimerOperation
			if op == nil {
				add(r, "missing scheduler operation")
				continue
			}
			for _, v := range []string{op.Sequence, op.Output, op.ArmEngine, op.ArmStep, op.ArmOutput} {
				if _, ok := SchedulerUint(v); !ok {
					add(r, "invalid scheduler counter")
				}
			}
			n, _ := SchedulerUint(op.Sequence)
			entry, e := SchedulerMono(op.EntryMono)
			end, deadline := SchedulerMono(op.Deadline)
			if n == 0 || !e || !deadline || entry > r.TMono || !slices.Contains([]string{"core", "restore", "lifecycle", "dequeue"}, op.Source) || !slices.Contains([]string{"arm", "replace", "cancelled", "queued", "pop", "cancel", "clear"}, op.Action) || op.Kinds == nil {
				add(r, "invalid scheduler operation shape")
			}
			if op.Action == "cancel" || op.Action == "clear" {
				if op.TimeoutSHA256 != "" || op.Decode != "not_applicable" || op.Timer != "" || op.Generation != "" || op.Height != "" || op.Round != "" || op.ArmEngine != "0" || op.ArmStep != "0" || op.ArmOutput != "0" || op.EntryMono != "0" || op.Deadline != "0" {
					add(r, "cancellation invents a timeout")
				}
				seen := map[string]bool{}
				for _, k := range op.Kinds {
					if !slices.Contains([]string{"round", "retry", "future"}, k) || seen[k] {
						add(r, "invalid cancellation kinds")
					}
					seen[k] = true
				}
				if op.Action == "clear" && len(op.Kinds) != 0 {
					add(r, "clear has cancellation kinds")
				}
			} else {
				_, gok := SchedulerUint(op.Generation)
				hok := SchedulerDecimal(op.Height)
				rok := SchedulerDecimal(op.Round)
				if end < entry || !gok || !hok || !rok || !sha256Pattern.MatchString(op.TimeoutSHA256) || op.Decode != "complete" || !slices.Contains([]string{"round", "retry", "future"}, op.Timer) || len(op.Kinds) != 0 {
					add(r, "incomplete scheduler timeout")
				}
			}
		}
		result = append(result, *g)
	}
	return result, problems
}
