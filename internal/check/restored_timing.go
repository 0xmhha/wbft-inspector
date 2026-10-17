package check

import (
	"bytes"
	"encoding/json"
	"io"
	"math"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

type restoredArm struct {
	start, arm *events.Event
	from       int64
	valid      bool
}

// TimerTiming indexes explicit restored deadlines in canonical event streams.
// A deadline is usable only within an uninterrupted replay lifecycle and for
// the same live timer. Legacy arms keep their original timing interpretation.
type TimerTiming struct {
	fires map[*events.Event]*restoredArm
}

func NewTimerTiming(in *Inputs) *TimerTiming {
	t := &TimerTiming{fires: map[*events.Event]*restoredArm{}}
	if in.Events == nil {
		return t
	}
	for _, run := range in.Events.Runs {
		var start, previous *events.Event
		var engine, lastEngine int64
		healthy, restoring := false, false
		live := map[string]*restoredArm{}
		seen := map[string]bool{}
		for _, e := range run.Events {
			identity := e.Node == run.Node && e.Run == run.ID && !e.FromLog && !run.FromLog && e.TMono >= 0
			ordered := previous == nil || (previous.Seq < math.MaxUint64 && e.Seq == previous.Seq+1 && e.TMono >= previous.TMono)
			if !identity || !ordered {
				healthy = false
			}
			previous = e
			if e.Kind == "ENGINE_START" {
				start = e
				var ok bool
				engine, ok = timingInt(e, "engine_run")
				healthy = identity && ordered && len(in.Events.Errors) == 0 && len(in.Events.UnknownKinds) == 0 && len(run.Lost) == 0 && ok && engine > lastEngine && e.Step == nil && replaySucceeded(e)
				lastEngine = max(lastEngine, engine)
				restoring = healthy
				live, seen = map[string]*restoredArm{}, map[string]bool{}
				continue
			}
			if e.Has("engine_run") {
				er, ok := timingInt(e, "engine_run")
				if !ok || er != engine {
					healthy = false
				}
			}
			if e.Kind == "ENGINE_STOP" || e.Kind == "NODE_STOP" {
				healthy, restoring = false, false
			}
			rearmed, _ := e.Bool("rearmed")
			if e.Kind == "TIMER_ARM" {
				kind := e.Str("timer")
				delete(live, kind)
				if rearmed && e.Has("deadline_mono_ns") {
					a := &restoredArm{start: start, arm: e}
					deadline, deadlineOK := timingInt(e, "deadline_mono_ns")
					duration, durationOK := timingInt(e, "duration_ms")
					er, erOK := timingInt(e, "engine_run")
					generation, genOK := timingInt(e, "gen")
					if healthy && restoring && !seen[kind] && e.Step == nil && erOK && er == engine && genOK && generation >= 0 &&
						(kind == events.TimerRound || kind == events.TimerRetry || kind == events.TimerFuture) && timingView(e.View) &&
						durationOK && duration >= 0 && duration <= math.MaxInt64/1_000_000 && deadlineOK && deadline >= duration*1_000_000 {
						a.from = deadline - duration*1_000_000
						a.valid = a.from >= start.TMono && a.from <= e.TMono
					}
					live[kind] = a
				}
				if !rearmed {
					restoring = false
				}
				seen[kind] = true
			} else {
				restoring = false
			}
			if e.Kind == "TIMER_CANCEL" {
				delete(live, e.Str("timer"))
			}
			if e.Kind == "TIMER_FIRE" {
				kind := e.Str("timer")
				if a := live[kind]; a != nil {
					// Store a copy: a later event must not invalidate a proved
					// earlier prefix, or make an incomplete earlier prefix valid.
					proof := *a
					liveExpiry := bytes.Equal(bytes.TrimSpace(e.F["stale"]), []byte("false"))
					proof.valid = proof.valid && healthy && liveExpiry && e.Step != nil && *e.Step > 0 &&
						timingSameInt(a.arm, e, "engine_run") && timingSameInt(a.arm, e, "gen") && a.arm.View.Equal(e.View) && e.TMono >= a.from
					t.fires[e] = &proof
				}
				delete(live, kind)
			}
		}
	}
	return t
}

// Elapsed returns the elapsed duration and the events that establish its
// origin. A nonempty explanation means the explicit new evidence is unusable;
// callers must keep that instance undecided rather than fall back silently.
func (t *TimerTiming) Elapsed(arm, fire *events.Event) (int64, string, []*events.Event) {
	if !arm.Has("rearmed") || !arm.Has("deadline_mono_ns") {
		return fire.TMono - arm.TMono, "", nil
	}
	a := t.fires[fire]
	if a == nil || a.arm != arm || !a.valid {
		return 0, "explicit restored deadline lacks an uninterrupted matching replay lifecycle", nil
	}
	return fire.TMono - a.from, "", []*events.Event{a.start, a.arm}
}

func timingInt(e *events.Event, key string) (int64, bool) {
	n, ok := e.Int(key)
	return n, ok && bytes.Equal(bytes.TrimSpace(e.F[key]), []byte(strconv.FormatInt(n, 10)))
}

func timingSameInt(a, b *events.Event, key string) bool {
	x, ok := timingInt(a, key)
	y, yes := timingInt(b, key)
	return ok && yes && x == y
}

func timingView(v *events.View) bool {
	if v == nil {
		return false
	}
	h, r := v.SeqBig(), v.RoundBig()
	return h != nil && r != nil && h.Sign() >= 0 && r.Sign() >= 0 && h.String() == v.Seq && r.String() == v.Round
}

func replaySucceeded(e *events.Event) bool {
	fields := map[string]json.RawMessage{}
	d := json.NewDecoder(bytes.NewReader(e.F["replay"]))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return false
		}
		switch key {
		case "replayed", "records", "stopped", "available", "enabled":
		default:
			return false
		}
		if _, duplicate := fields[key]; duplicate {
			return false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return false
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return false
	}
	if !bytes.Equal(bytes.TrimSpace(fields["replayed"]), []byte("true")) ||
		!bytes.Equal(bytes.TrimSpace(fields["stopped"]), []byte("null")) {
		return false
	}
	record := &events.Event{F: fields}
	n, ok := timingInt(record, "records")
	if !ok || n <= 0 {
		return false
	}
	for _, key := range []string{"available", "enabled"} {
		if raw, exists := fields[key]; exists && !bytes.Equal(bytes.TrimSpace(raw), []byte("true")) {
			return false
		}
	}
	return true
}
