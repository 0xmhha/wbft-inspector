package synccontrol

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/syncobs"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const testNode = "0xaa00000000000000000000000000000000000000"
const testRun = "controlled-downloader-policy"
const testHash = "0xbb00000000000000000000000000000000000000000000000000000000000000"

type row = map[string]any

type controlledSource struct{ events, frames, typed []row }

// These synthetic source coordinates exercise the independent reader/checker
// contract. They are not authentic journal bytes or an executed network.
func controlled() controlledSource {
	s := controlledSource{}
	kinds := []string{"NODE_START", "ENGINE_START", "ENGINE_STOP", "ENGINE_START", "ENGINE_STOP", "NEW_HEAD", "ENGINE_START", "NEW_HEAD", "ENGINE_STOP", "NODE_STOP"}
	for i, kind := range kinds {
		e := row{"v": 1, "node": testNode, "run": testRun, "seq": i, "kind": kind, "t_wall": "2026-01-01T00:00:00Z", "t_mono_ns": i}
		if i == 0 {
			e["validator"] = true
		}
		if kind == "NEW_HEAD" {
			e["number"] = "3"
			if i == 7 {
				e["number"] = "4"
			}
			e["hash"] = testHash
		}
		s.events = append(s.events, e)
	}
	s.typed = append(s.typed, row{"format": syncobs.Format, "type": "header", "node": testNode, "run": testRun, "validator": true, "core_start_seq": "0"})
	declaration := row{"v": 1, "node": testNode, "run": testRun, "type": "sync_trace", "seq": 1, "journal_segment": 0, "journal_offset": 0, "t_mono_ns": 0, "t_wall": "1970-01-01T00:00:00Z", "clock_source": "unavailable", "sync_trace": row{"version": "1", "requests": "6", "operations": "6", "complete": true, "event_cursor": "next_sequence"}}
	s.frames = append(s.frames, declaration)
	notifications := []string{"start", "failed", "start", "done", "start", "done"}
	actions := []string{"stop", "start", "stop", "start", "none", "none"}
	befores := []int{2, 3, 4, 6, 0, 0}
	afters := []int{3, 4, 5, 7, 0, 0}
	runningBefore := []bool{true, false, true, false, true, true}
	runningAfter := []bool{false, true, false, true, true, true}
	for i, kind := range notifications {
		id := strconv.Itoa(i + 1)
		n := row{"type": "notification", "sequence": id, "kind": kind, "posted_at_available": false}
		if kind == "done" {
			n["number"] = "3"
			if i == 5 {
				n["number"] = "4"
			}
			n["hash"] = testHash
		}
		s.typed = append(s.typed, n)
		reqseq := 2 + i*2
		request := row{"stage": "requested", "request": id, "operation": "0", "syncing": kind == "start", "success": kind == "done", "first_before": false, "first_after": false, "running_before": false, "running_after": false, "action": "", "failed": false, "events_available": false, "event_before": "0", "event_after": "0", "sequence_exhausted": false}
		operation := row{"stage": "processed", "request": id, "operation": id, "syncing": kind == "start", "success": kind == "done", "first_before": i > 3, "first_after": i >= 3, "running_before": runningBefore[i], "running_after": runningAfter[i], "action": actions[i], "failed": false, "events_available": actions[i] != "none", "event_before": strconv.Itoa(befores[i]), "event_after": strconv.Itoa(afters[i]), "sequence_exhausted": false, "request_source": row{"source_available": true, "source_seq": strconv.Itoa(reqseq), "source_segment": "0", "source_offset": strconv.Itoa(reqseq * 64)}}
		for j, c := range []row{request, operation} {
			seq := reqseq + j
			s.frames = append(s.frames, row{"v": 1, "node": testNode, "run": testRun, "type": "sync_control", "seq": seq, "journal_segment": 0, "journal_offset": seq * 64, "t_mono_ns": seq, "t_wall": "2026-01-01T00:00:00Z", "sync_control": c})
		}
	}
	s.typed = append(s.typed, row{"type": "footer", "observed": "6", "written": "6", "dropped": "0", "invalid": "0", "sequence_exhausted": false, "core_complete": true, "core_stop_seq": "9", "closed_normally": true, "complete": true})
	return s
}

func writeRows(t *testing.T, path string, rows []row) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for _, r := range rows {
		if err := encoder.Encode(r); err != nil {
			_ = f.Close()
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}
func inputs(t *testing.T, s controlledSource) *check.Inputs {
	t.Helper()
	root := t.TempDir()
	eventpath := filepath.Join(root, "events.jsonl")
	writeRows(t, eventpath, s.events)
	ev, err := events.Load([]string{eventpath})
	if err != nil {
		t.Fatal(err)
	}
	framepath := filepath.Join(root, "frames-"+testRun+".jsonl")
	writeRows(t, framepath, s.frames)
	dump, err := frames.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	dump.SetInput("in-frames")
	typedpath := filepath.Join(t.TempDir(), "notifications.jsonl")
	writeRows(t, typedpath, s.typed)
	typed, err := syncobs.Load(typedpath)
	if err != nil {
		t.Fatal(err)
	}
	typed.Input = "in-typed"
	return &check.Inputs{Events: ev, Frames: []*frames.Dump{dump}, SyncObservations: []*syncobs.Source{typed}}
}

type collector []verdict.Instance

func (c *collector) Emit(v verdict.Instance) { *c = append(*c, v) }
func judge(t *testing.T, in *check.Inputs) collector {
	t.Helper()
	var out collector
	if err := (downloaderCore{}).Run(context.Background(), in, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
func requireNoDecision(t *testing.T, out collector) {
	t.Helper()
	if len(out) == 0 {
		t.Fatal("no coverage instance")
	}
	for _, i := range out {
		if i.Verdict != verdict.CannotDecide {
			t.Fatal("incomplete evidence became decided", i)
		}
	}
}

func TestCompleteControlledSourcePassesWithSeparateOriginalPointers(t *testing.T) {
	in := inputs(t, controlled())
	out := judge(t, in)
	if len(out) != 6 {
		t.Fatal(out)
	}
	for i, v := range out {
		if v.Verdict != verdict.Pass || v.Requirement != requirement || v.Key != "sync:"+testRun+":"+strconv.Itoa(i+1) || len(v.Evidence) < 3 || v.Evidence[0].Kind != "log" || v.Evidence[0].Input != "in-typed" || v.Evidence[0].Line != i+2 || v.Evidence[1].Kind != "frame" || v.Evidence[2].Kind != "frame" || v.Evidence[1].FrameID == v.Evidence[2].FrameID {
			t.Fatal(v)
		}
	}
}

func TestSupersededRequestsRemainUndecidedWithOriginalEvidence(t *testing.T) {
	s := controlled()
	c := s.frames[4]["sync_control"].(row)
	c["request"] = "3"
	c["syncing"] = true
	c["action"] = "none"
	c["running_before"] = false
	c["running_after"] = false
	c["events_available"] = false
	c["event_before"] = "0"
	c["event_after"] = "0"
	c["request_source"] = row{"source_available": true, "source_seq": "6", "source_segment": "0", "source_offset": "384"}
	out := judge(t, inputs(t, s))
	requireNoDecision(t, out)
	if len(out) != 1 || out[0].Reason != verdict.ObserverScope || len(out[0].Evidence) < 4 {
		t.Fatal(out)
	}
}

func TestIncompleteOrAmbiguousSourcesNeverPass(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*check.Inputs)
	}{
		{"foreign-typed-process", func(in *check.Inputs) { in.SyncObservations[0].Header.Run = "another-run" }},
		{"duplicate-typed-source", func(in *check.Inputs) { in.SyncObservations = append(in.SyncObservations, in.SyncObservations[0]) }},
		{"duplicate-control-source", func(in *check.Inputs) { in.Frames = append(in.Frames, in.Frames[0]) }},
		{"missing-control-source", func(in *check.Inputs) { in.Frames = nil }},
		{"incomplete-typed-source", func(in *check.Inputs) { in.SyncObservations[0].Complete = false }},
		{"missing-footer", func(in *check.Inputs) { in.SyncObservations[0].Footer = nil }},
		{"wrong-stop-sequence", func(in *check.Inputs) { in.SyncObservations[0].Footer.CoreStopSeq = "10" }},
		{"lost-canonical-events", func(in *check.Inputs) { in.Events.Runs[0].Lost = []events.Span{{From: 2, To: 2}} }},
		{"legacy-log", func(in *check.Inputs) { in.Events.Runs[0].FromLog = true }},
		{"unknown-canonical-kind", func(in *check.Inputs) { in.Events.UnknownKinds["UNKNOWN"] = 1 }},
		{"missing-canonical-head", func(in *check.Inputs) {
			in.Events.Runs[0].Events[5].F["hash"] = json.RawMessage(`"0xcc00000000000000000000000000000000000000000000000000000000000000"`)
		}},
	} {
		t.Run(test.name, func(t *testing.T) { in := inputs(t, controlled()); test.edit(in); requireNoDecision(t, judge(t, in)) })
	}
}

func TestNoCallBoundaryAndOverlappingControlRangesStayUndecided(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*controlledSource)
	}{
		{"invented-none-cursor", func(s *controlledSource) {
			c := s.frames[10]["sync_control"].(row)
			c["events_available"] = true
			c["event_before"] = "7"
			c["event_after"] = "7"
		}},
		{"overlapping-call-range", func(s *controlledSource) { c := s.frames[4]["sync_control"].(row); c["event_before"] = "2" }},
		{"canonical-state-mismatch", func(s *controlledSource) { c := s.frames[2]["sync_control"].(row); c["running_before"] = false }},
	} {
		t.Run(test.name, func(t *testing.T) { s := controlled(); test.edit(&s); requireNoDecision(t, judge(t, inputs(t, s))) })
	}
}

func TestGuardOrFailedCallDoesNotInventPolicyPass(t *testing.T) {
	for _, field := range []string{"first_after", "failed"} {
		t.Run(field, func(t *testing.T) {
			s := controlled()
			c := s.frames[2]["sync_control"].(row)
			c[field] = true
			out := judge(t, inputs(t, s))
			if len(out) != 6 || out[0].Verdict != verdict.CannotDecide {
				t.Fatal(out)
			}
			for _, i := range out {
				if i.Verdict == verdict.Fail {
					t.Fatal("internal observation became a policy violation", i)
				}
			}
		})
	}
}

func TestObservedLaterStopFailsEvenWhenShutdownNeedsNoAdditionalStop(t *testing.T) {
	s := controlled()
	s.events[7] = row{"v": 1, "node": testNode, "run": testRun, "seq": 7, "kind": "ENGINE_STOP", "t_wall": "2026-01-01T00:00:00Z", "t_mono_ns": 7}
	s.events[8] = row{"v": 1, "node": testNode, "run": testRun, "seq": 8, "kind": "NEW_HEAD", "number": "4", "hash": testHash, "t_wall": "2026-01-01T00:00:00Z", "t_mono_ns": 8}
	c := s.frames[10]["sync_control"].(row)
	c["action"] = "stop"
	c["events_available"] = true
	c["event_before"] = "7"
	c["event_after"] = "8"
	c["running_after"] = false
	c = s.frames[12]["sync_control"].(row)
	c["running_before"] = false
	c["running_after"] = false
	out := judge(t, inputs(t, s))
	if len(out) != 6 || out[4].Verdict != verdict.Fail {
		t.Fatal(out)
	}
	found := false
	for _, e := range out[4].Evidence {
		found = found || (e.Kind == "event" && e.Msg == "ENGINE_STOP")
	}
	if !found {
		t.Fatal("failure lacks its actual stop event", out[4])
	}
}

func TestUnexercisedLaterCycleKeepsOverallPolicyUndecided(t *testing.T) {
	s := controlled()
	s.frames = s.frames[:9]
	trace := s.frames[0]["sync_trace"].(row)
	trace["requests"] = "4"
	trace["operations"] = "4"
	footer := s.typed[len(s.typed)-1]
	footer["observed"] = "4"
	footer["written"] = "4"
	s.typed = append(s.typed[:5], footer)
	out := judge(t, inputs(t, s))
	if len(out) != 5 {
		t.Fatal(out)
	}
	for _, instance := range out[:4] {
		if instance.Verdict != verdict.Pass {
			t.Fatal(instance)
		}
	}
	last := out[4]
	if last.Verdict != verdict.CannotDecide || last.Reason != verdict.NotExercised {
		t.Fatal(last)
	}
}
