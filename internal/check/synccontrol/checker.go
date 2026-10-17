package synccontrol

import (
	"context"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const requirement = "SNET-SYNC-030"

func init() {
	check.Register(downloaderCore{check.Base{ID: "sync.downloader_core", Reqs: []string{requirement}, Kinds: []check.Kind{check.Events, check.Frames, check.SyncObservations}}})
}

// Only a closed, unique source context can produce a decided instance.
type downloaderCore struct{ check.Base }

func (c downloaderCore) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	if in.Events == nil {
		return nil
	}
	for _, run := range in.Events.Runs {
		if run == nil || len(run.Events) == 0 || run.Events[0] == nil {
			continue
		}
		anchor := run.Events[0]
		view, err := retainedContext(in, run)
		if err != nil {
			instance := check.Undecided(requirement, anchor, verdict.ObserverScope, err.Error())
			instance.Key = "sync-source:" + run.ID
			instance.Evidence = append(instance.Evidence, sourceEvidence(in, run)...)
			out.Emit(instance)
			continue
		}
		if !view.typed.Header.Validator || len(view.operations) == 0 {
			out.Emit(check.Undecided(requirement, anchor, verdict.NotExercised, "no validator downloader cycle in the retained process"))
			continue
		}
		lifecycles, err := controlLifecycles(view)
		if err != nil {
			out.Emit(check.Undecided(requirement, anchor, verdict.ObserverScope, err.Error()))
			continue
		}
		first := false
		failed, firstSuccess, laterStart, laterEnd := false, false, false, false
		for i, notification := range view.typed.Notifications {
			op := view.operations[i]
			control := op.SyncControl
			before := first
			if notification.Kind == "failed" && !first {
				failed = true
			}
			if notification.Kind == "start" && first {
				laterStart = true
			}
			if notification.Kind != "start" && first && laterStart {
				laterEnd = true
			}
			if notification.Kind == "done" && !first {
				first = true
				firstSuccess = true
			}
			want := "none"
			if !before {
				want = "start"
				if notification.Kind == "start" {
					want = "stop"
				}
			}
			value, reason, message := verdict.Pass, verdict.Reason(""), "recorded control follows the uniquely matched downloader notification"
			switch {
			case before && len(lifecycles[i]) == 1 && lifecycles[i][0].Kind == "ENGINE_STOP":
				value, message = verdict.Fail, "later downloader handling stopped the core after the first successful sync"
			case !before && notification.Kind == "start" && len(lifecycles[i]) == 1 && lifecycles[i][0].Kind == "ENGINE_START":
				value, message = verdict.Fail, "downloader start restarted the core before the first successful sync"
			case !before && notification.Kind != "start" && len(lifecycles[i]) == 1 && lifecycles[i][0].Kind == "ENGINE_STOP":
				value, message = verdict.Fail, "downloader completion stopped the core before the first successful sync"
			case *control.FirstBefore != before || *control.FirstAfter != first:
				value, reason, message = verdict.CannotDecide, verdict.InconsistentInput, "recorded first-success guard differs from the complete notification sequence"
			case *control.Failed:
				value, reason, message = verdict.CannotDecide, verdict.ObserverScope, "control call failed; successful lifecycle completion is not established"
			case control.Action != want:
				value, reason, message = verdict.CannotDecide, verdict.ObserverScope, "the required control action has no uniquely attributable call range"
			case want == "none" && (!*control.RunningBefore || !*control.RunningAfter):
				value, reason, message = verdict.CannotDecide, verdict.ObserverScope, "later no-call handling lacks a continuously running core state"
			case want != "none" && (len(lifecycles[i]) != 1 || *control.RunningAfter != (want == "start")):
				value, reason, message = verdict.CannotDecide, verdict.ObserverScope, "control call lacks the complete canonical lifecycle transition"
			}
			instance := verdict.Instance{Requirement: requirement, Node: run.Node, Key: fmt.Sprintf("sync:%s:%s", run.ID, notification.Sequence), Verdict: value, Reason: reason, Message: message, Source: op.Input, Evidence: []evidence.Pointer{view.typed.Pointer(notification.Line), check.FramePointer(view.requests[i]), check.FramePointer(op)}}
			for _, event := range lifecycles[i] {
				instance.Evidence = append(instance.Evidence, check.Pointer(event))
			}
			if notification.Kind == "done" {
				instance.Evidence = append(instance.Evidence, check.Pointer(view.heads[[2]string{notification.Number, notification.Hash}]))
			}
			out.Emit(instance)
		}
		for _, branch := range []struct {
			name string
			seen bool
		}{{"failed-before-first-success", failed}, {"first-success", firstSuccess}, {"later-cycle", laterStart && laterEnd}} {
			if branch.seen {
				continue
			}
			instance := check.Undecided(requirement, anchor, verdict.NotExercised, "required downloader branch not exercised: "+branch.name)
			instance.Key = "sync-branch:" + run.ID + ":" + branch.name
			out.Emit(instance)
		}
	}
	return nil
}

func sourceEvidence(in *check.Inputs, run *events.Run) []evidence.Pointer {
	var pointers []evidence.Pointer
	for _, source := range in.SyncObservations {
		if source == nil || source.Header.Node != run.Node || source.Header.Run != run.ID {
			continue
		}
		pointers = append(pointers, source.Pointer(1))
		if source.Footer != nil {
			pointers = append(pointers, source.Pointer(source.FooterLine))
		}
		if len(pointers) >= 6 {
			break
		}
	}
	// Repeated handling is evidence of missing one-to-one coverage, not a
	// repaired association with the typed notification at the same ordinal.
	seen := map[string]bool{}
	for _, dump := range in.Frames {
		if dump == nil {
			continue
		}
		for _, record := range dump.Records {
			if record.Node != run.Node || record.Run != run.ID || record.SyncControl == nil || record.SyncControl.Stage != "processed" {
				continue
			}
			request := record.SyncControl.Request
			if seen[request] {
				pointers = append(pointers, check.FramePointer(record))
				if len(pointers) >= 10 {
					return pointers
				}
			}
			seen[request] = true
		}
	}
	return pointers
}
