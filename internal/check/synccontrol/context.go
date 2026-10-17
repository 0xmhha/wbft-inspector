// Package synccontrol compares retained downloader notifications with the
// core's request processing and canonical lifecycle. Wall time is not a join.
package synccontrol

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/syncobs"
)

type contextView struct {
	run        *events.Run
	typed      *syncobs.Source
	source     frames.SyncSource
	requests   []*frames.Record
	operations []*frames.Record
	// running[i] describes the canonical state immediately before next seq i.
	running []bool
	heads   map[[2]string]*events.Event
}

func number(value string) uint64 { n, _ := strconv.ParseUint(value, 10, 64); return n }

func retainedContext(in *check.Inputs, run *events.Run) (*contextView, error) {
	if run == nil || run.FromLog || len(run.Lost) != 0 || len(run.Events) < 2 || in.Events == nil || len(in.Events.Errors) != 0 || len(in.Events.UnknownKinds) != 0 {
		return nil, errors.New("canonical process coverage is unavailable")
	}
	if run.Events[0] == nil || run.Events[len(run.Events)-1] == nil || run.Events[0].Kind != "NODE_START" || run.Events[len(run.Events)-1].Kind != "NODE_STOP" {
		return nil, errors.New("canonical process lifecycle is incomplete")
	}
	v := &contextView{run: run, heads: map[[2]string]*events.Event{}, running: make([]bool, len(run.Events)+1)}
	running := false
	for i, e := range run.Events {
		if e == nil || e.Seq != uint64(i) || e.Node != run.Node || e.Run != run.ID || e.FromLog {
			return nil, errors.New("canonical process sequence or identity is incomplete")
		}
		if i > 0 && e.Kind == "NODE_START" || i < len(run.Events)-1 && e.Kind == "NODE_STOP" {
			return nil, errors.New("canonical process lifecycle repeats")
		}
		v.running[i] = running
		switch e.Kind {
		case "ENGINE_START":
			if running {
				return nil, errors.New("ambiguous repeated canonical engine start")
			}
			running = true
		case "ENGINE_STOP":
			if !running {
				return nil, errors.New("ambiguous repeated canonical engine stop")
			}
			running = false
		case "NEW_HEAD":
			v.heads[[2]string{e.Str("number"), e.Str("hash")}] = e
		}
	}
	v.running[len(run.Events)] = running
	for _, source := range in.SyncObservations {
		if source != nil && source.Header.Node == run.Node && source.Header.Run == run.ID {
			if v.typed != nil {
				return nil, errors.New("multiple typed sources claim the same process")
			}
			v.typed = source
		}
	}
	if v.typed == nil || !v.typed.Complete || v.typed.Footer == nil || !v.typed.Footer.Complete || !v.typed.Footer.CoreComplete || !v.typed.Footer.ClosedNormally || v.typed.Footer.SequenceExhausted || v.typed.Footer.Dropped != "0" || v.typed.Footer.Invalid != "0" {
		return nil, errors.New("complete typed notification source is unavailable")
	}
	typed := v.typed
	validator, available := run.Events[0].Bool("validator")
	if !available || validator != typed.Header.Validator || typed.Header.Format != syncobs.Format || typed.Header.CoreStartSeq != "0" || typed.Footer.CoreStopSeq != strconv.Itoa(len(run.Events)-1) {
		return nil, errors.New("typed and canonical process boundaries differ")
	}
	found := false
	for _, dump := range in.Frames {
		if dump == nil {
			continue
		}
		sources, problems := frames.SyncSources(dump)
		for _, source := range sources {
			d := source.Declaration
			if d == nil || d.Node != run.Node || d.Run != run.ID {
				continue
			}
			if found {
				return nil, errors.New("multiple recorded control sources claim the same process")
			}
			found = true
			if len(problems) != 0 || len(frames.Validate(dump).Problems) != 0 || !source.Complete {
				return nil, errors.New("recorded control source is incomplete or malformed")
			}
			v.source = source
		}
	}
	if !found {
		return nil, errors.New("recorded control source is unavailable")
	}
	v.requests = slices.Clone(v.source.Requests)
	v.operations = slices.Clone(v.source.Operations)
	sort.Slice(v.requests, func(i, j int) bool {
		return number(v.requests[i].SyncControl.Request) < number(v.requests[j].SyncControl.Request)
	})
	sort.Slice(v.operations, func(i, j int) bool {
		return number(v.operations[i].SyncControl.Operation) < number(v.operations[j].SyncControl.Operation)
	})
	if len(v.requests) != len(typed.Notifications) || len(v.operations) != len(v.requests) {
		return nil, errors.New("typed notifications do not have one unique handling each")
	}
	if typed.Footer.Observed != strconv.Itoa(len(v.requests)) || typed.Footer.Written != strconv.Itoa(len(v.requests)) {
		return nil, errors.New("typed notification counts differ from retained controls")
	}
	active := false
	for i, n := range typed.Notifications {
		id := strconv.Itoa(i + 1)
		request, operation := v.requests[i], v.operations[i]
		r, c := request.SyncControl, operation.SyncControl
		linked, ok := v.source.Request(operation)
		if n.Sequence != id || r.Request != id || c.Request != id || c.Operation != id || !ok || linked != request || *c.SequenceExhausted {
			return nil, errors.New("control handling is superseded, repeated, reordered or lacks an exact request link")
		}
		syncing, success := n.Kind == "start", n.Kind == "done"
		if *r.Syncing != syncing || *r.Success != success || *c.Syncing != syncing || *c.Success != success {
			return nil, errors.New("typed notification and recorded request states differ")
		}
		switch n.Kind {
		case "start":
			if active {
				return nil, errors.New("overlapping downloader notification cycles")
			}
			active = true
		case "failed", "done":
			if !active {
				return nil, errors.New("completion lacks its original start notification")
			}
			active = false
		default:
			return nil, errors.New("unsupported typed notification kind")
		}
		if n.Kind == "done" && v.heads[[2]string{n.Number, n.Hash}] == nil {
			return nil, fmt.Errorf("completion %s lacks the original canonical head number and hash", id)
		}
	}
	if active {
		return nil, errors.New("downloader cycle remains open at shutdown")
	}
	return v, nil
}
