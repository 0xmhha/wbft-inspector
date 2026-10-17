package frames

import (
	"bytes"
	"encoding/json"
	"slices"
	"strconv"
)

// SyncSource retains physical source order. Operations use their own logical
// identity; neither source completeness nor a link decides sync conformance.
type SyncSource struct {
	Declaration *Record
	Requests    []*Record
	Operations  []*Record
	Records     []*Record
	Complete    bool
	requests    map[string]*Record
	operations  map[string]*Record
}

// Request returns only an exact retained link in a complete recorded context.
func (s SyncSource) Request(operation *Record) (*Record, bool) {
	if !s.Complete || operation == nil || operation.SyncControl == nil || operation.SyncControl.Stage != "processed" {
		return nil, false
	}
	c := operation.SyncControl
	if !syncControlValid(c, true) || s.operations[c.Operation] != operation || !*c.RequestSource.Available {
		return nil, false
	}
	r := s.requests[c.Request]
	if r == nil || !syncControlValid(r.SyncControl, true) || !cacheMeasuredPosition(r) || r.File != operation.File || r.Node != operation.Node || r.Run != operation.Run || *r.SyncControl.Syncing != *c.Syncing || *r.SyncControl.Success != *c.Success {
		return nil, false
	}
	ref := c.RequestSource
	if ref.Seq != strconv.FormatUint(r.Seq, 10) || ref.Segment != strconv.FormatUint(*r.JournalSegment, 10) || ref.Offset != strconv.FormatInt(*r.JournalOffset, 10) {
		return nil, false
	}
	return r, true
}

func decodeSyncFields(fields map[string]json.RawMessage, r *Record) error {
	if raw, ok := fields["sync_trace"]; ok {
		t, err := decodeSyncTrace(raw)
		if err != nil {
			return err
		}
		r.SyncTrace = t
	}
	if raw, ok := fields["sync_control"]; ok {
		c, err := decodeSyncControl(raw)
		if err != nil {
			return err
		}
		r.SyncControl = c
	}
	if r.SyncTrace != nil || r.SyncControl != nil {
		for _, name := range append(slices.Clone(commonFields), "journal_segment", "journal_offset") {
			if raw, ok := fields[name]; !ok || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return errSyncSource
			}
		}
	}
	return nil
}

// SyncSources validates snapshot counts and original request coordinates.
// Explicitly incomplete sources stay incomplete; clocks never repair links.
func SyncSources(d *Dump) ([]SyncSource, []string) {
	groups := map[[3]string]*SyncSource{}
	var order [][3]string
	problems := slices.Clone(d.Malformed)
	add := func(r *Record, msg string) { problems = append(problems, r.Where()+": "+msg) }
	identities := map[string][2]string{}
	conflicted := map[string]bool{}
	for _, r := range d.Records {
		if id, ok := identities[r.File]; ok && id != [2]string{r.Node, r.Run} {
			add(r, "mixed sync source file identity")
			conflicted[r.File] = true
		} else {
			identities[r.File] = [2]string{r.Node, r.Run}
		}
		key := [3]string{r.File, r.Node, r.Run}
		g := groups[key]
		if g == nil {
			g = &SyncSource{requests: map[string]*Record{}, operations: map[string]*Record{}}
			groups[key] = g
			order = append(order, key)
		}
		g.Records = append(g.Records, r)
		if r.SyncTrace != nil {
			if g.Declaration != nil {
				add(r, "duplicate sync snapshot declaration")
			}
			g.Declaration = r
			if !slices.Contains([]string{"sync_trace", "scheduler_trace", "cache_trace"}, r.Type) {
				add(r, "sync declaration on another record type")
			}
		}
		if r.SyncControl != nil {
			if r.Type != "sync_control" {
				add(r, "sync control on another record type")
			}
			if r.SyncControl.Stage == "requested" {
				g.Requests = append(g.Requests, r)
			} else {
				g.Operations = append(g.Operations, r)
			}
		}
		if r.Type == "sync_trace" && r.SyncTrace == nil || r.Type == "sync_control" && r.SyncControl == nil {
			add(r, "missing sync metadata")
		}
	}
	var result []SyncSource
	for _, key := range order {
		g := groups[key]
		if g.Declaration == nil {
			if len(g.Requests)+len(g.Operations) > 0 {
				add(g.Records[0], "sync controls lack capability declaration")
			}
			continue
		}
		problemStart := len(problems)
		dc := g.Declaration
		t := dc.SyncTrace
		if !syncTraceValid(t) {
			add(dc, "invalid sync snapshot metadata")
			continue
		}
		rq, _ := SchedulerUint(t.Requests)
		op, _ := SchedulerUint(t.Operations)
		if rq != uint64(len(g.Requests)) || op != uint64(len(g.Operations)) {
			add(dc, "sync snapshot counts differ")
		}
		if !cacheUnavailableClock(dc) {
			add(dc, "sync snapshot invents a measured clock")
		}
		complete := dc.Seq == 1
		seqs := map[uint64]bool{}
		positions := map[[2]uint64]bool{}
		var maxRequest, maxOperation uint64
		for _, r := range g.Records {
			if seqs[r.Seq] || r.Seq == 0 {
				add(r, "invalid or duplicate sync source sequence")
			}
			seqs[r.Seq] = true
			if r.Type == "dropped" {
				complete = false
			}
			if r.JournalSegment != nil || r.JournalOffset != nil || r.SyncTrace != nil || r.SyncControl != nil {
				if !cacheMeasuredPosition(r) {
					add(r, "invalid sync source journal position")
				} else {
					p := [2]uint64{*r.JournalSegment, uint64(*r.JournalOffset)}
					if positions[p] {
						add(r, "duplicate sync source journal position")
					}
					positions[p] = true
				}
			}
			if r.SyncTrace != nil || r.SyncControl != nil {
				if r.V != 1 || !addressPattern.MatchString(r.Node) || r.Run == "" || r.TMono < 0 {
					add(r, "invalid sync source identity or clock")
				}
				if r.Type == "sync_trace" || r.Type == "sync_control" {
					allowed := append(slices.Clone(commonFields), "journal_segment", "journal_offset", r.Type)
					if r.Type == "sync_trace" {
						allowed = append(allowed, "clock_source")
					}
					for name := range r.present {
						if !slices.Contains(allowed, name) {
							add(r, "unknown sync source field "+name)
						}
					}
				}
			}
			c := r.SyncControl
			if c == nil {
				continue
			}
			if !syncControlValid(c, true) {
				add(r, "invalid sync control metadata")
				complete = false
				continue
			}
			request, _ := SchedulerUint(c.Request)
			if request == 0 || *c.SequenceExhausted {
				complete = false
			}
			if c.Stage == "requested" {
				if request != 0 {
					if g.requests[c.Request] != nil {
						add(r, "duplicate sync request identity")
					}
					g.requests[c.Request] = r
					maxRequest = max(maxRequest, request)
				}
			} else {
				n, _ := SchedulerUint(c.Operation)
				if n == 0 {
					complete = false
				} else {
					if g.operations[c.Operation] != nil {
						add(r, "duplicate sync handling identity")
					}
					g.operations[c.Operation] = r
					maxOperation = max(maxOperation, n)
				}
				if c.Action != "none" && !*c.EventsAvailable {
					complete = false
				}
			}
		}
		complete = complete && uint64(len(g.Requests)) == maxRequest && uint64(len(g.Operations)) == maxOperation
		for _, r := range g.Operations {
			c := r.SyncControl
			if !syncControlValid(c, true) {
				continue
			}
			q := g.requests[c.Request]
			if q == nil || *q.SyncControl.Syncing != *c.Syncing || *q.SyncControl.Success != *c.Success {
				complete = false
			}
		}
		if *t.Complete && !complete {
			add(dc, "claimed complete sync source has missing context")
		}
		g.Complete = complete && *t.Complete && len(d.Malformed) == 0 && !conflicted[dc.File]
		for _, r := range g.Operations {
			c := r.SyncControl
			if !syncControlValid(c, true) {
				continue
			}
			s := c.RequestSource
			if *s.Available != g.Complete {
				add(r, "sync request availability contradicts source coverage")
				continue
			}
			if *s.Available {
				q := g.requests[c.Request]
				if q == nil || !cacheMeasuredPosition(q) || s.Seq != strconv.FormatUint(q.Seq, 10) || s.Segment != strconv.FormatUint(*q.JournalSegment, 10) || s.Offset != strconv.FormatInt(*q.JournalOffset, 10) {
					add(r, "sync request reference differs from original journal position")
				}
			}
		}
		if len(problems) != problemStart {
			g.Complete = false
		}
		result = append(result, *g)
	}
	return result, problems
}
