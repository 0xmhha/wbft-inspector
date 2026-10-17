package frames

import (
	"encoding/json"
	"errors"
	"strconv"
)

var errSyncSource = errors.New("invalid recorded sync control source")

// SyncTrace describes retained source coverage, not consensus-policy success
// or independent authentication of an external downloader result.
type SyncTrace struct {
	Version     string `json:"version"`
	Requests    string `json:"requests"`
	Operations  string `json:"operations"`
	Complete    *bool  `json:"complete"`
	EventCursor string `json:"event_cursor"`
}

// SyncRequestSource uses journal coordinates. It is never an event-stream
// position, a timestamp-derived boundary, or a remote delivery assertion.
type SyncRequestSource struct {
	Available *bool  `json:"source_available"`
	Seq       string `json:"source_seq,omitempty"`
	Segment   string `json:"source_segment,omitempty"`
	Offset    string `json:"source_offset,omitempty"`
}

type SyncControl struct {
	Stage             string             `json:"stage"`
	Request           string             `json:"request"`
	Operation         string             `json:"operation"`
	Syncing           *bool              `json:"syncing"`
	Success           *bool              `json:"success"`
	FirstBefore       *bool              `json:"first_before"`
	FirstAfter        *bool              `json:"first_after"`
	RunningBefore     *bool              `json:"running_before"`
	RunningAfter      *bool              `json:"running_after"`
	Action            string             `json:"action"`
	Failed            *bool              `json:"failed"`
	EventsAvailable   *bool              `json:"events_available"`
	EventBefore       string             `json:"event_before"`
	EventAfter        string             `json:"event_after"`
	SequenceExhausted *bool              `json:"sequence_exhausted"`
	RequestSource     *SyncRequestSource `json:"request_source,omitempty"`
}

func syncTraceValid(t *SyncTrace) bool {
	if t == nil {
		return false
	}
	_, requests := SchedulerUint(t.Requests)
	_, operations := SchedulerUint(t.Operations)
	return t.Version == "1" && t.Complete != nil && t.EventCursor == "next_sequence" && requests && operations
}

func syncControlValid(c *SyncControl, linked bool) bool {
	if c == nil {
		return false
	}
	for _, value := range []*bool{c.Syncing, c.Success, c.FirstBefore, c.FirstAfter, c.RunningBefore, c.RunningAfter, c.Failed, c.EventsAvailable, c.SequenceExhausted} {
		if value == nil {
			return false
		}
	}
	for _, value := range []string{c.Request, c.Operation, c.EventBefore, c.EventAfter} {
		if _, valid := SchedulerUint(value); !valid {
			return false
		}
	}
	before, _ := SchedulerUint(c.EventBefore)
	after, _ := SchedulerUint(c.EventAfter)
	if *c.EventsAvailable && after < before {
		return false
	}
	switch c.Stage {
	case "requested":
		return c.Operation == "0" && c.Action == "" && !*c.FirstBefore && !*c.FirstAfter && !*c.RunningBefore && !*c.RunningAfter && !*c.Failed && !*c.EventsAvailable && c.EventBefore == "0" && c.EventAfter == "0" && c.RequestSource == nil
	case "processed":
		if c.Action != "none" && c.Action != "stop" && c.Action != "start" {
			return false
		}
		if !linked && c.RequestSource == nil {
			return true
		}
		return syncRequestSourceValid(c.RequestSource)
	default:
		return false
	}
}

func syncRequestSourceValid(s *SyncRequestSource) bool {
	if s == nil || s.Available == nil {
		return false
	}
	if !*s.Available {
		return s.Seq == "" && s.Segment == "" && s.Offset == ""
	}
	seq, validSeq := SchedulerUint(s.Seq)
	_, validSegment := SchedulerUint(s.Segment)
	offset, err := strconv.ParseInt(s.Offset, 10, 64)
	return validSeq && seq > 0 && validSegment && err == nil && offset >= 0 && strconv.FormatInt(offset, 10) == s.Offset
}

func decodeSyncTrace(raw json.RawMessage) (*SyncTrace, error) {
	var t SyncTrace
	if closedCacheObject(raw, &t, []string{"version", "requests", "operations", "complete", "event_cursor"}) != nil || !syncTraceValid(&t) {
		return nil, errSyncSource
	}
	return &t, nil
}

func decodeSyncControl(raw json.RawMessage) (*SyncControl, error) {
	var c SyncControl
	required := []string{"stage", "request", "operation", "syncing", "success", "first_before", "first_after", "running_before", "running_after", "action", "failed", "events_available", "event_before", "event_after", "sequence_exhausted"}
	if closedCacheObject(raw, &c, required) != nil {
		return nil, errSyncSource
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return nil, errSyncSource
	}
	if link, ok := fields["request_source"]; ok {
		if closedCacheObject(link, &c.RequestSource, []string{"source_available"}) != nil {
			return nil, errSyncSource
		}
	}
	if !syncControlValid(&c, true) {
		return nil, errSyncSource
	}
	return &c, nil
}
