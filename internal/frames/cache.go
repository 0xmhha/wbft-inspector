package frames

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"sort"
	"strconv"
)

// CacheTrace closes the available snapshot, including deliberately incomplete
// prefixes. Complete does not authenticate source bytes or imply delivery.
type CacheTrace struct {
	Version    string `json:"version"`
	Instances  string `json:"instances"`
	Operations string `json:"operations"`
	Complete   *bool  `json:"complete"`
}
type CacheInstance struct {
	Instance        string `json:"instance"`
	Self            string `json:"self"`
	PeerCapacity    string `json:"peer_capacity"`
	MessageCapacity string `json:"message_capacity"`
	InitialState    string `json:"initial_state"`
}
type CacheOperation struct {
	Instance   string   `json:"instance"`
	Sequence   string   `json:"sequence"`
	Action     string   `json:"action"`
	Peer       string   `json:"peer"`
	Code       string   `json:"code"`
	Key        string   `json:"dedup_key"`
	Payload    string   `json:"payload_sha256"`
	Cause      string   `json:"cause"`
	Known      *bool    `json:"known_hit"`
	Recent     *bool    `json:"peer_recent_hit"`
	Available  *bool    `json:"candidates_available"`
	Candidates []string `json:"candidates"`
	Targets    []string `json:"targets"`
	Suppressed []string `json:"suppressed"`
}
type CacheDecision struct {
	Instance  string `json:"instance"`
	Operation string `json:"operation"`
	Available *bool  `json:"source_available"`
	Seq       string `json:"source_seq,omitempty"`
	Segment   string `json:"source_segment,omitempty"`
	Offset    string `json:"source_offset,omitempty"`
}
type SendAttempt struct {
	Available      *bool          `json:"available"`
	Sequence       string         `json:"sequence,omitempty"`
	CacheAvailable *bool          `json:"cache_source_available,omitempty"`
	Decision       *CacheDecision `json:"cache_decision,omitempty"`
}

// CacheSource is one file/node/writer lifetime. Operations are replayed using
// their cache-local sequence; file order and frame time are not cache order.
type CacheSource struct {
	Declaration *Record
	Instances   []*Record
	Operations  []*Record
	Records     []*Record
}

func closedCacheObject(raw []byte, target any, required []string) error {
	if !uniqueFields(raw) {
		return fmt.Errorf("invalid or duplicate cache metadata fields")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	for _, name := range required {
		if _, ok := fields[name]; !ok {
			return fmt.Errorf("missing cache metadata field %s", name)
		}
	}
	for name, v := range fields {
		if bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return fmt.Errorf("null cache metadata field %s", name)
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing cache metadata")
	}
	return nil
}

func decodeCacheFields(fields map[string]json.RawMessage, r *Record) error {
	targets := []struct {
		name     string
		target   any
		required []string
	}{
		{"cache_trace", &r.CacheTrace, []string{"version", "instances", "operations", "complete"}},
		{"cache_instance", &r.CacheInstance, []string{"instance", "self", "peer_capacity", "message_capacity", "initial_state"}},
		{"cache_operation", &r.CacheOperation, []string{"instance", "sequence", "action", "peer", "code", "dedup_key", "payload_sha256", "cause", "known_hit", "peer_recent_hit", "candidates_available", "candidates", "targets", "suppressed"}},
		{"cache_decision", &r.CacheDecision, []string{"instance", "operation", "source_available"}},
		{"send_attempt", &r.SendAttempt, []string{"available"}},
	}
	for _, v := range targets {
		if raw, ok := fields[v.name]; ok {
			if err := closedCacheObject(raw, v.target, v.required); err != nil {
				return fmt.Errorf("%s: %w", v.name, err)
			}
		}
	}
	if raw, ok := fields["send_attempt"]; ok {
		var nested map[string]json.RawMessage
		if err := json.Unmarshal(raw, &nested); err != nil {
			return err
		}
		if ref, ok := nested["cache_decision"]; ok {
			if err := closedCacheObject(ref, &r.SendAttempt.Decision, []string{"instance", "operation", "source_available"}); err != nil {
				return err
			}
		}
	}
	if r.CacheTrace != nil || r.CacheInstance != nil || r.CacheOperation != nil || r.SendAttempt != nil || r.CacheDecision != nil {
		for _, name := range append(slices.Clone(commonFields), "journal_segment", "journal_offset") {
			if raw, ok := fields[name]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				return fmt.Errorf("null cache source field %s", name)
			}
		}
	}
	return nil
}

func cachePositive(s string) bool { n, ok := SchedulerUint(s); return ok && n > 0 }
func cacheZeroPeer(s string) bool { return s == "0x0000000000000000000000000000000000000000" }
func cacheSortedAddresses(a []string) bool {
	if a == nil {
		return false
	}
	for i, p := range a {
		if !addressPattern.MatchString(p) || i > 0 && a[i-1] >= p {
			return false
		}
	}
	return true
}
func cacheMeasuredPosition(r *Record) bool {
	return r.JournalSegment != nil && r.JournalOffset != nil && *r.JournalOffset >= 0
}
func cacheUnavailableClock(r *Record) bool {
	return r.ClockSource == "unavailable" && r.TMono == 0 && r.TWall == "1970-01-01T00:00:00Z"
}

// CacheSources validates closed metadata, snapshot counts and exact references.
// Missing context is not repaired from clocks, neighboring rows or payload FIFO.
func CacheSources(d *Dump) ([]CacheSource, []string) {
	groups := map[[3]string]*CacheSource{}
	var order [][3]string
	problems := slices.Clone(d.Malformed)
	add := func(r *Record, msg string) { problems = append(problems, r.Where()+": "+msg) }
	for _, r := range d.Records {
		k := [3]string{r.File, r.Node, r.Run}
		g := groups[k]
		if g == nil {
			g = &CacheSource{}
			groups[k] = g
			order = append(order, k)
		}
		g.Records = append(g.Records, r)
		if r.CacheTrace != nil {
			if g.Declaration != nil {
				add(r, "duplicate cache trace declaration")
			}
			g.Declaration = r
		}
		if r.Type == "cache_instance" {
			g.Instances = append(g.Instances, r)
		}
		if r.Type == "cache_operation" {
			g.Operations = append(g.Operations, r)
		}
		if r.CacheTrace != nil && r.Type != "cache_trace" && r.Type != "scheduler_trace" || r.CacheInstance != nil && r.Type != "cache_instance" || r.CacheOperation != nil && r.Type != "cache_operation" || r.CacheDecision != nil && r.Type != "send_suppressed" || r.SendAttempt != nil && (r.Type != "frame" || r.Dir != "out") {
			add(r, "cache metadata on another record type")
		}
		if r.Type == "cache_trace" && r.CacheTrace == nil || r.Type == "cache_instance" && r.CacheInstance == nil || r.Type == "cache_operation" && r.CacheOperation == nil {
			add(r, "missing cache metadata")
		}
	}
	var result []CacheSource
	for _, key := range order {
		g := groups[key]
		if g.Declaration == nil {
			for _, r := range g.Records {
				if r.CacheInstance != nil || r.CacheOperation != nil || r.CacheDecision != nil || r.SendAttempt != nil {
					add(r, "cache source lacks capability declaration")
				}
			}
			continue
		}
		dc := g.Declaration
		tr := dc.CacheTrace
		countI, ci := SchedulerUint(tr.Instances)
		countO, co := SchedulerUint(tr.Operations)
		if tr.Version != "1" || tr.Complete == nil || !ci || !co || countI != uint64(len(g.Instances)) || countO != uint64(len(g.Operations)) {
			add(dc, "cache snapshot counts or version differ")
		}
		complete := tr.Complete != nil && *tr.Complete
		if !cacheUnavailableClock(dc) {
			add(dc, "cache declaration invents a measured clock")
		}
		seqs := map[uint64]*Record{}
		positions := map[[2]uint64]*Record{}
		for _, r := range g.Records {
			if seqs[r.Seq] != nil {
				add(r, "duplicate cache source sequence")
			}
			seqs[r.Seq] = r
			if r.Type == "dropped" && complete {
				add(r, "complete cache source contains a gap")
			}
			source := r == dc || r.CacheInstance != nil || r.CacheOperation != nil || r.SendAttempt != nil || r.JournalSegment != nil || r.JournalOffset != nil
			if !source {
				continue
			}
			for _, name := range commonFields {
				if !r.Has(name) {
					add(r, "missing cache source field "+name)
				}
			}
			if r.Seq == 0 || r.V != 1 || r.Run == "" || !addressPattern.MatchString(r.Node) || !cacheMeasuredPosition(r) {
				add(r, "invalid cache source identity or position")
			}
			if cacheMeasuredPosition(r) {
				p := [2]uint64{*r.JournalSegment, uint64(*r.JournalOffset)}
				if positions[p] != nil {
					add(r, "duplicate cache source position")
				}
				positions[p] = r
			}
			if r.Type == "cache_trace" || r.Type == "cache_instance" || r.Type == "cache_operation" {
				allowed := append(slices.Clone(commonFields), "journal_segment", "journal_offset", r.Type)
				if r.Type != "cache_operation" {
					allowed = append(allowed, "clock_source")
				}
				if r.Type == "cache_trace" && r.SyncTrace != nil {
					allowed = append(allowed, "sync_trace")
				}
				for name := range r.present {
					if !slices.Contains(allowed, name) {
						add(r, "unknown cache source field "+name)
					}
				}
			}
		}
		instances := map[string]*Record{}
		ops := map[[2]string]*Record{}
		perInstance := map[string][]*Record{}
		for _, r := range g.Instances {
			x := r.CacheInstance
			if x == nil {
				continue
			}
			if !cachePositive(x.Instance) || x.Self != r.Node || x.PeerCapacity != "40" || x.MessageCapacity != "1024" || x.InitialState != "empty" || !cacheUnavailableClock(r) {
				add(r, "invalid empty cache instance declaration")
			}
			if instances[x.Instance] != nil {
				add(r, "duplicate cache instance")
			}
			instances[x.Instance] = r
		}
		for _, r := range g.Operations {
			o := r.CacheOperation
			if o == nil {
				continue
			}
			if !cachePositive(o.Instance) || !cachePositive(o.Sequence) || !slices.Contains([]string{"inbound", "gossip"}, o.Action) || !addressPattern.MatchString(o.Peer) || !cacheCodeValid(o.Code) || !hashPattern.MatchString(o.Key) || !sha256Pattern.MatchString(o.Payload) || o.Known == nil || o.Recent == nil || o.Available == nil || !cacheSortedAddresses(o.Candidates) || !cacheSortedAddresses(o.Targets) || !cacheSortedAddresses(o.Suppressed) || r.TMono < 0 {
				add(r, "invalid cache operation shape")
			}
			if o.Action == "inbound" && (o.Cause != "" || o.Available != nil && *o.Available || len(o.Candidates)+len(o.Targets)+len(o.Suppressed) != 0) {
				add(r, "inbound cache operation has gossip decision")
			}
			if o.Action == "gossip" && (!cacheZeroPeer(o.Peer) || o.Recent != nil && *o.Recent || o.Cause != "" && !slices.Contains(causes, o.Cause)) {
				add(r, "invalid gossip operation origin")
			}
			if o.Available != nil && !*o.Available && len(o.Candidates)+len(o.Targets)+len(o.Suppressed) != 0 {
				add(r, "unavailable candidates have targets")
			}
			for _, peer := range o.Candidates {
				if peer == r.Node {
					add(r, "cache candidate contains self")
				}
				a, b := slices.Contains(o.Targets, peer), slices.Contains(o.Suppressed, peer)
				if a == b {
					add(r, "cache target/suppression partition differs")
				}
			}
			for _, peer := range append(slices.Clone(o.Targets), o.Suppressed...) {
				if !slices.Contains(o.Candidates, peer) {
					add(r, "cache decision peer not a candidate")
				}
			}
			k := [2]string{o.Instance, o.Sequence}
			if ops[k] != nil {
				add(r, "duplicate cache operation identity")
			}
			ops[k] = r
			perInstance[o.Instance] = append(perInstance[o.Instance], r)
			if instance := instances[o.Instance]; complete && (instance == nil || instance.Seq >= r.Seq) {
				add(r, "cache operation lacks earlier empty instance")
			}
		}
		for _, operations := range perInstance {
			sort.Slice(operations, func(i, j int) bool {
				a, _ := SchedulerUint(operations[i].CacheOperation.Sequence)
				b, _ := SchedulerUint(operations[j].CacheOperation.Sequence)
				return a < b
			})
			for i, r := range operations {
				if complete && r.CacheOperation.Sequence != strconv.Itoa(i+1) {
					add(r, "complete cache operation sequence has a gap")
				}
				if i > 0 && (operations[i-1].Seq >= r.Seq || operations[i-1].TMono > r.TMono) {
					add(r, "cache mutex sequence conflicts with source order or monotonic clock")
				}
			}
		}
		attempts := map[[2]string]bool{}
		contexts := map[string][6]string{}
		for _, r := range g.Records {
			ref := r.CacheDecision
			if a := r.SendAttempt; a != nil {
				if a.Available == nil {
					add(r, "send attempt availability missing")
					continue
				}
				if !*a.Available {
					if a.Sequence != "" || a.Decision != nil || a.CacheAvailable != nil {
						add(r, "unavailable send attempt invents identity")
					}
					continue
				}
				if !cachePositive(a.Sequence) || r.Peer == nil {
					add(r, "invalid send attempt identity")
				}
				if r.Peer != nil {
					k := [2]string{a.Sequence, *r.Peer}
					if attempts[k] {
						add(r, "duplicate send attempt for peer")
					}
					attempts[k] = true
				}
				context := [6]string{r.Code, r.DedupKey, r.Payload, r.Cause, "", ""}
				if a.Decision != nil {
					context[4], context[5] = a.Decision.Instance, a.Decision.Operation
				}
				if old, ok := contexts[a.Sequence]; ok && old != context {
					add(r, "send attempt identity changed call context")
				}
				contexts[a.Sequence] = context
				if a.Decision == nil {
					if a.CacheAvailable == nil || *a.CacheAvailable {
						add(r, "send attempt lacks explicit cache unavailability")
					}
					continue
				}
				if a.CacheAvailable != nil {
					add(r, "conflicting send attempt cache availability")
				}
				ref = a.Decision
			}
			if ref == nil {
				continue
			}
			if !cachePositive(ref.Instance) || !cachePositive(ref.Operation) || ref.Available == nil {
				add(r, "invalid cache decision reference")
				continue
			}
			if !*ref.Available {
				if ref.Seq != "" || ref.Segment != "" || ref.Offset != "" {
					add(r, "unavailable cache decision invents source coordinates")
				}
				continue
			}
			op := ops[[2]string{ref.Instance, ref.Operation}]
			seq, ss := SchedulerUint(ref.Seq)
			segment, gs := SchedulerUint(ref.Segment)
			offset, os := SchedulerMono(ref.Offset)
			if !complete || op == nil || !ss || !gs || !os || !cacheMeasuredPosition(op) || seq != op.Seq || segment != *op.JournalSegment || offset != *op.JournalOffset || seq >= r.Seq {
				add(r, "cache decision source identity or position differs")
				continue
			}
			o := op.CacheOperation
			if o.Action != "gossip" || o.Key != r.DedupKey || o.Cause != r.Cause {
				add(r, "cache decision key or cause differs")
			}
			if r.Type == "frame" {
				code, e := strconv.ParseUint(stringsTrimCode(o.Code), 16, 64)
				wire := code
				if wire < 0x12 || wire > 0x15 {
					wire = 0x11
				}
				actual, e2 := strconv.ParseUint(stringsTrimCode(r.Code), 16, 64)
				if e != nil || e2 != nil || actual != wire || o.Payload != r.Payload {
					add(r, "cache decision code or payload differs")
				}
			}
			if r.Type == "send_suppressed" && r.ClockSource != "unavailable" {
				add(r, "suppression invents a measured callback clock")
			}
		}
		result = append(result, *g)
	}
	return result, problems
}
func stringsTrimCode(s string) string {
	if len(s) >= 2 && s[:2] == "0x" {
		return s[2:]
	}
	return ""
}

func cacheCodeValid(s string) bool {
	n, e := strconv.ParseUint(stringsTrimCode(s), 16, 64)
	return e == nil && fmt.Sprintf("%#x", n) == s
}
