package frames

import (
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/spec/message"
)

func validateOwnInput(d *Dump, r *Record, add func(*Record, string, ...any), checked map[string]bool, payloads *int) {
	if r.Via != "internal" || r.InputKind != "message" || r.Peer == nil || *r.Peer != r.Node || r.EngineRun == nil || *r.EngineRun == 0 || r.Step == nil || *r.Step == 0 {
		add(r, "own input requires internal message, self peer and known engine/step")
	}
	if r.JournalSegment == nil || r.JournalOffset == nil || *r.JournalOffset <= 0 {
		add(r, "own input requires original journal segment/offset")
	}
	if r.Seq == 0 || r.Size == nil || r.Payload == "" || !hashPattern.MatchString(r.DedupKey) {
		add(r, "own input requires journal sequence, size, payload hash and key")
	}
	validatePayload(d, r, add, checked, payloads)
	b, err := d.Payload(r)
	if err != nil {
		add(r, "own input payload: %v", err)
		return
	}
	code, err := strconv.ParseUint(r.Code, 0, 64)
	if err != nil {
		add(r, "own input code: %v", err)
		return
	}
	m, err := message.Decode(code, b)
	if err != nil {
		add(r, "own input signature: %v", err)
	} else if fmt.Sprintf("0x%x", m.Signer) != r.Node {
		add(r, "own input signer is not the recording node")
	}
}

// validateOwnReferences verifies byte provenance. An asynchronous wire write
// is not assigned the input's engine/step or claimed to be that exact call.
func validateOwnReferences(recs []*Record, add func(*Record, string, ...any)) {
	type scope struct{ file, node, run string }
	type generation struct{ engine, step uint64 }
	type position struct {
		segment uint64
		offset  int64
	}
	type key struct{ code, dedup string }
	type run struct {
		seqs        map[uint64]*Record
		lost        bool
		inputs      map[key]int
		users       map[uint64]int
		generations map[generation]bool
		positions   map[position]bool
	}
	runs := map[scope]*run{}
	for _, r := range recs {
		k := scope{r.File, r.Node, r.Run}
		x := runs[k]
		if x == nil {
			x = &run{seqs: map[uint64]*Record{}, inputs: map[key]int{}, users: map[uint64]int{}, generations: map[generation]bool{}, positions: map[position]bool{}}
			runs[k] = x
		}
		x.seqs[r.Seq] = r
		if r.Type == "dropped" {
			x.lost = true
		}
		if r.Type == "own_input" {
			x.inputs[key{r.Code, r.DedupKey}]++
			if r.EngineRun != nil && r.Step != nil {
				g := generation{*r.EngineRun, *r.Step}
				if x.generations[g] {
					add(r, "duplicate own input engine/step")
				}
				x.generations[g] = true
			}
			if r.JournalSegment != nil && r.JournalOffset != nil {
				p := position{*r.JournalSegment, *r.JournalOffset}
				if x.positions[p] {
					add(r, "duplicate own input journal position")
				}
				x.positions[p] = true
			}
		}
		if r.InputOf != nil {
			x.users[*r.InputOf]++
		}
	}
	for _, r := range recs {
		x := runs[scope{r.File, r.Node, r.Run}]
		if r.Has("input_of") && (r.Type != "outcome" || r.InputOf == nil) {
			add(r, "input_of requires an outcome and a non-null reference")
		}
		if r.Has("own_message_of") && (r.Type != "frame" || r.OwnMessageOf == nil) {
			add(r, "own_message_of requires an outgoing relay and a non-null reference")
		}
		if r.Type == "own_input" {
			if x.lost || x.users[r.Seq] != 1 {
				add(r, "own input requires exactly one accepted outcome in a lossless run")
			}
		}
		validOutcome := func(o *Record) *Record {
			if o == nil || o.Type != "outcome" || o.InputOf == nil || o.Of != nil || o.Via != "self" || o.Outcome != "ACCEPT" || o.Check != "PROCESS" || o.Peer == nil || *o.Peer != o.Node {
				return nil
			}
			i := x.seqs[*o.InputOf]
			if i == nil || i.Type != "own_input" || i.Seq <= o.Seq || o.EngineRun == nil || o.Step == nil || i.EngineRun == nil || i.Step == nil || *o.EngineRun != *i.EngineRun || *o.Step != *i.Step || o.Code != i.Code || o.DedupKey != i.DedupKey || i.Peer == nil || *o.Peer != *i.Peer {
				return nil
			}
			return i
		}
		if r.Type == "outcome" && r.InputOf != nil {
			if x.lost || validOutcome(r) == nil {
				add(r, "input_of is not the accepted own input of this outcome")
			}
		}
		if r.OwnMessageOf != nil {
			i := validOutcome(x.seqs[*r.OwnMessageOf])
			if r.Type != "frame" || r.Dir != "out" || r.Cause != "relay" || r.RelayOf != nil || x.lost || i == nil || x.inputs[key{r.Code, r.DedupKey}] != 1 {
				add(r, "own_message_of is not a unique accepted own message of the run")
				continue
			}
			if r.Payload == "" || r.Size == nil || i.Size == nil || r.Code != i.Code || r.DedupKey != i.DedupKey || r.Payload != i.Payload || *r.Size != *i.Size {
				add(r, "relay bytes differ from the accepted own input")
			}
		}
	}
}
