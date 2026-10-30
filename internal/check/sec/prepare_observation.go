package sec

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/spec/message"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

const prepareObservationSchema = "wbft-prepare-justification-observation/1"
const prepareObserverName = "sec.prepare_justification_pairs"

func init() {
	check.RegisterObserver(prepareJustificationPairs{check.Base{ID: prepareObserverName,
		Reqs: []string{reqReported}, Kinds: []check.Kind{check.Frames}, ReadsLogs: true}})
}

// This checker reports inspector observations, never the node's conformance.
// The existing equivocationReported checker remains separate and unchanged.
type prepareJustificationPairs struct{ check.Base }

type prepareContainerIdentity struct {
	SHA256   string `json:"sha256"`
	Size     int    `json:"size"`
	DedupKey string `json:"dedup_key"`
	Code     uint64 `json:"code"`
	Sequence string `json:"sequence"`
	Round    string `json:"round"`
	Signer   string `json:"signer"`
}

type prepareObservationBinding struct {
	Status  string            `json:"status"`
	Reason  string            `json:"reason"`
	Outcome *evidence.Pointer `json:"outcome,omitempty"`
}

type prepareObservationWitness struct {
	Input     string                    `json:"input"`
	Node      string                    `json:"node"`
	Run       string                    `json:"run"`
	Sequence  string                    `json:"sequence"`
	Round     string                    `json:"round"`
	Code      uint64                    `json:"code"`
	Signer    string                    `json:"signer"`
	Digest    string                    `json:"digest"`
	Signature string                    `json:"signature"`
	Nested    bool                      `json:"nested"`
	Index     int                       `json:"index"`
	Container prepareContainerIdentity  `json:"container"`
	Pointer   evidence.Pointer          `json:"pointer"`
	Binding   prepareObservationBinding `json:"binding"`
}

type prepareObservation struct {
	Observer  string                       `json:"observer"`
	Schema    string                       `json:"schema"`
	Status    string                       `json:"status"`
	Witnesses [2]prepareObservationWitness `json:"witnesses"`
}

func (c prepareJustificationPairs) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		var ordered []*frames.Record
		for _, recs := range check.FrameRuns(d) {
			ordered = append(ordered, recs...)
		}
		claimsByScope := map[[2]string]prepareClaims{}
		copies := map[[3]string]int{}
		lost := map[[2]string]bool{}
		for _, r := range ordered {
			if r.Type == "dropped" {
				lost[[2]string{r.Node, r.Run}] = true
			}
			if r.Type == "frame" && r.Dir == "in" && r.Payload != "" {
				copies[[3]string{r.Node, r.Run, strings.ToLower(r.Payload)}]++
			}
		}
		var votes []prepareObservationWitness
		for _, r := range ordered {
			if r.Type != "frame" || r.Dir != "in" {
				continue
			}
			code, err := strconv.ParseUint(strings.TrimPrefix(r.Code, "0x"), 16, 64)
			if err != nil || code != message.CodePrepare && code != message.CodePreprepare && code != message.CodeRoundChange {
				continue
			}
			b, err := d.Payload(r)
			if err != nil {
				c.unavailable(r, verdict.MissingData, "payload_missing", out)
				continue
			}
			h := sha256.Sum256(b)
			digest := hex.EncodeToString(h[:])
			key := keccak.DedupKey(b)
			dedup := fmt.Sprintf("0x%x", key)
			if !strings.EqualFold(r.Payload, digest) || r.Size != nil && *r.Size != int64(len(b)) ||
				r.DedupKey != "" && !strings.EqualFold(r.DedupKey, dedup) {
				c.unavailable(r, verdict.InconsistentInput, "container_identity_mismatch", out)
				continue
			}
			container, err := message.DecodePrepareContainer(code, b)
			if err != nil {
				c.unavailable(r, verdict.InconsistentInput, "prepare_container_unavailable", out)
				continue
			}
			outer := container.Outer
			id := prepareContainerIdentity{SHA256: digest, Size: len(b), DedupKey: dedup,
				Code: code, Sequence: outer.Sequence.String(), Round: outer.Round.String(), Signer: fmt.Sprintf("0x%x", outer.Signer)}
			scope := [2]string{r.Node, r.Run}
			claims, exists := claimsByScope[scope]
			if !exists {
				claims = prepareOutcomeClaims(in.Events, r.Node, r.Run)
				claimsByScope[scope] = claims
			}
			count := copies[[3]string{r.Node, r.Run, digest}]
			if lost[scope] {
				count = -1
			}
			binding := bindPrepareObservation(id, r, count, claims)
			for _, w := range container.Witnesses {
				pointer := check.FramePointer(r)
				pointer.PayloadSHA256 = digest
				if w.Nested {
					pointer.Field = fmt.Sprintf("justification.prepares[%d]", w.Index)
				}
				votes = append(votes, prepareObservationWitness{Input: d.Input, Node: r.Node, Run: r.Run,
					Sequence: w.Message.Sequence.String(), Round: w.Message.Round.String(), Code: message.CodePrepare,
					Signer: fmt.Sprintf("0x%x", w.Message.Signer), Digest: fmt.Sprintf("0x%x", w.Message.Digest),
					Signature: fmt.Sprintf("0x%x", w.Signature), Nested: w.Nested, Index: w.Index,
					Container: id, Pointer: pointer, Binding: binding})
			}
		}
		for _, pair := range representativePreparePairs(votes) {
			out.Emit(prepareObservationInstance(pair))
		}
	}
	return nil
}

func (c prepareJustificationPairs) unavailable(r *frames.Record, why verdict.Reason, status string, out check.Emitter) {
	i := check.FrameInstance(reqReported, r, verdict.CannotDecide, why,
		"PREPARE observation unavailable; this does not decide whether the node reported evidence")
	i.Key = "prepare-observation-unavailable:" + i.Key
	i.Actual = struct {
		Observer string `json:"observer"`
		Schema   string `json:"schema"`
		Status   string `json:"status"`
		Reason   string `json:"reason"`
	}{prepareObserverName, prepareObservationSchema, "unavailable", status}
	out.Emit(i)
}

// representativePreparePairs compares detached observation values only. Its
// caller recovers signatures; this routine grants no cryptographic authority.
// It emits at most the first qualifying pair per input/node/run/view/signer.
func representativePreparePairs(votes []prepareObservationWitness) [][2]prepareObservationWitness {
	type key struct {
		input, node, run, seq, round, signer string
		code                                 uint64
	}
	type sighting struct {
		vote prepareObservationWitness
		at   int
	}
	type group struct {
		first, other, nested *sighting
		done                 bool
	}
	groups := map[key]*group{}
	var pairs [][2]prepareObservationWitness
	for position, vote := range votes {
		v := vote
		if v.Code != message.CodePrepare {
			continue
		}
		if v.Binding.Outcome != nil {
			pointer := *v.Binding.Outcome
			v.Binding.Outcome = &pointer
		}
		seen := &sighting{vote: v, at: position}
		k := key{v.Input, v.Node, v.Run, v.Sequence, v.Round, v.Signer, v.Code}
		g := groups[k]
		if g == nil {
			g = &group{first: seen}
			groups[k] = g
		}
		if g.done {
			continue
		}
		if g.other == nil && v.Digest != g.first.vote.Digest {
			g.other = seen
		}
		if g.nested == nil && v.Nested {
			g.nested = seen
		}
		if g.nested == nil || g.other == nil {
			continue
		}
		other := g.first
		if other.vote.Digest == g.nested.vote.Digest {
			other = g.other
		}
		if other.vote.Digest != g.nested.vote.Digest {
			first, second := other, g.nested
			if first.at > second.at {
				first, second = second, first
			}
			pairs = append(pairs, [2]prepareObservationWitness{first.vote, second.vote})
			g.done = true
		}
	}
	return pairs
}

func prepareObservationInstance(pair [2]prepareObservationWitness) verdict.Instance {
	status := "cryptographic_candidate"
	if pair[0].Binding.Status == "node_membership_observed" && pair[1].Binding.Status == "node_membership_observed" {
		status = "node_membership_observed"
	}
	v := pair[1]
	return verdict.Instance{Requirement: reqReported, Node: v.Node,
		Key:     fmt.Sprintf("prepare-observation:%s:%s:%s:%s:%s:%d", v.Input, v.Run, v.Sequence, v.Round, v.Signer, v.Code),
		Verdict: verdict.CannotDecide, Reason: verdict.ObserverScope, Source: v.Input,
		Message:  "Inspector observed a representative PREPARE signature pair; node evidence reporting and independent chain authority are not decided",
		Actual:   prepareObservation{Observer: prepareObserverName, Schema: prepareObservationSchema, Status: status, Witnesses: pair},
		Evidence: []evidence.Pointer{pair[0].Pointer, pair[1].Pointer}}
}

type prepareClaims struct {
	candidates map[string][]*events.Event
	incomplete bool
}

func prepareOutcomeClaims(set *events.Set, node, run string) prepareClaims {
	claims := prepareClaims{candidates: map[string][]*events.Event{}}
	if set == nil {
		return claims
	}
	for _, r := range set.Runs {
		if r.Node != node || r.ID != run {
			continue
		}
		// This guard also protects direct callers that do not use the
		// framework's optional-log filtering.
		if r.FromLog && !r.Complete || len(r.Lost) > 0 {
			claims.incomplete = true
			continue
		}
		for _, e := range r.Events {
			if e.Kind != "MSG_OUTCOME" || e.Node != node || e.Run != run {
				continue
			}
			// Preserve all claims about these bytes before validating their
			// fields. A good claim cannot hide another contradictory view,
			// code, source, or incomplete claim in a different bucket.
			if key := strings.ToLower(e.Str("dedup_key")); key != "" {
				claims.candidates[key] = append(claims.candidates[key], e)
			}
		}
	}
	return claims
}

func bindPrepareObservation(id prepareContainerIdentity, r *frames.Record, copies int, claims prepareClaims) prepareObservationBinding {
	result := prepareObservationBinding{Status: "unbound", Reason: "outcome_missing"}
	if copies < 0 || claims.incomplete {
		result.Reason = "capture_incomplete"
		return result
	}
	if copies > 1 {
		result.Status, result.Reason = "ambiguous", "duplicate_container"
		return result
	}
	es := claims.candidates[id.DedupKey]
	if len(es) > 1 {
		result.Status, result.Reason = "ambiguous", "multiple_outcomes"
		return result
	}
	if len(es) == 0 {
		return result
	}
	e := es[0]
	code, codeKnown := e.Int("code")
	row, ok := e.Int("row")
	if !codeKnown || code < 0 || uint64(code) != id.Code || e.View == nil || e.View.Seq != id.Sequence || e.View.Round != id.Round ||
		!ok || row < 3 || row > 28 || e.Step == nil || *e.Step == 0 ||
		(e.Str("via") != "direct" && e.Str("via") != "self") || e.Str("check") == "prefilter" ||
		!strings.EqualFold(e.Str("source"), id.Signer) {
		result.Reason = "full_recovery_not_bound"
		return result
	}
	if r.Peer != nil && !strings.EqualFold(*r.Peer, e.Str("peer")) {
		result.Reason = "peer_not_bound"
		return result
	}
	pointer := check.Pointer(e)
	result.Status, result.Reason, result.Outcome = "node_membership_observed", "conditional_node_claim", &pointer
	return result
}
