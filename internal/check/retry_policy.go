package check

import (
	"bytes"
	"encoding/json"
	"fmt"
	"slices"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type retryPolicyScope struct{ node, run, input string }
type retryPolicyState struct {
	profile                   string
	declarations              int
	enabled, conflict, source bool
}
type retryFrameKey struct{ node, input, key string }
type retryFrameAnchor struct {
	scope   retryPolicyScope
	current bool
}
type retryPolicyIndex struct {
	known   map[[2]string]bool
	events  map[retryPolicyScope]retryPolicyState
	frames  map[retryPolicyScope]retryPolicyState
	anchors map[retryFrameKey]retryFrameAnchor
}

// A declaration is scoped to its actual input/node/run. Event labels provide
// no timer-generation, signer or WAL proof for the new retry contract.
func newRetryPolicyIndex(in *Inputs) *retryPolicyIndex {
	p := &retryPolicyIndex{known: map[[2]string]bool{}, events: map[retryPolicyScope]retryPolicyState{}, frames: map[retryPolicyScope]retryPolicyState{}, anchors: map[retryFrameKey]retryFrameAnchor{}}
	if in.Events != nil {
		for _, run := range in.Events.Runs {
			for _, e := range run.Events {
				key := retryPolicyScope{e.Node, e.Run, e.Input}
				state := p.events[key]
				state.source = state.source || len(e.F["round_change_retry"]) > 0 || slices.Contains(e.Imp, "round_change_retry")
				p.events[key] = state
				if e.Kind != "NODE_START" {
					continue
				}
				var names []struct {
					Name string `json:"name"`
				}
				raw, present := e.F["improvements"]
				valid := !present || json.Unmarshal(raw, &names) == nil
				enabled := false
				for _, name := range names {
					if name.Name == "round_change_retry" {
						enabled = true
					}
				}
				if !valid || state.declarations > 0 && state.enabled != enabled {
					state.conflict = true
				}
				state.declarations++
				state.enabled = state.enabled || enabled
				p.events[key] = state
			}
		}
	}
	for _, dump := range in.Frames {
		for _, r := range dump.Records {
			key := retryPolicyScope{r.Node, r.Run, r.Input}
			state := p.frames[key]
			if len(r.RoundChangeRetry) > 0 {
				var value map[string]json.RawMessage
				profile := string(bytes.TrimSpace(r.RoundChangeRetry))
				if json.Unmarshal(r.RoundChangeRetry, &value) == nil {
					if canonical, err := json.Marshal(value); err == nil {
						profile = string(canonical)
					}
				}
				if state.declarations > 0 && state.profile != profile {
					state.conflict = true
				}
				state.profile = profile
				state.declarations++
				state.enabled = true
			}
			state.source = state.source || len(r.RoundChangeRetrySource) > 0
			p.frames[key] = state
			code, codeErr := strconv.ParseUint(r.Code, 0, 64)
			anchor := retryFrameAnchor{scope: key, current: ((codeErr == nil && code == 0x15 || r.Code == "") && (r.Cause == "retry" || r.Cause == "")) || len(r.RoundChangeRetrySource) > 0}
			p.anchors[retryFrameKey{r.Node, r.Input, fmt.Sprintf("frame:%s:%d", r.Run, r.Seq)}] = anchor
		}
	}
	for scope, state := range p.events {
		if state.enabled || state.source {
			p.known[[2]string{scope.node, scope.run}] = true
		}
	}
	for scope, state := range p.frames {
		if state.enabled || state.source {
			p.known[[2]string{scope.node, scope.run}] = true
		}
	}
	return p
}
func retryAffected(req string) bool {
	return slices.Contains(PublicBehaviours["round_change_retry"], req)
}
func (p *retryPolicyIndex) gate(i verdict.Instance) verdict.Instance {
	if p == nil || !retryAffected(i.Requirement) {
		return i
	}
	state := retryPolicyState{}
	scope := retryPolicyScope{}
	if run, ok := eventRun(i.Key); ok {
		scope = retryPolicyScope{i.Node, run, i.Source}
		state = p.events[scope]
	} else if anchor, ok := p.anchors[retryFrameKey{i.Node, i.Source, i.Key}]; ok {
		if !anchor.current {
			return i
		}
		scope = anchor.scope
		state = p.frames[scope]
	}
	// A declaration in another input cannot establish this input's policy.
	// It does establish that silently assuming a legacy run would be unsafe.
	if state.declarations == 0 && p.known[[2]string{scope.node, scope.run}] {
		state.source = true
	}
	if !state.enabled && !state.source && !state.conflict {
		return i
	}
	i.Verdict = verdict.CannotDecide
	i.Reason = verdict.NotInBuild
	i.Message = "round-change retry policy requires original timer, signing and WAL sources; event/frame labels do not decide this instance"
	if state.conflict {
		i.Reason = verdict.InconsistentInput
		i.Message = "conflicting round-change retry declarations in the same input, node and run"
	} else if state.source && state.declarations == 0 {
		i.Reason = verdict.MissingData
		i.Message = "retry source marker has no policy declaration in the same input, node and run"
	}
	return i
}

// Do not let this policy's node-wide union soften failures in another run.
// Other optional declarations retain their existing handling.
func retryOptionalNode(in *Inputs, i verdict.Instance) *events.NodeInfo {
	node := in.Events.Nodes[i.Node]
	if node == nil || !slices.Contains(node.Behaviours, "round_change_retry") {
		return node
	}
	copy := *node
	copy.Behaviours = nil
	run, ok := eventRun(i.Key)
	enabled := false
	if ok {
		for _, r := range in.Events.Runs {
			if r.Node != i.Node || r.ID != run {
				continue
			}
			for _, e := range r.Events {
				if e.Input != i.Source || e.Kind != "NODE_START" {
					continue
				}
				var names []struct {
					Name string `json:"name"`
				}
				_ = json.Unmarshal(e.F["improvements"], &names)
				for _, n := range names {
					if n.Name == "round_change_retry" {
						enabled = true
					}
				}
			}
		}
	}
	for _, b := range node.Behaviours {
		if b != "round_change_retry" || enabled {
			copy.Behaviours = append(copy.Behaviours, b)
		}
	}
	copy.Optional = copy.Unnamed || len(copy.Behaviours) > 0
	return &copy
}
