package check

import (
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/events"
)

// TestPublicOnly: a failure stays a verdict only on a node whose every
// declaration is a named public behaviour, and only for a requirement
// none of them changes.
func TestPublicOnly(t *testing.T) {
	defaults := []string{"one_round0_proposal", "bad_block_release_mark", "parent_epoch_lookup", "integer_quorum", "checked_proposer_policy"}
	cases := []struct {
		node          events.NodeInfo
		req           string
		only, changes bool
	}{
		{events.NodeInfo{Behaviours: defaults}, "WBFT-SM-083", true, false},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-HDR-071", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-APP-003", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-SM-032", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-SM-082", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-VAL-002", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-VAL-003", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-PARAM-032", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-PARAM-034", true, true},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-PARAM-020", true, false},
		{events.NodeInfo{Behaviours: defaults}, "WBFT-VAL-001", true, false},
		{events.NodeInfo{Behaviours: defaults[1:]}, "WBFT-SM-082", true, false},
		{events.NodeInfo{Behaviours: append(defaults, "other")}, "WBFT-SM-083", false, false},
		{events.NodeInfo{Behaviours: defaults, Unnamed: true}, "WBFT-SM-083", false, false},
	}
	for _, c := range cases {
		only, changes := publicOnly(&c.node, c.req)
		if only != c.only || changes != c.changes {
			t.Errorf("%v %s: only %v changes %v, want %v %v", c.node.Behaviours, c.req, only, changes, c.only, c.changes)
		}
	}
	// The requirements named are requirements of the catalog.
	for b, reqs := range PublicBehaviours {
		for _, id := range reqs {
			if _, ok := catalog.Lookup(id); !ok {
				t.Errorf("%s: %s is not a requirement of the catalog", b, id)
			}
		}
	}
}
