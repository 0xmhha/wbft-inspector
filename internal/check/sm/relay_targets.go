package sm

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

// relaySelection validates the local target partition independently of the
// producer. A complete empty selection proves that no relay send was needed.
// It does not prove successful writes or remote delivery.
func relaySelection(plan *events.Event) (hasTargets, valid bool) {
	available, known := plan.Bool("available")
	index, hasIndex := plan.Int("output_index")
	if !known || !available || !hasIndex || index < 1 {
		return false, false
	}
	sets := []map[string]bool{}
	for _, key := range []string{"candidates", "targets", "suppressed"} {
		raw := plan.F[key]
		if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false, false
		}
		var peers []string
		if json.Unmarshal(raw, &peers) != nil {
			return false, false
		}
		set := map[string]bool{}
		for _, peer := range peers {
			if len(peer) != 42 || !strings.HasPrefix(peer, "0x") || peer != strings.ToLower(peer) || strings.EqualFold(peer, plan.Node) || set[peer] {
				return false, false
			}
			if b, err := hex.DecodeString(peer[2:]); err != nil || len(b) != 20 {
				return false, false
			}
			set[peer] = true
		}
		sets = append(sets, set)
	}
	candidates, targets, suppressed := sets[0], sets[1], sets[2]
	for peer := range targets {
		if !candidates[peer] || suppressed[peer] {
			return false, false
		}
	}
	for peer := range suppressed {
		if !candidates[peer] {
			return false, false
		}
	}
	if len(candidates) != len(targets)+len(suppressed) {
		return false, false
	}
	return len(targets) > 0, true
}
