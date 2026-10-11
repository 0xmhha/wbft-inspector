package check

import (
	"slices"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

// BadRetention is the number of bad-block records the reference keeps:
// the ten highest-numbered (A-09 WBFT-APP-004). What a bad-block record
// protects lasts while the record is kept.
const BadRetention = 10

// BadBlock is a block a node recorded as bad: its first IMPORT_FAIL
// record of the hash with recorded_bad.
type BadBlock struct {
	Event  *events.Event
	At     time.Time
	Number string
	Hash   string // lower-case hex
}

// BadBlocks returns the bad blocks of each node, in record order, and the
// nodes in order.
func BadBlocks(in *Inputs) (map[string][]*BadBlock, []string) {
	bad := map[string][]*BadBlock{}
	seen := map[[2]string]bool{}
	if in.Events == nil {
		return bad, nil
	}
	for _, r := range in.Events.Runs {
		for _, e := range r.Events {
			if e.Kind != "IMPORT_FAIL" {
				continue
			}
			if b, _ := e.Bool("recorded_bad"); !b {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, e.TWall)
			h := strings.ToLower(e.Str("hash"))
			if err != nil || seen[[2]string{e.Node, h}] {
				continue
			}
			seen[[2]string{e.Node, h}] = true
			bad[e.Node] = append(bad[e.Node], &BadBlock{Event: e, At: at, Number: e.Str("number"), Hash: h})
		}
	}
	nodes := make([]string, 0, len(bad))
	for n := range bad { //wbft:unordered sorted below
		nodes = append(nodes, n)
	}
	slices.Sort(nodes)
	return bad, nodes
}

// Lapsed reports whether, by time t, the node had recorded BadRetention bad
// blocks above b's height, so that b's record may have been dropped.
func (b *BadBlock) Lapsed(all []*BadBlock, t time.Time) bool {
	n := 0
	for _, o := range all {
		if o != b && !o.At.After(t) && Cmp(o.Number, b.Number) > 0 {
			n++
		}
	}
	return n >= BadRetention
}
