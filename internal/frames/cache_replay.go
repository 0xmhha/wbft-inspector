package frames

import (
	"slices"
	"sort"
)

// CacheState is the independently replayed state immediately before one real
// cache operation. Known is false after missing or inconsistent context.
type CacheState struct {
	Record     *Record
	Known      bool
	Consistent bool
	Held       map[string]bool
}

// cacheLRU intentionally uses an ordered slice, independent of the producer's
// list/map implementation. Index zero is most recently used.
type cacheLRU struct {
	limit int
	keys  []string
}

func (l *cacheLRU) has(key string) bool { return slices.Contains(l.keys, key) }
func (l *cacheLRU) touch(key string) bool {
	i := slices.Index(l.keys, key)
	if i < 0 {
		return false
	}
	copy(l.keys[1:i+1], l.keys[:i])
	l.keys[0] = key
	return true
}
func (l *cacheLRU) add(key string) string {
	if l.touch(key) {
		return ""
	}
	var old string
	if len(l.keys) == l.limit {
		old = l.keys[len(l.keys)-1]
	} else {
		l.keys = append(l.keys, "")
	}
	copy(l.keys[1:], l.keys[:len(l.keys)-1])
	l.keys[0] = key
	return old
}

type replayedCache struct {
	trusted      bool
	known, peers cacheLRU
	recent       map[string]*cacheLRU
}

func (c *replayedCache) peer(peer string, create bool) *cacheLRU {
	if c.peers.touch(peer) {
		return c.recent[peer]
	}
	if !create {
		return nil
	}
	keys := &cacheLRU{limit: 1024}
	c.recent[peer] = keys
	if evicted := c.peers.add(peer); evicted != "" {
		delete(c.recent, evicted)
	}
	return keys
}

// ReplayCache reconstructs both LRU levels from the declared empty instances.
// Reconnection and engine changes do not reset a cache; only a new declaration
// starts another instance. Calls must use a source checked by CacheSources.
func ReplayCache(source CacheSource) map[[2]string]CacheState {
	result := map[[2]string]CacheState{}
	models := map[string]*replayedCache{}
	complete := source.Declaration != nil && source.Declaration.CacheTrace != nil && source.Declaration.CacheTrace.Complete != nil && *source.Declaration.CacheTrace.Complete
	for _, r := range source.Instances {
		x := r.CacheInstance
		if x != nil {
			models[x.Instance] = &replayedCache{trusted: complete, known: cacheLRU{limit: 1024}, peers: cacheLRU{limit: 40}, recent: map[string]*cacheLRU{}}
		}
	}
	operations := slices.Clone(source.Operations)
	sort.SliceStable(operations, func(i, j int) bool {
		a, b := operations[i].CacheOperation, operations[j].CacheOperation
		if a.Instance != b.Instance {
			return a.Instance < b.Instance
		}
		x, _ := SchedulerUint(a.Sequence)
		y, _ := SchedulerUint(b.Sequence)
		return x < y
	})
	for _, r := range operations {
		op := r.CacheOperation
		key := [2]string{op.Instance, op.Sequence}
		state := CacheState{Record: r, Held: map[string]bool{}}
		model := models[op.Instance]
		if model == nil || op.Known == nil || op.Recent == nil || op.Available == nil {
			result[key] = state
			continue
		}
		hit := model.known.has(op.Key)
		state.Known = model.trusted && hit == *op.Known
		consistent := hit == *op.Known
		switch op.Action {
		case "inbound":
			recent := model.peer(op.Peer, true)
			had := recent.has(op.Key)
			recent.add(op.Key)
			model.known.add(op.Key)
			consistent = consistent && had == *op.Recent
		case "gossip":
			model.known.add(op.Key)
			var targets, suppressed []string
			for _, peer := range op.Candidates {
				recent := model.peer(peer, false)
				held := recent != nil && recent.has(op.Key)
				state.Held[peer] = held
				if held {
					recent.touch(op.Key)
					suppressed = append(suppressed, peer)
				} else {
					if recent == nil {
						recent = model.peer(peer, true)
					}
					recent.add(op.Key)
					model.peers.add(peer)
					targets = append(targets, peer)
				}
			}
			consistent = consistent && slices.Equal(targets, op.Targets) && slices.Equal(suppressed, op.Suppressed)
		default:
			consistent = false
		}
		state.Consistent = consistent
		model.trusted = model.trusted && consistent
		result[key] = state
	}
	return result
}
