package timer

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestRetryDelayedWriteUsesItsOriginalCacheDecision(t *testing.T) {
	d, err := frames.Load("../../frames/testdata/cache-source")
	if err != nil {
		t.Fatal(err)
	}
	if v := frames.Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	var result sink
	c := retryWire{check.Base{ID: "timer.retry_wire_suppressed"}}
	if err = c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{d}}, &result); err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 || result[0].Verdict != verdict.Pass {
		t.Fatalf("a later suppression must not rewrite an earlier target decision: %+v", result)
	}
}

// These generated unit scenarios declare synthetic coordinates. They do not
// authenticate raw source bytes; the separate producer fixture does that audit.
type cacheScenario struct {
	t                     *testing.T
	rows                  []map[string]any
	frame                 map[string]any
	sequence              uint64
	operations, instances int
	local                 map[string]int
	peer, key, payload    string
}

func cloneCacheRow(row map[string]any) map[string]any {
	b, _ := json.Marshal(row)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}
func newCacheScenario(t *testing.T) *cacheScenario {
	t.Helper()
	raw, err := os.ReadFile("../../frames/testdata/cache-source/frames-cache-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	start := 0
	for i, b := range raw {
		if b == '\n' {
			var r map[string]any
			if err = json.Unmarshal(raw[start:i], &r); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, r)
			start = i + 1
		}
	}
	s := &cacheScenario{t: t, local: map[string]int{}}
	for _, r := range rows {
		switch r["type"] {
		case "cache_trace":
			s.rows = append(s.rows, cloneCacheRow(r))
			s.sequence = 1
		case "frame":
			s.frame = cloneCacheRow(r)
		}
	}
	s.peer = s.frame["peer"].(string)
	s.key = s.frame["dedup_key"].(string)
	s.payload = s.frame["payload_sha256"].(string)
	s.instance("1")
	return s
}
func (s *cacheScenario) common(typ string) map[string]any {
	s.sequence++
	return map[string]any{"v": 1, "type": typ, "node": s.frame["node"], "run": "cache-fixture", "seq": s.sequence, "t_wall": "1970-01-01T00:00:00Z", "t_mono_ns": int64(s.sequence), "journal_segment": uint64(0), "journal_offset": int64(s.sequence * 100)}
}
func (s *cacheScenario) instance(id string) {
	r := s.common("cache_instance")
	r["t_mono_ns"] = 0
	r["clock_source"] = "unavailable"
	r["cache_instance"] = map[string]any{"instance": id, "self": s.frame["node"], "peer_capacity": "40", "message_capacity": "1024", "initial_state": "empty"}
	s.rows = append(s.rows, r)
	s.instances++
}
func (s *cacheScenario) operation(id, action, peer, key, payload, cause string, known, recent, held bool) map[string]any {
	r := s.common("cache_operation")
	s.operations++
	s.local[id]++
	op := map[string]any{"instance": id, "sequence": strconv.Itoa(s.local[id]), "action": action, "peer": "0x0000000000000000000000000000000000000000", "code": "0x13", "dedup_key": key, "payload_sha256": payload, "cause": cause, "known_hit": known, "peer_recent_hit": recent, "candidates_available": action == "gossip", "candidates": []string{}, "targets": []string{}, "suppressed": []string{}}
	if action == "inbound" {
		op["peer"] = peer
	} else {
		op["candidates"] = []string{peer}
		if held {
			op["suppressed"] = []string{peer}
		} else {
			op["targets"] = []string{peer}
		}
	}
	r["cache_operation"] = op
	s.rows = append(s.rows, r)
	return r
}
func scenarioPayload(i int) (string, string) {
	b := []byte(fmt.Sprintf("synthetic unique cache payload %d", i))
	key, sum := keccak.DedupKey(b), sha256.Sum256(b)
	return fmt.Sprintf("0x%x", key), fmt.Sprintf("%x", sum)
}
func (s *cacheScenario) finish(source map[string]any) *frames.Dump {
	s.t.Helper()
	r := s.common("frame")
	for k, v := range s.frame {
		if k != "seq" && k != "journal_segment" && k != "journal_offset" && k != "t_mono_ns" {
			r[k] = v
		}
	}
	op := source["cache_operation"].(map[string]any)
	r["send_attempt"] = map[string]any{"available": true, "sequence": "9", "cache_decision": map[string]any{"instance": op["instance"], "operation": op["sequence"], "source_available": true, "source_seq": fmt.Sprint(source["seq"]), "source_segment": "0", "source_offset": fmt.Sprint(source["journal_offset"])}}
	s.rows = append(s.rows, r)
	tr := s.rows[0]["cache_trace"].(map[string]any)
	tr["instances"], tr["operations"] = strconv.Itoa(s.instances), strconv.Itoa(s.operations)
	return s.dump()
}
func (s *cacheScenario) dump() *frames.Dump {
	s.t.Helper()
	dir := s.t.TempDir()
	f, err := os.Create(filepath.Join(dir, "frames-cache-fixture.jsonl"))
	if err != nil {
		s.t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for _, r := range s.rows {
		if err = encoder.Encode(r); err != nil {
			s.t.Fatal(err)
		}
	}
	if err = f.Close(); err != nil {
		s.t.Fatal(err)
	}
	payload, err := os.ReadFile(filepath.Join("../../frames/testdata/cache-source/payloads", s.payload[:2], s.payload))
	if err != nil {
		s.t.Fatal(err)
	}
	dest := filepath.Join(dir, "payloads", s.payload[:2])
	if err = os.MkdirAll(dest, 0700); err != nil {
		s.t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dest, s.payload), payload, 0600); err != nil {
		s.t.Fatal(err)
	}
	d, err := frames.Load(dir)
	if err != nil {
		s.t.Fatal(err)
	}
	if v := frames.Validate(d); len(v.Problems) != 0 {
		s.t.Fatal(v.Problems)
	}
	return d
}
func cacheVerdicts(t *testing.T, d *frames.Dump) []verdict.Instance {
	t.Helper()
	var result sink
	c := retryWire{check.Base{ID: "timer.retry_wire_suppressed"}}
	if err := c.Run(context.Background(), &check.Inputs{Frames: []*frames.Dump{d}}, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func requireCacheVerdict(t *testing.T, d *frames.Dump, want verdict.Verdict) {
	t.Helper()
	got := cacheVerdicts(t, d)
	if len(got) != 1 || got[0].Verdict != want {
		t.Fatalf("got %+v, want %s", got, want)
	}
}

func TestRetryCacheActualHeldWriteAndMessageLRUEviction(t *testing.T) {
	for _, n := range []int{0, 1023, 1024} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			s := newCacheScenario(t)
			s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
			for i := range n {
				key, sha := scenarioPayload(i)
				s.operation("1", "inbound", s.peer, key, sha, "", false, false, false)
			}
			held := n < 1024
			op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", held, false, held)
			want := verdict.Pass
			if held {
				want = verdict.Fail
			}
			requireCacheVerdict(t, s.finish(op), want)
		})
	}
}
func TestRetryCacheActualHeldWriteAndPeerLRUEviction(t *testing.T) {
	for _, n := range []int{39, 40} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			s := newCacheScenario(t)
			s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
			for i := range n {
				s.operation("1", "gossip", peerAddr(i+10), s.key, s.payload, "gossip", true, false, false)
			}
			held := n < 40
			op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", true, false, held)
			want := verdict.Pass
			if held {
				want = verdict.Fail
			}
			requireCacheVerdict(t, s.finish(op), want)
		})
	}
}
func TestRetryCacheRefreshAndSeparateInstances(t *testing.T) {
	t.Run("suppressed lookup refreshes message", func(t *testing.T) {
		s := newCacheScenario(t)
		s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
		for i := range 1023 {
			key, sha := scenarioPayload(i)
			s.operation("1", "inbound", s.peer, key, sha, "", false, false, false)
		}
		s.operation("1", "gossip", s.peer, s.key, s.payload, "gossip", true, false, true)
		key, sha := scenarioPayload(1023)
		s.operation("1", "inbound", s.peer, key, sha, "", false, false, false)
		op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", true, false, true)
		requireCacheVerdict(t, s.finish(op), verdict.Fail)
	})
	t.Run("suppressed lookup refreshes peer", func(t *testing.T) {
		s := newCacheScenario(t)
		s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
		for i := range 39 {
			s.operation("1", "gossip", peerAddr(i+10), s.key, s.payload, "gossip", true, false, false)
		}
		s.operation("1", "gossip", s.peer, s.key, s.payload, "gossip", true, false, true)
		s.operation("1", "gossip", peerAddr(99), s.key, s.payload, "gossip", true, false, false)
		op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", true, false, true)
		requireCacheVerdict(t, s.finish(op), verdict.Fail)
	})
	t.Run("new instance starts empty", func(t *testing.T) {
		s := newCacheScenario(t)
		s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
		s.instance("2")
		op := s.operation("2", "gossip", s.peer, s.key, s.payload, "retry", false, false, false)
		requireCacheVerdict(t, s.finish(op), verdict.Pass)
	})
}
func TestRetryCacheUnknownOwnershipPrefixAndFailedWrites(t *testing.T) {
	for _, mode := range []string{"owner", "incomplete", "inconsistent", "not-attached", "error"} {
		t.Run(mode, func(t *testing.T) {
			s := newCacheScenario(t)
			s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
			known := mode != "inconsistent"
			op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", known, false, true)
			_ = s.finish(op)
			f := s.rows[len(s.rows)-1]
			switch mode {
			case "owner":
				f["send_attempt"] = map[string]any{"available": false}
			case "incomplete":
				s.rows[0]["cache_trace"].(map[string]any)["complete"] = false
				ref := f["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
				ref["source_available"] = false
				delete(ref, "source_seq")
				delete(ref, "source_segment")
				delete(ref, "source_offset")
			case "not-attached":
				f["write_result"] = "not_attached"
				f["write_error"] = "not_attached"
			case "error":
				f["write_result"] = "error"
				f["write_error"] = "error"
			}
			want := verdict.CannotDecide
			if mode == "not-attached" {
				want = verdict.Pass
			}
			requireCacheVerdict(t, s.dump(), want)
		})
	}
}

func TestRetryCombinedSchedulerAndCacheSource(t *testing.T) {
	d, err := frames.Load("../../frames/testdata/cache-source-combined")
	if err != nil {
		t.Fatal(err)
	}
	if v := frames.Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	requireCacheVerdict(t, d, verdict.Pass)
}
func TestRetryCacheSurvivesPeerReconnection(t *testing.T) {
	s := newCacheScenario(t)
	s.operation("1", "gossip", s.peer, s.key, s.payload, "broadcast", false, false, false)
	for _, event := range []string{"closed", "istanbul_attached"} {
		r := s.common("conn")
		r["peer"] = s.peer
		r["event"] = event
		if event == "closed" {
			r["by"] = "peer"
			r["reason"] = "synthetic disconnect"
		}
		s.rows = append(s.rows, r)
	}
	op := s.operation("1", "gossip", s.peer, s.key, s.payload, "retry", true, false, true)
	requireCacheVerdict(t, s.finish(op), verdict.Fail)
}

func TestRetryCacheFileOrderDoesNotReplaceMutexSequence(t *testing.T) {
	d, err := frames.Load("../../frames/testdata/cache-source")
	if err != nil {
		t.Fatal(err)
	}
	for left, right := 0, len(d.Records)-1; left < right; left, right = left+1, right-1 {
		d.Records[left], d.Records[right] = d.Records[right], d.Records[left]
	}
	if v := frames.Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	requireCacheVerdict(t, d, verdict.Pass)
}
