package check_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/check"
	_ "github.com/0xmhha/wbft-inspector/internal/check/all"
	"github.com/0xmhha/wbft-inspector/internal/events"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

// The fixtures are event streams of one node written by the wbft
// simulator: round-changes.jsonl is a node restarted in the middle of a
// height (write-ahead-log replay, re-armed timers), with round-timer
// expiries, retries (one for a past round), the F+1 rule and PRE-PREPARE
// acceptance; engine-stop.jsonl is a node whose engine is stopped.
// The tests change single records and expect the checker of the rule the
// change breaks to fail, while the unchanged streams must not fail.

type rec = map[string]any

func loadRecs(t *testing.T, name string) []rec {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "events", name))
	if err != nil {
		t.Fatal(err)
	}
	var out []rec
	for _, l := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		d := json.NewDecoder(bytes.NewReader(l))
		d.UseNumber()
		var r rec
		if err := d.Decode(&r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func seqOf(r rec) string { return string(r["seq"].(json.Number)) }

func index(t *testing.T, recs []rec, seq string) int {
	t.Helper()
	for i, r := range recs {
		if seqOf(r) == seq {
			return i
		}
	}
	t.Fatalf("no record with seq %s", seq)
	return -1
}

func remove(t *testing.T, recs []rec, seqs ...string) []rec {
	for _, s := range seqs {
		i := index(t, recs, s)
		recs = append(recs[:i:i], recs[i+1:]...)
	}
	return recs
}

func set(t *testing.T, recs []rec, seq, field string, v any) []rec {
	recs[index(t, recs, seq)][field] = v
	return recs
}

// insertAfter inserts a copy of the record seq with the given changes
// after the record after.
func insertAfter(t *testing.T, recs []rec, after, like string, change rec) []rec {
	n := rec{}
	for k, v := range recs[index(t, recs, like)] {
		n[k] = v
	}
	for k, v := range change {
		if v == nil {
			delete(n, k)
		} else {
			n[k] = v
		}
	}
	i := index(t, recs, after) + 1
	recs = append(recs[:i:i], append([]rec{n}, recs[i:]...)...)
	return recs
}

// decide writes the records with consecutive seq numbers and runs every
// checker on them.
func decide(t *testing.T, recs []rec) map[string]verdict.Result {
	t.Helper()
	var buf bytes.Buffer
	for i, r := range recs {
		r["seq"] = json.Number(strings.TrimSpace(jsonInt(i)))
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		buf.Write(append(b, '\n'))
	}
	p := filepath.Join(t.TempDir(), "events.jsonl")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := events.Load([]string{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Errors) > 0 {
		t.Fatalf("stream errors: %v", set.Errors)
	}
	cb, err := os.ReadFile(filepath.Join("..", "..", "testdata", "chain-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := params.ParseGenesis(cb)
	if err != nil {
		t.Fatal(err)
	}
	in := &check.Inputs{Events: set, Config: cfg, Given: map[check.Kind]bool{check.Events: true, check.ChainConfig: true},
		Clock: check.Clock{Model: "shared-host", SchedMs: 100, Margin: 100}}
	sel := map[string]bool{}
	for _, r := range catalog.Rows() {
		sel[r.Requirement] = true
	}
	out := check.Run(context.Background(), in, sel)
	if len(out.Errors) > 0 {
		t.Fatalf("checker errors: %v", out.Errors)
	}
	res := map[string]verdict.Result{}
	for id, insts := range out.Instances {
		res[id] = verdict.Aggregate(insts)
	}
	return res
}

func jsonInt(i int) string { b, _ := json.Marshal(i); return string(b) }

func noFail(t *testing.T, res map[string]verdict.Result) {
	t.Helper()
	for id, r := range res {
		if r.Verdict == verdict.Fail {
			t.Errorf("%s: FAIL: %s", id, r.Violations[0].Message)
		}
	}
}

func wantVerdict(t *testing.T, res map[string]verdict.Result, v verdict.Verdict, ids ...string) {
	t.Helper()
	for _, id := range ids {
		if got := res[id].Verdict; got != v {
			msg := ""
			if len(res[id].Violations) > 0 {
				msg = res[id].Violations[0].Message
			}
			t.Errorf("%s: verdict %s, want %s %s", id, got, v, msg)
		}
	}
}

func TestFixturesPass(t *testing.T) {
	res := decide(t, loadRecs(t, "round-changes.jsonl"))
	noFail(t, res)
	wantVerdict(t, res, verdict.Pass,
		"WBFT-SM-011", "WBFT-SM-013", "WBFT-SM-014", "WBFT-SM-020", "WBFT-SM-030", "WBFT-SM-039", "WBFT-SM-043",
		"WBFT-SM-046", "WBFT-SM-050", "WBFT-SM-057", "WBFT-SM-077", "WBFT-SM-089",
		"WBFT-TIMER-002", "WBFT-TIMER-003", "WBFT-TIMER-005", "WBFT-TIMER-010", "WBFT-TIMER-012", "WBFT-TIMER-013",
		"WBFT-TIMER-015", "WBFT-TIMER-016", "WBFT-TIMER-020", "WBFT-TIMER-021", "WBFT-TIMER-022", "WBFT-TIMER-023",
		"WBFT-TIMER-041")
	res = decide(t, loadRecs(t, "engine-stop.jsonl"))
	noFail(t, res)
	wantVerdict(t, res, verdict.Pass, "WBFT-TIMER-018")
}

func TestMutationsFail(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		mutate func(*testing.T, []rec) []rec
		fail   []string
	}{
		{"round timer not armed on entering a view", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "15") },
			[]string{"WBFT-SM-030", "WBFT-TIMER-010"}},
		{"round timer with a wrong duration", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "15", "duration_ms", json.Number("7000")) },
			[]string{"WBFT-TIMER-005", "WBFT-TIMER-002", "WBFT-TIMER-010"}},
		{"retry timer not cancelled when the round timer is armed", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "37") },
			[]string{"WBFT-SM-030", "WBFT-TIMER-013"}},
		{"no ROUND-CHANGE after a round-timer expiry", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "17") },
			[]string{"WBFT-TIMER-015"}},
		{"a FUTURE message relayed", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec {
				return insertAfter(t, r, "47", "41", rec{"step": json.Number("24"), "code": json.Number("19"), "dedup_key": r[index(t, r, "48")]["dedup_key"]})
			},
			[]string{"WBFT-SM-013"}},
		{"a FUTURE message with outcome ACCEPT", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "48", "outcome", "ACCEPT") },
			[]string{"WBFT-SM-020"}},
		{"a relay with other bytes", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec {
				return set(t, r, "41", "dedup_key", "0x0000000000000000000000000000000000000000000000000000000000000001")
			},
			[]string{"WBFT-SM-011"}},
		{"an own message never processed by the node", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "43") },
			[]string{"WBFT-SM-014"}},
		{"build for round 2 waits", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "14", "wait_ms", json.Number("500")) },
			[]string{"WBFT-TIMER-041"}},
		{"retry expiry without a ROUND-CHANGE", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "8") },
			[]string{"WBFT-SM-077", "WBFT-TIMER-021"}},
		{"retry expiry for a past round sends a ROUND-CHANGE", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec {
				return insertAfter(t, r, "20", "8", rec{"step": json.Number("13")})
			},
			[]string{"WBFT-SM-077", "WBFT-TIMER-022"}},
		{"retry timer with a doubled duration", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "16", "duration_ms", json.Number("4000")) },
			[]string{"WBFT-TIMER-020", "WBFT-TIMER-003"}},
		{"retry timer cancelled on its own", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "37", "step", json.Number("999")) },
			[]string{"WBFT-TIMER-023"}},
		{"F+1 rule without start_new_round", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "34") },
			[]string{"WBFT-SM-057"}},
		{"ROUND-CHANGE without a cause", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return set(t, r, "33", "what", "ROUND_CHANGE") },
			[]string{"WBFT-SM-089"}},
		{"PRE-PREPARE accepted without entering Preprepared", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "58") },
			[]string{"WBFT-SM-039"}},
		{"expiry of a superseded round timer changes the view", "round-changes.jsonl",
			func(t *testing.T, r []rec) []rec {
				// Inserted in reverse order: the expiry comes first.
				r = insertAfter(t, r, "60", "13", rec{"step": json.Number("900"), "t_mono_ns": json.Number("16117000000")})
				return insertAfter(t, r, "60", "12", rec{"step": json.Number("900"), "gen": json.Number("11"), "t_mono_ns": json.Number("16117000000")})
			},
			[]string{"WBFT-TIMER-014"}},
		{"engine stopped with a timer armed", "engine-stop.jsonl",
			func(t *testing.T, r []rec) []rec { return remove(t, r, "114") },
			[]string{"WBFT-TIMER-018"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := decide(t, c.mutate(t, loadRecs(t, c.file)))
			wantVerdict(t, res, verdict.Fail, c.fail...)
		})
	}
}

func TestDecisionAndCommitRules(t *testing.T) {
	recs := loadRecs(t, "round-changes.jsonl")
	// Find the first decision of the stream.
	var quorumSeq, committedSeq string
	for i, r := range recs {
		if r["kind"] == "STATE" && r["to"] == "Committed" {
			committedSeq = seqOf(r)
			quorumSeq = seqOf(recs[i-1])
			break
		}
	}
	if committedSeq == "" || recs[index(t, recs, quorumSeq)]["what"] != "COMMIT" {
		t.Fatal("fixture has no COMMIT quorum followed by Committed")
	}
	t.Run("decide without Committed", func(t *testing.T) {
		wantVerdict(t, decide(t, remove(t, loadRecs(t, "round-changes.jsonl"), committedSeq)), verdict.Fail, "WBFT-SM-046")
	})
	t.Run("round timer cancelled at the decision", func(t *testing.T) {
		r := loadRecs(t, "round-changes.jsonl")
		// The live round timer at the decision is the last round-timer arm
		// before it.
		var gen any
		for _, x := range r[:index(t, r, committedSeq)] {
			if x["kind"] == "TIMER_ARM" && x["timer"] == "round" {
				gen = x["gen"]
			}
		}
		like := ""
		for _, x := range r {
			if x["kind"] == "TIMER_CANCEL" && x["timer"] == "round" {
				like = seqOf(x)
				break
			}
		}
		st := r[index(t, r, committedSeq)]
		r = insertAfter(t, r, committedSeq, like, rec{"gen": gen, "step": st["step"], "t_mono_ns": st["t_mono_ns"]})
		wantVerdict(t, decide(t, r), verdict.Fail, "WBFT-SM-050", "WBFT-TIMER-016")
	})
	t.Run("PREPARE quorum below Q", func(t *testing.T) {
		r := loadRecs(t, "round-changes.jsonl")
		for _, x := range r {
			if x["kind"] == "QUORUM" && x["what"] == "PREPARE" {
				x["count"] = json.Number("2")
				break
			}
		}
		wantVerdict(t, decide(t, r), verdict.Fail, "WBFT-SM-043")
	})
}

func TestWithoutChainConfigDurationsAreUndecided(t *testing.T) {
	set, err := events.Load([]string{filepath.Join("..", "..", "testdata", "events", "round-changes.jsonl")})
	if err != nil {
		t.Fatal(err)
	}
	in := &check.Inputs{Events: set, Given: map[check.Kind]bool{check.Events: true}, Clock: check.Clock{SchedMs: 100, Margin: 100}}
	out := check.Run(context.Background(), in, map[string]bool{"WBFT-TIMER-005": true, "WBFT-TIMER-020": true})
	for _, id := range []string{"WBFT-TIMER-005", "WBFT-TIMER-003"} {
		r := verdict.Aggregate(out.Instances[id])
		if r.Verdict != verdict.CannotDecide || r.Reason != verdict.MissingData {
			t.Errorf("%s: %s %s, want CANNOT_DECIDE MISSING_DATA", id, r.Verdict, r.Reason)
		}
	}
}

// A failure on a node that declares optional behaviours is not a verdict
// the public build can give.
func TestOptionalBehavioursMakeFailuresUndecided(t *testing.T) {
	r := remove(t, loadRecs(t, "round-changes.jsonl"), "15")
	r[0]["improvements"] = []any{map[string]any{"id": "X", "source": "node"}}
	res := decide(t, r)
	for _, id := range []string{"WBFT-SM-030", "WBFT-TIMER-010"} {
		if res[id].Verdict == verdict.Fail || res[id].Reasons[verdict.NotInBuild] == 0 {
			t.Errorf("%s: %s, reasons %v; want the failure turned into NOT_IN_BUILD", id, res[id].Verdict, res[id].Reasons)
		}
	}
}

func TestRegistryMatchesCatalog(t *testing.T) {
	for _, c := range check.All() {
		for _, id := range c.Requirements() {
			row, ok := catalog.RowOf(id)
			if !ok {
				t.Errorf("checker %s decides %s, which has no catalog row", c.Name(), id)
				continue
			}
			if row.Checker != c.Name() {
				t.Errorf("%s: catalog names checker %s, registered %s", id, row.Checker, c.Name())
			}
		}
	}
}
