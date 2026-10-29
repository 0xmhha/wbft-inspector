package headers

import (
	"fmt"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"os"
	"testing"
)

// The existing signed corpus is decoded unchanged, with the successor absent.
func TestSuccessorTailUnknownOnOriginalHeaders(t *testing.T) {
	s := &Source{Offline: true}
	for n := uint64(0); n < 4; n++ {
		raw, err := os.ReadFile(fmt.Sprintf("testdata/%d.json", n))
		if err != nil {
			t.Fatal(err)
		}
		encoded, _, err := JSONHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		h, err := header.Decode(encoded)
		if err != nil {
			t.Fatal(err)
		}
		s.remember(n, h)
	}
	r := &Range{Source: s, From: 1, To: 3, Node: "original", Input: "original"}
	got, err := r.Analyze(config(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range got.Findings {
		if f.Kind == "decision_round_unknown" {
			if f.Count != 1 || len(f.Evidence) != 1 || f.Evidence[0].Number != "3" {
				t.Fatal(f)
			}
			found = true
		}
		if f.Kind == "proposer_schedule_diff" {
			if len(f.Evidence) != 2 || f.Evidence[1].Field != "extra.prev_round" || f.Evidence[0].Number == "3" {
				t.Fatal("unconfirmed schedule or missing child pointer", f)
			}
		}
	}
	if !found {
		t.Fatal("tail did not remain explicitly unconfirmed", got)
	}
	// A fresh observer policy projects a schedule difference over the exact same
	// original bytes. This is a configuration observation, not a chain fault.
	cfg := config(t)
	policy := uint64(1)
	cfg.Base.ProposerPolicy = &policy
	projected, err := r.Analyze(cfg)
	if err != nil {
		t.Fatal(err)
	}
	schedules := 0
	for _, f := range projected.Findings {
		if f.Kind != "proposer_schedule_diff" {
			continue
		}
		schedules += f.Count
		if len(f.Evidence) != 2*f.Count {
			t.Fatal("missing evidence pairs", f)
		}
		for i := 0; i < len(f.Evidence); i += 2 {
			own, carrier := f.Evidence[i], f.Evidence[i+1]
			if own.Field != "Coinbase" || carrier.Field != "extra.prev_round" || own.Number == "3" {
				t.Fatal(f)
			}
			if own.Number == "1" && carrier.Number != "2" || own.Number == "2" && carrier.Number != "3" {
				t.Fatal("wrong carrier", f)
			}
			if own.Hash == carrier.Hash || own.Node != carrier.Node || own.Input != carrier.Input {
				t.Fatal(f)
			}
		}
	}
	if schedules == 0 {
		t.Fatal("schedule evidence assertion was not exercised")
	}

}
