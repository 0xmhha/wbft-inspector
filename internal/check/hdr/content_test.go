package hdr

import (
	"context"
	"os"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/headers"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

type contentCollector struct{ Instances map[string][]verdict.Instance }

func (c *contentCollector) Emit(i verdict.Instance) {
	c.Instances[i.Requirement] = append(c.Instances[i.Requirement], i)
}
func TestContentScopeAndDeterministicWorkers(t *testing.T) {
	raw, err := os.ReadFile("../../headers/testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := params.ParseGenesis(raw)
	if err != nil {
		t.Fatal(err)
	}
	for run := 0; run < 2; run++ {
		input := &check.Inputs{Config: cfg, Headers: &headers.Range{Source: &headers.Source{Blocks: "../../headers/testdata", Context: context.Background()}, From: 0, To: 3, Node: "a", Input: "in-1"}}
		c := headerContent{check.Base{ID: "hdr.canonical_content", Reqs: contentRequirements, Kinds: []check.Kind{check.Headers}}}
		out := &contentCollector{Instances: map[string][]verdict.Instance{}}
		if err := c.Run(context.Background(), input, out); err != nil {
			t.Fatal(err)
		}
		for _, id := range contentRequirements {
			r := verdict.Aggregate(out.Instances[id])
			if id == "WBFT-HDR-014" {
				if r.Verdict != verdict.CannotDecide || r.Reason != verdict.PartlyDecided || r.Pass != 3 || r.CannotDecide != 3 {
					t.Fatal(r)
				}
			} else if r.Verdict != verdict.Pass || r.Pass != 3 {
				t.Fatal(id, r)
			}
		}
		for _, xs := range out.Instances {
			for _, i := range xs {
				if len(i.Evidence) != 1 || i.Evidence[0].Hash == "" || i.Evidence[0].Number == "0" {
					t.Fatal("genesis or missing pointer", i)
				}
			}
		}
	}
}
