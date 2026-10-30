package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/report"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func TestPrepareObserverSelectionPreservesPrimary(t *testing.T) {
	for _, token := range []string{"sec.prepare_justification_pairs", "sec.prepare_justification_*"} {
		selected, unknown := selectRows([]string{token})
		if len(selected) != 1 || !selected["WBFT-SEC-041"] || len(unknown) != 0 {
			t.Fatalf("%s: %v %v", token, selected, unknown)
		}
	}
	c, ok := check.ForRequirement("WBFT-SEC-041")
	if !ok || c.Name() != "sec.equivocation_reported" {
		t.Fatalf("primary changed: %v %v", c, ok)
	}
	for _, c := range check.All() {
		if c.Name() == "sec.prepare_justification_pairs" {
			t.Fatal("observer acquired primary registry ownership")
		}
	}
}

// This exercises the real CLI entry assembler with unsigned model results.
// It does not claim a conflicting signed-pair CLI end-to-end execution.
func TestPrepareObserverEntrySurvivesMissingPrimaryEvents(t *testing.T) {
	id := "WBFT-SEC-041"
	out := &check.Outcome{Missing: map[string][]check.Kind{"sec.equivocation_reported": {check.Events}}, Ran: map[string]bool{},
		Instances: map[string][]verdict.Instance{id: {{Requirement: id, Key: "unsigned-model", Verdict: verdict.CannotDecide,
			Reason: verdict.ObserverScope, Actual: map[string]string{"schema": "wbft-prepare-justification-observation/1", "status": "cryptographic_candidate"},
			Evidence: []evidence.Pointer{{Kind: evidence.KindFrame, FrameID: "first"}, {Kind: evidence.KindFrame, FrameID: "second"}}}}}}
	entry := checkerReportEntry(id, out)
	if len(entry.Instances) != 2 || entry.Instances[0].Reason != verdict.MissingData || entry.Instances[1].Key != "unsigned-model" {
		t.Fatalf("missing primary or observation hidden: %+v", entry)
	}
	result := report.MakeResult(entry)
	encoded, err := json.Marshal(result)
	if err != nil || result.Coverage.CannotDecide != 2 || result.Coverage.Pass != 0 {
		t.Fatalf("result %+v %v", result, err)
	}
	for _, value := range []string{"primary_checker", "cryptographic_candidate", "first", "second"} {
		if !strings.Contains(string(encoded), value) {
			t.Fatalf("lost %s in %s", value, encoded)
		}
	}
	out.Instances = nil
	entry = checkerReportEntry(id, out)
	if len(entry.Instances) != 0 || entry.Undecided != verdict.MissingData || entry.Checker != "sec.equivocation_reported" {
		t.Fatal("legacy primary missing-data entry changed", entry)
	}
}
