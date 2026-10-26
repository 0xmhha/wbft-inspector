package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/codec"
	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/observe/journal"
	"github.com/0xmhha/wbft/types"
)

// The producer is a normal chain; the inspector keeps its independent scope.
func TestNormalBLSRevealHeadersRemainPartlyDecided(t *testing.T) {
	dir := t.TempDir()
	validators := testKeys()[:4]
	sc := sim.Scenario{Name: "normal_reveal", Seed: 1, Validators: validators,
		Params: sim.Params{EpochLength: 4, RuleActivations: map[types.RuleName]string{types.RejectNumberJump: "0", types.BLSRandao: "3"}},
		Until:  sim.Stop{Height: 8, Duration: time.Minute}}
	events, journals := filepath.Join(dir, "events"), filepath.Join(dir, "journals")
	result, err := sim.Run(context.Background(), sc, sim.Output{EventsDir: events, JournalDir: journals})
	if err != nil || len(result.Violations) != 0 || len(result.Chain) < 9 {
		t.Fatal("normal chain did not complete", result.Violations, err)
	}
	first, err := sim.NewValidator(validators[0].ECDSA)
	if err != nil {
		t.Fatal(err)
	}
	records, err := journal.ReadAll(nil, filepath.Join(journals, strings.TrimPrefix(strings.ToLower(first.Address().Hex()), "0x")))
	if err != nil || len(records) == 0 {
		t.Fatal("actual journal records missing", err)
	}
	var configuration []byte
	for _, record := range records {
		if segment, ok := record.Body.(*journal.SegmentRec); ok {
			configuration = segment.Core.ChainConfig
			break
		}
	}
	cfg, err := types.ParseChainConfig(configuration)
	if err != nil {
		t.Fatal("actual journal configuration missing", err)
	}
	if at, ok := cfg.RuleActivation(types.BLSRandao); !ok || at.String() != "3" {
		t.Fatal("actual activation differs")
	}
	configPath := filepath.Join(dir, "actual-config.json")
	if err := os.WriteFile(configPath, configuration, 0o600); err != nil {
		t.Fatal(err)
	}
	blocks := filepath.Join(dir, "blocks")
	if err := os.Mkdir(blocks, 0o700); err != nil {
		t.Fatal(err)
	}
	for n := 0; n <= 8; n++ {
		raw, err := codec.EncodeBlock(result.Chain[n])
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(blocks, fmt.Sprintf("%012d.rlp", n)), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	bin := build(t, dir, "./cmd/wbft-inspector", "wbft-inspector")
	out := filepath.Join(dir, "report.json")
	command := exec.Command(bin, "check", "--events", events, "--chain-config", configPath, "--blocks", blocks, "--from", "1", "--to", "7", "--header-node", "normal-observer", "--out", out)
	message, err := command.CombinedOutput()
	report := readReport(t, schema(t), out)
	if err != nil || report.Summary.ExitCode != 0 || len(report.Errors) != 0 {
		t.Fatalf("normal observer failed: %v %s %+v", err, message, report.Errors)
	}
	found := false
	for _, row := range report.Results {
		if row.Verdict == "FAIL" {
			t.Fatal(row.Requirement, row.Violations)
		}
		if row.Requirement == "WBFT-HDR-014" {
			found = true
			if row.Verdict != "CANNOT_DECIDE" || row.Reason == nil || row.Reason.Code != "PARTLY_DECIDED" {
				t.Fatal("BLS cryptographic scope was promoted or misclassified", row)
			}
		}
	}
	if !found {
		t.Fatal("reveal observation absent")
	}
}
