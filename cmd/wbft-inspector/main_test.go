package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/report"
)

func testdata(p string) string { return filepath.Join("..", "..", "testdata", p) }

func runCLI(t *testing.T, args ...string) (int, *report.Report, string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "report.json")
	var stdout, stderr bytes.Buffer
	code := run(append(args, "--out", out), &stdout, &stderr)
	b, err := os.ReadFile(out)
	if err != nil {
		return code, nil, stderr.String()
	}
	var r report.Report
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	return code, &r, stderr.String()
}

func TestCheckReport(t *testing.T) {
	code, r, stderr := runCLI(t, "check", "--events", testdata("events"), "--chain-config", testdata("chain-config.json"),
		"--checks", "P0,P1,P2,V,WBFT-SM-999")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if r.Schema != report.SchemaID || r.Run.Inspector.Build != "public" || r.Run.Inspector.CatalogSHA256 == "" {
		t.Fatalf("run header: %+v", r.Run.Inspector)
	}
	if len(r.Run.Inputs) != 3 || len(r.Run.Nodes) != 1 {
		t.Fatalf("inputs %d, nodes %d", len(r.Run.Inputs), len(r.Run.Nodes))
	}
	byID := map[string]report.Result{}
	for _, x := range r.Results {
		byID[x.Requirement] = x
	}
	if x := byID["WBFT-SM-999"]; x.Verdict != "CANNOT_DECIDE" || x.Reason == nil || x.Reason.Code != "NOT_IN_BUILD" {
		t.Errorf("unknown ID: %+v", x)
	}
	if x := byID["WBFT-TIMER-005"]; x.Verdict != "PASS" || x.Coverage.Instances == 0 {
		t.Errorf("WBFT-TIMER-005: %+v", x)
	}
	if x := byID["WBFT-SM-003"]; x.Verdict != "NOT_RUN" {
		t.Errorf("a requirement without a checker: %+v", x)
	}
	if r.Summary.Requirements.Fail != 0 || r.Summary.ExitCode != 0 {
		t.Errorf("summary %+v", r.Summary)
	}
}

func TestCheckIsDeterministic(t *testing.T) {
	args := []string{"check", "--events", testdata("events"), "--chain-config", testdata("chain-config.json")}
	_, a, _ := runCLI(t, args...)
	_, b, _ := runCLI(t, args...)
	for _, r := range []*report.Report{a, b} {
		r.Run.StartedAt, r.Run.FinishedAt, r.Run.Command = "", "", nil
	}
	ja, _ := json.Marshal(a)
	jb, _ := json.Marshal(b)
	if !bytes.Equal(ja, jb) {
		t.Fatal("two runs on the same input differ beyond the run times")
	}
}

func TestCheckWithoutConfigLeavesDurationsUndecided(t *testing.T) {
	code, r, _ := runCLI(t, "check", "--events", testdata("events"), "--checks", "timer.round_timeout")
	if code != report.ExitOK {
		t.Fatalf("exit %d", code)
	}
	for _, x := range r.Results {
		if x.Verdict != "CANNOT_DECIDE" || x.Reason.Code != "MISSING_DATA" {
			t.Errorf("%s: %s %+v", x.Requirement, x.Verdict, x.Reason)
		}
	}
}

func TestRequireDecided(t *testing.T) {
	f := filepath.Join(t.TempDir(), "ids.txt")
	// WBFT-TIMER-017 is not exercised by the fixtures; WBFT-SM-011 is.
	if err := os.WriteFile(f, []byte("# scenario list\nWBFT-SM-011\nWBFT-TIMER-017\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, r, _ := runCLI(t, "check", "--events", testdata("events"), "--chain-config", testdata("chain-config.json"), "--require-decided", f)
	if code != report.ExitCoverage || r.Summary.ExitCode != report.ExitCoverage {
		t.Fatalf("exit %d, want %d", code, report.ExitCoverage)
	}
	found := false
	for _, e := range r.Errors {
		if strings.Contains(e.Message, "WBFT-TIMER-017") {
			found = true
		}
	}
	if !found {
		t.Errorf("errors %v do not name WBFT-TIMER-017", r.Errors)
	}
}

func TestFailExitCode(t *testing.T) {
	// A stream whose round timer is armed with a wrong duration.
	b, err := os.ReadFile(testdata("events/round-changes.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Replace(string(b), `"duration_ms":8000`, `"duration_ms":7000`, 1)
	p := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
	code, r, _ := runCLI(t, "check", "--events", p, "--chain-config", testdata("chain-config.json"))
	if code != report.ExitFail || r.Summary.FailBySeverity["medium"] == 0 {
		t.Fatalf("exit %d, summary %+v", code, r.Summary)
	}
	code, _, _ = runCLI(t, "check", "--events", p, "--chain-config", testdata("chain-config.json"), "--fail-on", "critical")
	if code != report.ExitOK {
		t.Fatalf("exit %d with --fail-on critical", code)
	}
}

func TestUsageAndMissingInput(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"nope"}, &o, &e); code != report.ExitUsage {
		t.Errorf("unknown command: exit %d", code)
	}
	code, r, _ := runCLI(t, "check", "--events", filepath.Join(t.TempDir(), "missing.jsonl"))
	if code != report.ExitNoInput || len(r.Errors) == 0 {
		t.Errorf("missing input: exit %d", code)
	}
}

func TestCatalogList(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"catalog", "list", "--chapter", "A-06"}, &o, &e); code != 0 {
		t.Fatalf("exit %d: %s", code, e.String())
	}
	if !strings.Contains(o.String(), "WBFT-TIMER-005") || !strings.Contains(o.String(), "implemented") {
		t.Fatalf("output: %s", o.String())
	}
}
