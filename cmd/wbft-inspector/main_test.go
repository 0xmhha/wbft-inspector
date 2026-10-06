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

// TestFramesVerify validates the wbft frame dump fixture, and refuses a
// directory without frame files and a missing --frames.
func TestFramesVerify(t *testing.T) {
	var o, e bytes.Buffer
	if code := run([]string{"frames", "verify", "--frames", testdata("frames/wbft-kvstore")}, &o, &e); code != report.ExitOK {
		t.Fatalf("exit %d: %s %s", code, o.String(), e.String())
	}
	var out struct {
		Problems []string       `json:"problems"`
		Records  map[string]int `json:"records"`
	}
	if err := json.Unmarshal(o.Bytes(), &out); err != nil || len(out.Problems) != 0 || out.Records["frame"] == 0 {
		t.Fatalf("output %s: %v", o.String(), err)
	}
	if code := run([]string{"frames", "verify", "--frames", t.TempDir()}, &o, &e); code != report.ExitNoInput {
		t.Fatalf("empty directory: exit %d", code)
	}
	if code := run([]string{"frames", "verify"}, &o, &e); code != report.ExitUsage {
		t.Fatalf("no --frames: exit %d", code)
	}
}

// TestCheckFrames decides the frame checkers from the wbft frame dump: the
// node sent only consensus codes, and the dump has no frame of the other
// decided rows.
func TestCheckFrames(t *testing.T) {
	code, r, stderr := runCLI(t, "check", "--frames", testdata("frames/wbft-kvstore"), "--checks", "net.*")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(r.Run.Inputs) != 1 || r.Run.Inputs[0].Kind != "frames" || r.Run.Inputs[0].Records == 0 || len(r.Errors) != 0 {
		t.Fatalf("inputs %+v errors %+v", r.Run.Inputs, r.Errors)
	}
	byID := map[string]report.Result{}
	for _, x := range r.Results {
		byID[x.Requirement] = x
	}
	if x := byID["WBFT-NET-011"]; x.Verdict != "PASS" || x.Coverage.Instances == 0 {
		t.Errorf("WBFT-NET-011: %+v", x)
	}
	for _, id := range []string{"WBFT-NET-013", "WBFT-NET-020", "WBFT-NET-021", "WBFT-NET-028"} {
		if x := byID[id]; x.Verdict != "CANNOT_DECIDE" || x.Reason == nil || x.Reason.Code != "NOT_EXERCISED" {
			t.Errorf("%s: %+v", id, x)
		}
	}
	// Without --frames the checker lacks its input.
	_, r, _ = runCLI(t, "check", "--events", testdata("events"), "--checks", "WBFT-NET-011")
	if x := r.Results[0]; x.Verdict != "CANNOT_DECIDE" || x.Reason == nil || x.Reason.Code != "MISSING_DATA" {
		t.Errorf("without frames: %+v", x)
	}
}

// TestCheckRetryWire decides WBFT-TIMER-024 from the dump of a stalled
// wbft network: every retransmission was left off the wire.
func TestCheckRetryWire(t *testing.T) {
	code, r, stderr := runCLI(t, "check", "--frames", testdata("frames/wbft-kvstore-stalled"), "--checks", "WBFT-TIMER-024")
	if code != report.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if len(r.Results) != 1 || r.Results[0].Verdict != "PASS" || r.Results[0].Coverage.Instances == 0 || len(r.Errors) != 0 {
		t.Fatalf("results %+v errors %+v", r.Results, r.Errors)
	}
}

// TestCheckLogs checks a node through its log instead of its event stream:
// both files come from one run of a wbft node with every module at trace
// (internal/logs/testdata). A checker that judges log runs reaches the same
// verdict and instance count from either; a checker that measures
// monotonic time cannot decide the log run (NEEDS_NODE_FEATURE).
func TestCheckLogs(t *testing.T) {
	const node = "0xa79140f1543ba4be52a0bb330e8088c67a89e655"
	logsDir := filepath.Join("..", "..", "internal", "logs", "testdata")
	sel := "sm.*,timer.*"
	code, fromEvents, stderr := runCLI(t, "check", "--events", filepath.Join(logsDir, "node.events.jsonl"), "--checks", sel)
	if code != report.ExitOK {
		t.Fatalf("events: exit %d: %s", code, stderr)
	}
	code, fromLogs, stderr := runCLI(t, "check", "--logs", strings.ToUpper(node[:4])+node[4:]+"="+filepath.Join(logsDir, "node.log"),
		"--log-profile", filepath.Join(logsDir, "wbft-profile.json"), "--checks", sel)
	if code != report.ExitOK {
		t.Fatalf("logs: exit %d: %s", code, stderr)
	}
	if in := fromLogs.Run.Inputs; len(in) != 1 || in[0].Kind != "log" || in[0].Node != node || len(fromLogs.Errors) != 0 {
		t.Fatalf("log input %+v, errors %v", in, fromLogs.Errors)
	}
	evBy := map[string]report.Result{}
	for _, x := range fromEvents.Results {
		evBy[x.Requirement] = x
	}
	mono := map[string]bool{"sm.round_timer_on_entry": true, "sm.accept_preprepare_order": true, "sm.first_rc_cause": true,
		"timer.round_timeout": true, "timer.cancel_on_arm": true}
	passes := 0
	for _, x := range fromLogs.Results {
		e := evBy[x.Requirement]
		switch {
		case x.Verdict == "NOT_RUN":
		case mono[x.Checker]:
			if x.Verdict != "CANNOT_DECIDE" || x.Reason == nil || x.Reason.Code != "NEEDS_NODE_FEATURE" {
				t.Errorf("%s (%s) from logs: %+v", x.Requirement, x.Checker, x)
			}
		default:
			if x.Verdict != e.Verdict || x.Coverage.Instances != e.Coverage.Instances {
				t.Errorf("%s (%s): %s with %d instances from logs, %s with %d from events", x.Requirement, x.Checker,
					x.Verdict, x.Coverage.Instances, e.Verdict, e.Coverage.Instances)
			}
			if x.Verdict == "PASS" {
				passes++
			}
		}
	}
	if passes == 0 {
		t.Fatal("no requirement passed from logs")
	}
	// Both together: the inputs and the instances add up.
	code, both, stderr := runCLI(t, "check", "--events", filepath.Join(logsDir, "node.events.jsonl"),
		"--logs", node+"="+filepath.Join(logsDir, "node.log"), "--log-profile", filepath.Join(logsDir, "wbft-profile.json"), "--checks", sel)
	if code != report.ExitOK || len(both.Run.Inputs) != 2 {
		t.Fatalf("both: exit %d, inputs %+v: %s", code, both.Run.Inputs, stderr)
	}
	logBy := map[string]report.Result{}
	for _, x := range fromLogs.Results {
		logBy[x.Requirement] = x
	}
	for _, x := range both.Results {
		if x.Verdict == "PASS" && x.Coverage.Instances != evBy[x.Requirement].Coverage.Instances+logBy[x.Requirement].Coverage.Instances {
			t.Errorf("%s: %d instances from both, %d + %d apart", x.Requirement, x.Coverage.Instances,
				evBy[x.Requirement].Coverage.Instances, logBy[x.Requirement].Coverage.Instances)
		}
	}
	// Without the profile, --logs is a usage error.
	if code, _, _ := runCLI(t, "check", "--logs", node+"="+filepath.Join(logsDir, "node.log")); code != report.ExitUsage {
		t.Fatalf("--logs without --log-profile: exit %d", code)
	}
}
