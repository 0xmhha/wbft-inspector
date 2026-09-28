package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/0xmhha/wbft/conformance/sim"
	"github.com/0xmhha/wbft/crypto/bls"
	"github.com/0xmhha/wbft/crypto/keccak"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// repoRoot is the root of the inspector repository.
var repoRoot = filepath.Join("..", "..")

// build compiles a command of the inspector module into dir.
func build(t *testing.T, dir, pkg, name string) string {
	t.Helper()
	out := filepath.Join(dir, name)
	cmd := exec.Command("go", "build", "-o", out, pkg)
	cmd.Dir = repoRoot
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build %s: %v\n%s", pkg, err, b)
	}
	return out
}

func seeds(t *testing.T) int {
	if s := os.Getenv("WBFT_E2E_SEEDS"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 1 {
			t.Fatalf("WBFT_E2E_SEEDS=%q", s)
		}
		return n
	}
	if testing.Short() {
		return 1
	}
	return 3
}

// testKeys are the simulator's test keys (never keys of a real network).
func testKeys() []sim.Validator {
	keys := make([]sim.Validator, 8)
	for i := range keys {
		keys[i] = sim.Validator{ECDSA: keccak.Sum256Bytes([]byte("wbft-sim-key-" + strconv.Itoa(i)))}
	}
	return keys
}

// chainConfig writes the consensus part of the chain configuration of a
// scenario, with the simulator's defaults for parameters left at zero.
func chainConfig(t *testing.T, dir string, p sim.Params) string {
	t.Helper()
	w := map[string]any{"requestTimeoutSeconds": p.RequestTimeoutSeconds, "blockPeriodSeconds": p.BlockPeriodSeconds,
		"epochLength": p.EpochLength, "proposerPolicy": 0}
	if p.RequestTimeoutSeconds == 0 {
		w["requestTimeoutSeconds"] = 2
	}
	if p.BlockPeriodSeconds == 0 {
		w["blockPeriodSeconds"] = 1
	}
	if p.EpochLength == 0 {
		w["epochLength"] = uint64(1) << 40
	}
	if p.MaxRequestTimeoutSeconds != nil {
		w["maxRequestTimeoutSeconds"] = *p.MaxRequestTimeoutSeconds
	}
	b, err := json.Marshal(map[string]any{"config": map[string]any{"chainId": 1, "anzeon": map[string]any{"wbft": w}}})
	if err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "chain-config.json")
	if err := os.WriteFile(f, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return f
}

type result struct {
	Requirement string `json:"requirement"`
	Verdict     string `json:"verdict"`
	Checker     string `json:"checker"`
	Reason      *struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	} `json:"reason"`
	Violations []struct {
		Message string `json:"message"`
	} `json:"violations"`
}

type reportDoc struct {
	Run struct {
		Inspector struct {
			Build string `json:"build"`
		} `json:"inspector"`
	} `json:"run"`
	Summary struct {
		ExitCode int `json:"exit_code"`
	} `json:"summary"`
	Results []result `json:"results"`
	Errors  []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func schema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	c := jsonschema.NewCompiler()
	s, err := c.Compile(filepath.Join(repoRoot, "schema", "report-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func readReport(t *testing.T, s *jsonschema.Schema, path string) reportDoc {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Validate(inst); err != nil {
		t.Fatalf("%s does not follow schema/report-v1.json: %v", path, err)
	}
	var r reportDoc
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	return r
}

// scenarios returns the simulator's scenario bundle and one scenario of its
// own: a stopped proposer on a chain whose round timeout is capped below the
// base timeout, where every round >= 1 lasts the cap (A-06 WBFT-TIMER-006,
// WBFT-TIMER-007).
func scenarios(keys []sim.Validator) []sim.Template {
	ts := sim.Bundle()
	capped := sim.Template{Name: "capped_timeout", Needs: 4, Make: func(seed int64, k []sim.Validator) sim.Scenario {
		one := uint64(1)
		v1, _ := sim.NewValidator(k[1].ECDSA)
		return sim.Scenario{Name: "capped_timeout", Seed: seed, Validators: append([]sim.Validator(nil), k[:4]...),
			Params: sim.Params{RequestTimeoutSeconds: 2, MaxRequestTimeoutSeconds: &one},
			Schedule: []sim.NodeEvent{{At: 1500 * time.Millisecond, Node: v1.Address(), Action: sim.ActionStop},
				{At: 9 * time.Second, Node: v1.Address(), Action: sim.ActionRestart}},
			Until: sim.Stop{Height: 8, Duration: 3 * time.Minute}}
	}}
	return append(ts, capped)
}

// TestSimulatorEvents runs every scenario of the simulator, writes the event
// streams of all nodes, checks them with the inspector and requires that no
// requirement fails and that every report follows the schema. It prints
// which requirements of A-05 and A-06 were decided.
func TestSimulatorEvents(t *testing.T) {
	bls.SetParallelism(1)
	bin := build(t, t.TempDir(), "./cmd/wbft-inspector", "wbft-inspector")
	sch := schema(t)
	keys := testKeys()
	n := seeds(t)
	decided := map[string]map[string]int{} // requirement -> verdict -> reports
	checkers := map[string]string{}
	runs := 0
	for _, tmpl := range scenarios(keys) {
		for seed := int64(1); seed <= int64(n); seed++ {
			name := fmt.Sprintf("%s-%d", tmpl.Name, seed)
			sc := tmpl.Make(seed, keys)
			dir := t.TempDir()
			evDir := filepath.Join(dir, "events")
			res, err := sim.Run(context.Background(), sc, sim.Output{EventsDir: evDir})
			if err != nil {
				t.Fatalf("%s: simulation: %v", name, err)
			}
			if len(res.Violations) > 0 {
				t.Fatalf("%s: the simulator reports violations: %v", name, res.Violations)
			}
			out := filepath.Join(dir, "report.json")
			cmd := exec.Command(bin, "check", "--events", evDir, "--chain-config", chainConfig(t, dir, sc.Params), "--out", out)
			msg, err := cmd.CombinedOutput()
			rep := readReport(t, sch, out)
			if err != nil || rep.Summary.ExitCode != 0 {
				for _, r := range rep.Results {
					if r.Verdict == "FAIL" {
						t.Errorf("%s: %s FAIL: %s", name, r.Requirement, r.Violations[0].Message)
					}
				}
				t.Fatalf("%s: inspector exit %v (%s), errors %v", name, err, msg, rep.Errors)
			}
			if rep.Run.Inspector.Build != "public" {
				t.Fatalf("%s: build %q", name, rep.Run.Inspector.Build)
			}
			for _, e := range rep.Errors {
				t.Errorf("%s: report error: %s", name, e.Message)
			}
			for _, r := range rep.Results {
				if decided[r.Requirement] == nil {
					decided[r.Requirement] = map[string]int{}
				}
				decided[r.Requirement][r.Verdict]++
				checkers[r.Requirement] = r.Checker
			}
			runs++
		}
	}
	// Coverage table: PASS in at least one scenario, only undecided, or no
	// checker yet.
	var ids []string
	for id := range decided {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var passed, undecided, notRun []string
	for _, id := range ids {
		v := decided[id]
		switch {
		case v["FAIL"] > 0:
			t.Errorf("%s failed in %d reports", id, v["FAIL"])
		case v["PASS"] > 0:
			passed = append(passed, id)
		case v["NOT_RUN"] > 0:
			notRun = append(notRun, id)
		default:
			undecided = append(undecided, id)
		}
		t.Logf("%-16s %-32s %v", id, checkers[id], v)
	}
	t.Logf("%d reports: %d requirements PASS in at least one scenario, %d only undecided (%s), %d without a checker",
		runs, len(passed), len(undecided), strings.Join(undecided, " "), len(notRun))
	// Requirements every run of the bundle exercises; a checker that stops
	// deciding them is a regression of the inspector or of the event stream.
	for _, id := range []string{"WBFT-SM-011", "WBFT-SM-013", "WBFT-SM-014", "WBFT-SM-020", "WBFT-SM-030", "WBFT-SM-039",
		"WBFT-SM-043", "WBFT-SM-046", "WBFT-SM-050", "WBFT-SM-057", "WBFT-SM-077", "WBFT-SM-089", "WBFT-TIMER-002",
		"WBFT-TIMER-003", "WBFT-TIMER-005", "WBFT-TIMER-006", "WBFT-TIMER-007", "WBFT-TIMER-010", "WBFT-TIMER-012",
		"WBFT-TIMER-013", "WBFT-TIMER-015", "WBFT-TIMER-016", "WBFT-TIMER-018", "WBFT-TIMER-020", "WBFT-TIMER-021",
		"WBFT-TIMER-022", "WBFT-TIMER-023", "WBFT-TIMER-041"} {
		if decided[id]["PASS"] == 0 {
			t.Errorf("%s was not decided PASS in any scenario: %v", id, decided[id])
		}
	}
}

// TestVectorsAgainstWbftAdapter runs every public vector against the vector
// adapter of the pinned wbft version (WBFT_SPEC_DIR names a wbft-spec
// checkout) and requires that no case fails and that every file is read.
func TestVectorsAgainstWbftAdapter(t *testing.T) {
	spec := os.Getenv("WBFT_SPEC_DIR")
	if spec == "" {
		t.Skip("WBFT_SPEC_DIR is not set")
	}
	dir := t.TempDir()
	bin := build(t, dir, "./cmd/wbft-inspector", "wbft-inspector")
	adapter := filepath.Join(dir, "wbft-vector-adapter")
	cmd := exec.Command("go", "build", "-o", adapter, "github.com/0xmhha/wbft/cmd/wbft-vector-adapter")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build the wbft adapter: %v\n%s", err, b)
	}
	self := build(t, dir, "./adapters/self", "self-adapter")
	out := filepath.Join(dir, "vectors.json")
	// The inspector's own model answers what the wbft adapter does not.
	run := exec.Command(bin, "vectors", "--impl", adapter, "--impl", self, "--vectors", filepath.Join(spec, "spec", "vectors"), "--out", out)
	msg, err := run.CombinedOutput()
	t.Logf("%s", msg)
	rep := readReport(t, schema(t), out)
	if err != nil || rep.Summary.ExitCode != 0 {
		t.Fatalf("vectors: exit %v, report exit %d", err, rep.Summary.ExitCode)
	}
}
