package vector

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as an adapter: with WBFT_TEST_ADAPTER set it
// speaks wbft-vector/1 on standard input and output, in the mode named by
// its last argument.
func TestMain(m *testing.M) {
	if os.Getenv("WBFT_TEST_ADAPTER") != "" {
		fakeAdapter(os.Args[len(os.Args)-1])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func fakeAdapter(mode string) {
	in := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)
	send := func(v any) { b, _ := json.Marshal(v); _, _ = w.Write(append(b, '\n')); _ = w.Flush() }
	for {
		line, err := in.ReadBytes('\n')
		if err != nil {
			return
		}
		var msg struct {
			Type    string          `json:"type"`
			ID      int             `json:"id"`
			Runner  json.RawMessage `json:"runner"`
			Handler string          `json:"handler"`
			Input   map[string]any  `json:"input"`
		}
		_ = json.Unmarshal(line, &msg)
		switch msg.Type {
		case "hello":
			proto := "wbft-vector/1"
			if mode == "otherproto" {
				proto = "wbft-vector/2"
			}
			handlers := []string{"test/echo", "test/hang", "test/crash"}
			if mode == "none" {
				handlers = []string{"test/echo"}
			}
			send(map[string]any{"type": "hello", "protocol": proto, "impl": map[string]string{"name": "fake-" + mode, "version": "0", "commit": "0", "lang": "go", "build": "nocgo"},
				"handlers": handlers, "improvements": []string{}})
		case "case":
			switch {
			case mode == "none":
				send(map[string]any{"type": "result", "id": msg.ID, "status": "unsupported"})
			case msg.Handler == "hang":
				time.Sleep(time.Hour)
			case msg.Handler == "crash":
				os.Exit(3)
			case msg.Input["fail"] != nil:
				send(map[string]any{"type": "result", "id": msg.ID, "status": "error", "error_class": "test"})
			case msg.Input["number"] != nil:
				send(map[string]any{"type": "result", "id": msg.ID, "status": "ok", "output": map[string]any{"value": 1}})
			default:
				send(map[string]any{"type": "result", "id": msg.ID, "status": "ok", "output": map[string]any{"value": msg.Input["value"]}})
			}
		case "bye":
			return
		}
	}
}

func writeCase(t *testing.T, dir, path, input, expected string, reqs ...string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(path))
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(path, "/")
	var meta strings.Builder
	meta.WriteString("runner: \"" + parts[0] + "\"\nhandler: \"" + parts[1] + "\"\ncase: \"" + parts[2] + "\"\nkind: \"pure\"\ndescription: \"test\"\nrequirements:\n")
	for _, r := range reqs {
		meta.WriteString("  - \"" + r + "\"\n")
	}
	meta.WriteString("reference:\n  implementation: \"x\"\n  commit: \"0000000000000000000000000000000000000000\"\n  toolchain: \"go\"\n  build: \"cgo\"\ngenerator:\n  name: \"t\"\n  version: \"0\"\n")
	must(t, os.WriteFile(filepath.Join(p, "meta.yaml"), []byte(meta.String()), 0o644))
	must(t, os.WriteFile(filepath.Join(p, "input.yaml"), []byte(input), 0o644))
	if expected != "" {
		must(t, os.WriteFile(filepath.Join(p, "expected.yaml"), []byte(expected), 0o644))
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func adapterCmd(mode string) []string { return []string{os.Args[0], "-test.run=^$", mode} }

func vectors(t *testing.T) string {
	dir := t.TempDir()
	const req = "WBFT-TIMER-005"
	writeCase(t, dir, "test/echo/ok", "value: \"1\"\n", "value: \"1\"\n", req)
	writeCase(t, dir, "test/echo/mismatch", "value: \"2\"\n", "value: \"1\"\n", req)
	writeCase(t, dir, "test/echo/number", "number: \"1\"\n", "value: \"1\"\n", req)
	writeCase(t, dir, "test/echo/must_fail", "fail: \"yes\"\n", "", req)
	writeCase(t, dir, "test/echo/must_fail_but_ok", "value: \"1\"\n", "", req)
	writeCase(t, dir, "test/echo/bad_yaml", "value: 1\n", "value: \"1\"\n", req)
	writeCase(t, dir, "test/hang/expected", "value: \"1\"\n", "value: \"1\"\n", req)
	writeCase(t, dir, "test/hang/no_expected", "value: \"1\"\n", "", req)
	writeCase(t, dir, "test/crash/expected", "value: \"1\"\n", "value: \"1\"\n", "WBFT-XYZ-999")
	writeCase(t, dir, "test/unlisted/case", "value: \"1\"\n", "value: \"1\"\n", req)
	must(t, os.WriteFile(filepath.Join(dir, "test", "echo", "stray.txt"), []byte("x"), 0o644))
	return dir
}

func TestRunDecidesCases(t *testing.T) {
	t.Setenv("WBFT_TEST_ADAPTER", "1")
	dir := vectors(t)
	out, err := Run(context.Background(), Options{Dir: dir, Impls: [][]string{adapterCmd("normal")},
		CaseTimeout: 2 * time.Second, StepsTimeout: 2 * time.Second, SpecCommit: "test", RunnerName: "test", RunnerVer: "0"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][2]string{ // result, passed
		"test/echo/ok":               {ResultPass, "true"},
		"test/echo/mismatch":         {ResultFail, "false"},
		"test/echo/number":           {ResultFail, "false"}, // a JSON number is not a decimal string
		"test/echo/must_fail":        {ResultPass, "true"},
		"test/echo/must_fail_but_ok": {ResultFail, "false"},
		"test/echo/bad_yaml":         {ResultFail, "false"},
		"test/hang/expected":         {ResultTimeout, "false"},
		"test/hang/no_expected":      {ResultTimeout, "true"},
		"test/crash/expected":        {ResultError, "false"},
		"test/unlisted/case":         {ResultUnsupported, "false"},
	}
	for _, c := range out.Cases {
		w, ok := want[c.Path]
		if !ok {
			t.Errorf("unexpected case %s", c.Path)
			continue
		}
		passed := "false"
		if c.Passed {
			passed = "true"
		}
		if c.Result != w[0] || passed != w[1] {
			t.Errorf("%s: %s passed=%v (%s %s), want %s passed=%s", c.Path, c.Result, c.Passed, c.Detail, c.Diff, w[0], w[1])
		}
	}
	if len(out.Cases) != len(want) {
		t.Errorf("%d cases, want %d", len(out.Cases), len(want))
	}
	if len(out.Unaccessed) != 1 || out.Unaccessed[0] != "test/echo/stray.txt" {
		t.Errorf("unaccessed files %v, want the stray file", out.Unaccessed)
	}
	if out.Totals.TimeoutPassed != 1 || out.Totals.Timeout != 2 || out.Totals.Error != 1 || out.Totals.Unsupported != 1 {
		t.Errorf("totals %+v", out.Totals)
	}
	// Restarted before the next case after the crash and after the first
	// timeout; the last timeout is followed by no case of that adapter.
	if out.AdapterRestarts != 2 {
		t.Errorf("adapter restarted %d times, want 2", out.AdapterRestarts)
	}
	if !out.Failed() {
		t.Error("Failed() = false")
	}
	if n := len(out.Instances["WBFT-XYZ-999"]); n != 1 {
		t.Errorf("instances of the unknown ID: %d", n)
	}
}

func TestUnsupportedGoesToTheNextAdapter(t *testing.T) {
	t.Setenv("WBFT_TEST_ADAPTER", "1")
	dir := t.TempDir()
	writeCase(t, dir, "test/echo/ok", "value: \"1\"\n", "value: \"1\"\n", "WBFT-TIMER-005")
	out, err := Run(context.Background(), Options{Dir: dir, Impls: [][]string{adapterCmd("none"), adapterCmd("normal")},
		CaseTimeout: 2 * time.Second, SpecCommit: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if c := out.Cases[0]; c.Result != ResultPass || c.Impl != "impl-2" {
		t.Fatalf("got %+v, want PASS by impl-2", c)
	}
}

func TestOtherProtocolIsAUsageError(t *testing.T) {
	t.Setenv("WBFT_TEST_ADAPTER", "1")
	dir := t.TempDir()
	writeCase(t, dir, "test/echo/ok", "value: \"1\"\n", "value: \"1\"\n", "WBFT-TIMER-005")
	_, err := Run(context.Background(), Options{Dir: dir, Impls: [][]string{adapterCmd("otherproto")}, CaseTimeout: time.Second})
	if !errors.Is(err, ErrProtocolName) {
		t.Fatalf("got %v, want ErrProtocolName", err)
	}
}

func TestSelection(t *testing.T) {
	dir := vectors(t)
	cases, unaccessed, err := Load(dir, Selection{Runner: "test", Handler: "hang"})
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 2 || len(unaccessed) != 0 {
		t.Fatalf("%d cases, unaccessed %v", len(cases), unaccessed)
	}
}

func TestCompare(t *testing.T) {
	want := map[string]any{"a": "1", "b": []any{"x", nil}, "c": map[string]any{"d": true}}
	same := map[string]any{"a": "1", "b": []any{"x", nil}, "c": map[string]any{"d": true}}
	if d := compare("o", want, same); d != "" {
		t.Fatal(d)
	}
	for _, got := range []map[string]any{
		{"a": "1", "b": []any{"x", nil}, "c": map[string]any{"d": true}, "e": "extra"},
		{"a": "1", "b": []any{"x"}, "c": map[string]any{"d": true}},
		{"a": "2", "b": []any{"x", nil}, "c": map[string]any{"d": true}},
		{"a": "1", "b": []any{"x", nil}, "c": map[string]any{"d": false}},
	} {
		if compare("o", want, got) == "" {
			t.Errorf("%v compared equal", got)
		}
	}
}
