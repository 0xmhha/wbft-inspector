package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/report"
)

func TestSyncObservationSourceDoesNotInventPolicyVerdict(t *testing.T) {
	path := filepath.Join("..", "..", "internal", "syncobs", "testdata", "complete.jsonl")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	code, r, stderr := runCLI(t, "check", "--sync-observations", path, "--checks", "SNET-SYNC-030")
	if code != report.ExitOK || len(r.Errors) != 0 || len(r.Run.Inputs) != 1 || len(r.Observations) != 1 {
		t.Fatal(code, r, stderr)
	}
	input := r.Run.Inputs[0]
	if input.Kind != "log" || input.Profile != "" || input.SHA256 != hex.EncodeToString(digest[:]) || input.Records != 8 {
		t.Fatal(input)
	}
	o := r.Observations[0]
	if o.Kind != "sync_notification_source" || o.Count != 6 || len(o.Evidence) != 2 || o.Evidence[0].Input != input.ID || o.Evidence[0].Line != 1 || o.Evidence[1].Line != 8 || !strings.Contains(o.Note, "source complete: true") || !strings.Contains(o.Note, "not a consensus-policy verdict") {
		t.Fatal(o)
	}
	if len(r.Results) != 1 || r.Results[0].Verdict == "PASS" || r.Results[0].Verdict == "FAIL" {
		t.Fatal("source coverage became a policy verdict", r.Results)
	}
	incomplete := filepath.Join(t.TempDir(), "incomplete.jsonl")
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if err := os.WriteFile(incomplete, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, r, stderr = runCLI(t, "check", "--sync-observations", incomplete, "--checks", "SNET-SYNC-030")
	if code != report.ExitOK || len(r.Errors) != 0 || len(r.Observations) != 1 || !strings.Contains(r.Observations[0].Note, "source complete: false") || len(r.Observations[0].Evidence) != 1 {
		t.Fatal(code, r, stderr)
	}
	code, r, stderr = runCLI(t, "check", "--sync-observations", path, "--sync-observations", incomplete, "--checks", "SNET-SYNC-030")
	if code != report.ExitOK || len(r.Run.Inputs) != 2 || len(r.Observations) != 2 || r.Observations[0].ID == r.Observations[1].ID || r.Run.Inputs[0].ID == r.Run.Inputs[1].ID {
		t.Fatal(code, r, stderr)
	}
}

func TestSyncObservationSourceFormatErrorsRemainInputErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.jsonl")
	if err := os.WriteFile(path, []byte("{\"type\":\"header\",\"validator\":false}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{path, filepath.Join(t.TempDir(), "missing.jsonl")} {
		code, r, stderr := runCLI(t, "check", "--sync-observations", p, "--checks", "SNET-SYNC-030")
		if code != report.ExitNoInput || len(r.Errors) == 0 || len(r.Observations) != 0 || len(r.Run.Inputs) != 0 {
			t.Fatal(code, r, stderr)
		}
	}
}
