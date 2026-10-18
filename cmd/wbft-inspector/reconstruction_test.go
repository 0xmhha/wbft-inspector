package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/reconstructreview"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

func TestReconstructionCommandSeparatesPacketValidationFromVerdict(t *testing.T) {
	raw, err := os.ReadFile("../../internal/reconstructreview/testdata/review.json")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "review.json")
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	var stdout, stderr bytes.Buffer
	code := run([]string{"reconstruction", "--packet", path, "--sha256", hex.EncodeToString(hash[:])}, &stdout, &stderr)
	var result reconstructreview.Result
	if code != report.ExitOK || json.Unmarshal(stdout.Bytes(), &result) != nil || result.SpecificationVerdict != "not_evaluated" || result.SourceTruthVerified || !result.ExpectedChecksumVerified {
		t.Fatal(code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code = run([]string{"reconstruction", "--packet", path, "--sha256", strings.Repeat("f", 64)}, &stdout, &stderr); code != report.ExitFail || stdout.Len() != 0 || strings.Contains(stderr.String(), path) {
		t.Fatal(code, stdout.String(), stderr.String())
	}
}
