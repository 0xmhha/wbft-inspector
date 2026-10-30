package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/report"
)

func TestDomainFrameDeclarationIsUnavailable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "frames-model.jsonl"), []byte("{\"signing_profile\":null}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output, diagnostics bytes.Buffer
	code := run([]string{"frames", "verify", "--frames", dir}, &output, &diagnostics)
	if code != report.ExitNoInput || output.Len() != 0 || !strings.Contains(diagnostics.String(), "unsupported chain signing domain") {
		t.Fatal("unbound domain was treated as a legacy frame verdict", code, output.String(), diagnostics.String())
	}
}
