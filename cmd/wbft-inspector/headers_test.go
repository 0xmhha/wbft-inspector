package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/report"
)

func TestHeadersCLI(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runCheck([]string{"--blocks", "../../internal/headers/testdata", "--chain-config", "../../internal/headers/testdata/config.json", "--from", "1", "--to", "3", "--header-node", "archive", "--checks", "P0"}, &stdout, &stderr)
	if code != 0 {
		t.Fatal(code, stderr.String())
	}
	var r report.Report
	if err := json.Unmarshal(stdout.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Run.Network == nil || r.Run.Network.ChainID != "8283" || r.Run.Range == nil || r.Run.Range.From != "1" || r.Run.Range.To != "3" || r.Summary.Requirements.Pass != 7 || r.Summary.Requirements.PartlyDecided != 1 {
		t.Fatal(r.Run, r.Summary)
	}
	if len(r.Observations) == 0 || len(r.Observations[0].Evidence) == 0 {
		t.Fatal("real header observations missing")
	}
	for _, o := range r.Observations {
		if o.Count < 1 || len(o.Evidence) > 20 || len(o.Imp) != 0 {
			t.Fatal(o)
		}
	}
}
func TestHeaderRPCCommandSanitized(t *testing.T) {
	for _, args := range [][]string{{"check", "--rpc", "https://dummy:dummy@example.invalid/private/path?dummy=secret"}, {"check", "--rpc=https://dummy:dummy@example.invalid/private/path?dummy=secret"}} {
		cmd := sanitizedCommand(args)
		text := strings.Join(cmd, " ")
		if strings.Contains(text, "dummy") || strings.Contains(text, "private") || strings.Contains(text, "secret") || !strings.Contains(text, "https://example.invalid") {
			t.Fatal(text)
		}
	}
}
