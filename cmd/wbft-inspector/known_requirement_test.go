package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/catalog"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

func TestKnownRequirementWithoutCheckerIsNotUnknown(t *testing.T) {
	const known = "SNET-SYNC-030"
	if _, ok := catalog.Lookup(known); !ok {
		t.Fatal("fixture must be in the embedded public requirement list")
	}
	if _, ok := catalog.RowOf(known); ok {
		t.Fatal("fixture must not have a checker row")
	}
	for _, required := range []bool{false, true} {
		name := "selected"
		if required {
			name = "required"
		}
		t.Run(name, func(t *testing.T) {
			args := []string{"check", "--events", testdata("events"), "--chain-config", testdata("chain-config.json"), "--checks", "WBFT-SM-999"}
			wantExit := report.ExitOK
			if required {
				path := filepath.Join(t.TempDir(), "required.txt")
				if err := os.WriteFile(path, []byte(known+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--require-decided", path)
				wantExit = report.ExitCoverage
			} else {
				args = append(args, "--checks", known+",WBFT-SM-999")
			}
			code, r, stderr := runCLI(t, args...)
			if code != wantExit || r == nil {
				t.Fatalf("exit %d, want %d: %s", code, wantExit, stderr)
			}
			foundKnown, foundUnknown := false, false
			for _, result := range r.Results {
				switch result.Requirement {
				case known:
					foundKnown = true
					if result.Verdict != "NOT_RUN" || result.Reason == nil || result.Reason.Code == "NOT_IN_BUILD" || result.Coverage.Instances != 0 {
						t.Fatalf("known requirement without checker: %+v", result)
					}
				case "WBFT-SM-999":
					foundUnknown = true
					if result.Verdict != "CANNOT_DECIDE" || result.Reason == nil || result.Reason.Code != "NOT_IN_BUILD" {
						t.Fatalf("unknown requirement changed: %+v", result)
					}
				}
			}
			if !foundKnown || !foundUnknown {
				t.Fatalf("missing selected results: %+v", r.Results)
			}
		})
	}
}
