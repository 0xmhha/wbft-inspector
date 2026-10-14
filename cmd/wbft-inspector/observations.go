package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft-inspector/internal/observations"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

func runObservations(args []string, stdout, stderr io.Writer) int {
	if len(args) != 2 || args[0] != "verify" {
		fmt.Fprintln(stderr, "wbft-inspector observations verify FILE")
		return report.ExitUsage
	}
	f, e := os.Open(args[1])
	if e != nil {
		fmt.Fprintln(stderr, "wbft-inspector: observation input unavailable")
		return report.ExitNoInput
	}
	defer f.Close()
	result, e := observations.Read(f)
	if e != nil {
		fmt.Fprintln(stderr, "wbft-inspector:", e)
		return report.ExitFail
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if enc.Encode(result) != nil {
		return report.ExitInternal
	}
	if !result.CaptureComplete {
		return report.ExitCoverage
	}
	return report.ExitOK
}
