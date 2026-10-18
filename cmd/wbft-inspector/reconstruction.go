package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/0xmhha/wbft-inspector/internal/reconstructreview"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

func runReconstruction(args []string, stdout, stderr io.Writer) int {
	fs := newFlags("reconstruction", stderr)
	packet := fs.String("packet", "", "one bounded wbft-reconstruction-review/1 file")
	expected := fs.String("sha256", "", "optional independently supplied packet checksum")
	if fs.Parse(args) != nil || fs.NArg() != 0 || *packet == "" {
		fs.Usage()
		return report.ExitUsage
	}
	f, err := os.Open(*packet)
	if err != nil {
		fmt.Fprintln(stderr, "reconstructed review packet unavailable")
		return report.ExitNoInput
	}
	defer f.Close()
	result, err := reconstructreview.Read(f, *expected)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return report.ExitFail
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if encoder.Encode(result) != nil {
		return report.ExitInternal
	}
	return report.ExitOK
}
