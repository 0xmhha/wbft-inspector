package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

const framesUsage = `wbft-inspector frames verify --frames DIR [--frames DIR ...]

Validates frame dumps in the R-01 format (frames-<run>.jsonl and payloads/)
and prints one JSON object per dump. Exit 1 when a dump has a problem.

`

// framesOutput is the result of one dump.
type framesOutput struct {
	Dir string `json:"dir"`
	*frames.Result
}

func runFrames(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "verify" {
		fmt.Fprint(stderr, framesUsage)
		return report.ExitUsage
	}
	fs := newFlags("frames verify", stderr)
	fs.Usage = func() { fmt.Fprint(stderr, framesUsage); fs.PrintDefaults() }
	var dirs multi
	fs.Var(&dirs, "frames", "frame dump directory (repeatable)")
	if fs.Parse(args[1:]) != nil || len(dirs) == 0 {
		fs.Usage()
		return report.ExitUsage
	}
	code := report.ExitOK
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	for _, dir := range dirs {
		d, err := frames.Load(dir)
		if err != nil {
			fmt.Fprintln(stderr, "wbft-inspector:", err)
			return report.ExitNoInput
		}
		res := frames.Validate(d)
		if len(res.Problems) > 0 {
			code = report.ExitFail
		}
		if err := enc.Encode(framesOutput{Dir: dir, Result: res}); err != nil {
			fmt.Fprintln(stderr, "wbft-inspector:", err)
			return report.ExitInternal
		}
	}
	return code
}
