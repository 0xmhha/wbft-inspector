// Command wbft-inspector checks WBFT implementations against the public
// wbft-spec specification. It runs as a batch command and writes a JSON
// report (schema/report-v1.json).
//
// Usage:
//
//	wbft-inspector check   --events PATH [--events PATH ...] [--chain-config FILE] [flags]
//	wbft-inspector vectors --impl "CMD ARGS" [--impl ...] --vectors DIR [flags]
//	wbft-inspector catalog [list|coverage|extract] [flags]
//	wbft-inspector frames verify --frames DIR [--frames DIR ...]
//	wbft-inspector version
//
// Exit codes: 0 no failure, 1 failures (of the --fail-on severities, or a
// failed vector case), 2 coverage policy not met, 3 vector files not read,
// 64 usage error, 69 input unavailable, 70 internal error.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/buildinfo"
	_ "github.com/0xmhha/wbft-inspector/internal/check/all"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

const usage = `wbft-inspector checks WBFT implementations against the public wbft-spec.

Commands:
  check     decide requirements from consensus event streams (JSON Lines)
  vectors   run conformance vectors against implementation adapters (wbft-vector/1)
  catalog   list the checker catalog, check it against a specification, or extract requirements
  frames    validate frame dumps in the R-01 format
  version   print the version and build

Run "wbft-inspector <command> -h" for the flags of a command.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return report.ExitUsage
	}
	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "vectors":
		return runVectors(args[1:], stdout, stderr)
	case "catalog":
		return runCatalog(args[1:], stdout, stderr)
	case "frames":
		return runFrames(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "wbft-inspector %s (commit %s, %s, build %s)\n", buildinfo.Version, buildinfo.Commit(), buildinfo.Go(), buildinfo.Build())
		return report.ExitOK
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stdout, usage)
		return report.ExitOK
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return report.ExitUsage
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func newFlags(name string, stderr io.Writer) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	return fs
}

// writeReport writes the report to path, or to stdout when path is "" or "-".
func writeReport(path string, stdout io.Writer, r *report.Report) error {
	if path == "" || path == "-" {
		return report.Write(stdout, r)
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	if err := report.Write(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// splitList splits a comma-separated flag value.
func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

// readIDs reads requirement IDs from a file: one per line, # starts a
// comment.
func readIDs(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		if i := strings.IndexByte(l, '#'); i >= 0 {
			l = l[:i]
		}
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}
