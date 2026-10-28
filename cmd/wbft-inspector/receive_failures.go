package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/failuresource"
	"github.com/0xmhha/wbft-inspector/internal/report"
)

func runReceiveFailures(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("receive-failures", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	binary := fs.String("checker", "", "absolute path to the WBFT journal checker")
	digest := fs.String("checker-sha256", "", "expected SHA256 of the selected checker")
	directory := fs.String("journal", "", "closed original journal directory")
	limits := fs.String("source-limits", "", "explicit inspection limits JSON file")
	timeout := fs.Duration("timeout", 2*time.Minute, "checker time limit, at most 10m")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stdout, "Usage: wbft-inspector receive-failures --checker ABSOLUTE_BINARY --checker-sha256 SHA256 --journal DIR --source-limits FILE [--timeout 2m]")
			return report.ExitOK
		}
		fmt.Fprintln(stderr, "invalid receive failure source arguments")
		return report.ExitUsage
	}
	if fs.NArg() != 0 || *binary == "" || *digest == "" || *directory == "" || *limits == "" || *timeout <= 0 || *timeout > 10*time.Minute {
		fmt.Fprintln(stderr, "receive failures require explicit checker identity, original journal and limits")
		return report.ExitUsage
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	result, err := failuresource.Check(ctx, *binary, *digest, *directory, *limits, *timeout)
	if err != nil {
		fmt.Fprintln(stderr, "original source checker unavailable or invalid")
		return report.ExitNoInput
	}
	if err = json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "cannot write receive failure source result")
		return report.ExitInternal
	}
	switch result.Status {
	case "consistent":
		return report.ExitOK
	case "inconsistent":
		return 1
	default:
		return report.ExitNoInput
	}
}
