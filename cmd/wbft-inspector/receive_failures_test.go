package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestReceiveFailureSourceArgumentsDoNotExposePaths(t *testing.T) {
	for _, args := range [][]string{{"receive-failures"}, {"receive-failures", "--unknown=private-host"}, {"receive-failures", "--checker", "/private/checker", "--checker-sha256", strings.Repeat("0", 64), "--journal", "/private/source", "--source-limits", "/private/limits"}} {
		var out, diagnostics bytes.Buffer
		code := run(args, &out, &diagnostics)
		if code == 0 || out.Len() != 0 || strings.Contains(diagnostics.String(), "/private") || strings.Contains(diagnostics.String(), "private-host") {
			t.Fatal(code, out.String(), diagnostics.String())
		}
	}
}
