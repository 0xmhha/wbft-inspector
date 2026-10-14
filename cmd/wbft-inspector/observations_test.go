package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestObservationCLIRefusesUnavailableAndMalformedInput(t *testing.T) {
	var out, err bytes.Buffer
	if runObservations(nil, &out, &err) != 64 {
		t.Fatal("usage accepted")
	}
	if runObservations([]string{"verify", filepath.Join(t.TempDir(), "missing")}, &out, &err) != 69 {
		t.Fatal("missing file accepted")
	}
	file := filepath.Join(t.TempDir(), "input.jsonl")
	if e := os.WriteFile(file, []byte("private-invalid-data\n"), 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	err.Reset()
	if runObservations([]string{"verify", file}, &out, &err) != 1 || bytes.Contains(err.Bytes(), []byte("private-invalid-data")) {
		t.Fatal(out.String(), err.String())
	}
	raw := `{"v":1,"node":"0x1111111111111111111111111111111111111111","run":"synthetic","seq":0,"t_wall":"2026-01-01T00:00:00Z","t_mono_ns":0,"type":"capture_end","dropped":0}`
	if e := os.WriteFile(file, []byte(raw), 0600); e != nil {
		t.Fatal(e)
	}
	out.Reset()
	err.Reset()
	if runObservations([]string{"verify", file}, &out, &err) != 2 || !bytes.Contains(out.Bytes(), []byte(`"capture_complete": false`)) {
		t.Fatal(out.String(), err.String())
	}
}
