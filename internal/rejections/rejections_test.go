package rejections

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	recA = `{"number":"7","hash":"0x6284D1A2D0A027E77A8249B3AB24207EF68A2F5B98236CC4B044B6AAF5A10A1E","step":"P3","errorClass":"ErrInvalidProposal","path":"preprepare","time":"2026-10-11T01:00:01.5Z"}`
	recB = `{"number":"8","hash":"0x1111111111111111111111111111111111111111111111111111111111111111","step":"","errorClass":"","path":"imported","time":"2026-10-11T01:00:02Z"}`
)

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestLoad reads the same two records from the node's store directory
// (previous file first), a JSON Lines file, a wbft_rejections result and
// a JSON-RPC response, and keeps malformed records out as problems.
func TestLoad(t *testing.T) {
	dir := t.TempDir()
	store := filepath.Join(dir, "rejections")
	if err := os.Mkdir(store, 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(store, "rejections.prev.jsonl"), recA+"\n")
	write(t, filepath.Join(store, "rejections.jsonl"), recB+"\n")
	write(t, filepath.Join(dir, "lines.jsonl"), recA+"\n"+recB+"\n")
	write(t, filepath.Join(dir, "result.json"), "["+recA+",\n"+recB+"]")
	write(t, filepath.Join(dir, "response.json"), `{"jsonrpc":"2.0","id":1,"result":[`+recA+","+recB+`]}`)
	for _, p := range []string{store, "lines.jsonl", "result.json", "response.json"} {
		if !filepath.IsAbs(p) {
			p = filepath.Join(dir, p)
		}
		s, err := Load("0xABC", p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if len(s.Records) != 2 || len(s.Problems) != 0 || s.Node != "0xabc" || s.SHA256 == "" {
			t.Fatalf("%s: %+v", p, s)
		}
		a, b := s.Records[0], s.Records[1]
		if a.Number != "7" || a.Path != "preprepare" || a.Hash != strings.ToLower(a.Hash) || a.At.Nanosecond() != 500000000 || a.Line != 1 ||
			b.Number != "8" || b.Step != "" || b.Line != 2 || b.Node != "0xabc" {
			t.Fatalf("%s: records %+v %+v", p, a, b)
		}
	}

	bad := []string{
		`{"number":"-1","hash":"0x11","path":"preprepare","time":"2026-10-11T01:00:00Z"}`,
		strings.Replace(recA, `"number":"7"`, `"number":"0x7"`, 1),
		strings.Replace(recA, `0x6284`, `0x62`, 1),
		strings.Replace(recA, `"path":"preprepare"`, `"path":"gossip"`, 1),
		strings.Replace(recA, `"time":"2026-10-11T01:00:01.5Z"`, `"time":"yesterday"`, 1),
		`"a string"`,
	}
	write(t, filepath.Join(dir, "bad.jsonl"), strings.Join(append(bad, recB), "\n"))
	s, err := Load("0xabc", filepath.Join(dir, "bad.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Records) != 1 || len(s.Problems) != len(bad) || s.Records[0].Line != len(bad)+1 {
		t.Fatalf("records %+v problems %q", s.Records, s.Problems)
	}

	write(t, filepath.Join(dir, "error.json"), `{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no such method"}}`)
	if _, err := Load("0xabc", filepath.Join(dir, "error.json")); err == nil {
		t.Fatal("an error response loaded")
	}
	if s, err := Load("0xabc", t.TempDir()); err != nil || len(s.Records) != 0 {
		t.Fatalf("a store without files: %+v %v", s, err)
	}
}
