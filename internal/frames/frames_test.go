package frames

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixture = "../../testdata/frames/wbft-kvstore"

// TestFixture validates a dump the wbft node wrote: every rule holds,
// including the payload hashes and the dedup keys of every frame.
func TestFixture(t *testing.T) {
	d, err := Load(fixture)
	if err != nil {
		t.Fatal(err)
	}
	res := Validate(d)
	if len(res.Problems) != 0 {
		t.Fatalf("problems %q", res.Problems)
	}
	if res.Files != 1 || res.Records["frame"] == 0 || res.Records["outcome"] == 0 || res.Records["conn"] == 0 || res.Payloads == 0 {
		t.Fatalf("result %+v", res)
	}
}

// copyFixture copies the fixture into a temporary directory.
func copyFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(fixture, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(fixture, path)
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// editLines rewrites the frame file: f gets each record as a map and its
// line index and returns the record to write, or nil to drop the line.
func editLines(t *testing.T, dir string, f func(i int, r map[string]any) map[string]any) {
	t.Helper()
	names, _ := filepath.Glob(filepath.Join(dir, "frames-*.jsonl"))
	b, err := os.ReadFile(names[0])
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for i, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		if r = f(i, r); r == nil {
			continue
		}
		nb, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(nb))
	}
	if err := os.WriteFile(names[0], []byte(strings.Join(out, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// first returns a matcher that changes only the first record matching ok.
func first(ok func(r map[string]any) bool, change func(r map[string]any)) func(int, map[string]any) map[string]any {
	done := false
	return func(_ int, r map[string]any) map[string]any {
		if !done && ok(r) {
			done = true
			change(r)
		}
		return r
	}
}

func isType(typ string) func(map[string]any) bool {
	return func(r map[string]any) bool { return r["type"] == typ }
}

func isFrame(dir string) func(map[string]any) bool {
	return func(r map[string]any) bool { return r["type"] == "frame" && r["dir"] == dir }
}

// TestValidateFinds changes the fixture in one way at a time and expects
// the matching problem.
func TestValidateFinds(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, dir string)
		want string
	}{
		{"wrong dedup key", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("in"), func(r map[string]any) { r["dedup_key"] = "0x" + strings.Repeat("ab", 32) }))
		}, "the payload's is"},
		{"wrong size", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("out"), func(r map[string]any) { r["size"] = 1 }))
		}, "size 1, payload has"},
		{"changed payload file", func(t *testing.T, dir string) {
			var sum string
			editLines(t, dir, first(isFrame("in"), func(r map[string]any) { sum = r["payload_sha256"].(string) }))
			p := filepath.Join(dir, "payloads", sum[:2], sum)
			b, _ := os.ReadFile(p)
			b[0] ^= 1
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatal(err)
			}
		}, "has sha256"},
		{"missing payload file", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("in"), func(r map[string]any) { r["payload_sha256"] = strings.Repeat("0", 64) }))
		}, "payload file:"},
		{"outcome of a sent frame", func(t *testing.T, dir string) {
			var seq any
			editLines(t, dir, first(isFrame("out"), func(r map[string]any) { seq = r["seq"] }))
			editLines(t, dir, first(func(r map[string]any) bool { return r["type"] == "outcome" && r["of"] != nil },
				func(r map[string]any) { r["of"] = seq }))
		}, "is not a received frame of the run"},
		{"duplicate seq", func(t *testing.T, dir string) {
			var seq any
			editLines(t, dir, first(isType("conn"), func(r map[string]any) { seq = r["seq"] }))
			editLines(t, dir, first(isType("outcome"), func(r map[string]any) { r["seq"] = seq }))
		}, "also at"},
		{"unknown outcome", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("in"), func(r map[string]any) { r["outcome"] = "ACCEPTED" }))
		}, `outcome "ACCEPTED"`},
		{"sent frame with an outcome", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("out"), func(r map[string]any) { r["outcome"] = "PENDING" }))
		}, "sent frame with an outcome"},
		{"relay without relay_of", func(t *testing.T, dir string) {
			editLines(t, dir, first(isFrame("out"), func(r map[string]any) { r["cause"] = "relay" }))
		}, `cause "relay" with relay_of`},
		{"missing common field", func(t *testing.T, dir string) {
			editLines(t, dir, first(isType("conn"), func(r map[string]any) { delete(r, "t_mono_ns") }))
		}, "without t_mono_ns"},
		{"other node in the file", func(t *testing.T, dir string) {
			editLines(t, dir, first(isType("outcome"), func(r map[string]any) { r["node"] = "0x" + strings.Repeat("11", 20) }))
		}, "in a file of node"},
		{"bad time", func(t *testing.T, dir string) {
			editLines(t, dir, first(isType("conn"), func(r map[string]any) { r["t_wall"] = "yesterday" }))
		}, "is not RFC 3339"},
		{"unknown type", func(t *testing.T, dir string) {
			editLines(t, dir, first(isType("conn"), func(r map[string]any) { r["type"] = "note" }))
		}, `unknown type "note"`},
		{"malformed line", func(t *testing.T, dir string) {
			names, _ := filepath.Glob(filepath.Join(dir, "frames-*.jsonl"))
			f, err := os.OpenFile(names[0], os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString("{not json\n")
			_ = f.Close()
		}, "invalid character"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := copyFixture(t)
			tc.edit(t, dir)
			d, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			res := Validate(d)
			if len(res.Problems) == 0 || !strings.Contains(strings.Join(res.Problems, "\n"), tc.want) {
				t.Fatalf("problems %q, want one with %q", res.Problems, tc.want)
			}
		})
	}
}

// TestLoadEmpty refuses a directory without frame files.
func TestLoadEmpty(t *testing.T) {
	if _, err := Load(t.TempDir()); err == nil {
		t.Fatal("no error")
	}
}
