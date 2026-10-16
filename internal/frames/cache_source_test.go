package frames

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func cacheFixtureRows(t *testing.T) []map[string]any {
	t.Helper()
	raw, err := os.ReadFile("testdata/cache-source/frames-cache-fixture.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		d := json.NewDecoder(bytes.NewReader(line))
		d.UseNumber()
		var row map[string]any
		if err = d.Decode(&row); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, row)
	}
	return rows
}
func cacheTestRow(rows []map[string]any, typ string) map[string]any {
	for _, r := range rows {
		if r["type"] == typ {
			return r
		}
	}
	panic("test row missing: " + typ)
}
func loadCacheRows(t *testing.T, rows []map[string]any, mutateRaw func([]byte) []byte) *Dump {
	t.Helper()
	dir := t.TempDir()
	var raw bytes.Buffer
	for _, r := range rows {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		raw.Write(b)
		raw.WriteByte('\n')
	}
	data := raw.Bytes()
	if mutateRaw != nil {
		data = mutateRaw(data)
	}
	if err := os.WriteFile(filepath.Join(dir, "frames-cache-fixture.jsonl"), data, 0600); err != nil {
		t.Fatal(err)
	}
	source := "testdata/cache-source/payloads"
	err := filepath.WalkDir(source, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		dest := filepath.Join(dir, "payloads", rel)
		if e.IsDir() {
			return os.MkdirAll(dest, 0700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dest, b, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	d, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestLoadSyntheticCacheDecisionSource(t *testing.T) {
	d := loadCacheRows(t, cacheFixtureRows(t), nil)
	if v := Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	sources, problems := CacheSources(d)
	if len(problems) != 0 || len(sources) != 1 {
		t.Fatal(problems)
	}
	state := ReplayCache(sources[0])
	a, b := state[[2]string{"1", "1"}], state[[2]string{"1", "2"}]
	peer := "0xbb00000000000000000000000000000000000000"
	if !a.Known || !a.Consistent || a.Held[peer] || !b.Known || !b.Consistent || !b.Held[peer] {
		t.Fatal("independent cache replay disagrees with synthetic operations", state)
	}
}

func TestCacheSourceRejectsMalformedMetadataAndReferences(t *testing.T) {
	cases := map[string]func([]map[string]any) []map[string]any{
		"snapshot count": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_trace")["cache_trace"].(map[string]any)["operations"] = "3"
			return r
		},
		"payload source": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)["payload_sha256"] = strings.Repeat("0", 64)
			return r
		},
		"code source": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)["code"] = "0x15"
			return r
		},
		"unknown metadata": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)["invented"] = 1
			return r
		},
		"null metadata": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"] = nil
			return r
		},
		"missing boolean": func(r []map[string]any) []map[string]any {
			delete(cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any), "known_hit")
			return r
		},
		"missing complete": func(r []map[string]any) []map[string]any {
			delete(cacheTestRow(r, "cache_trace")["cache_trace"].(map[string]any), "complete")
			return r
		},
		"missing snapshot row":   func(r []map[string]any) []map[string]any { return slices.Delete(r, 4, 5) },
		"missing declaration":    func(r []map[string]any) []map[string]any { return r[1:] },
		"duplicate raw sequence": func(r []map[string]any) []map[string]any { cacheTestRow(r, "frame")["seq"] = 1; return r },
		"source position": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "frame")["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)["source_offset"] = "343"
			return r
		},
		"source sequence": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "frame")["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)["source_seq"] = "5"
			return r
		},
		"overflow": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_instance")["cache_instance"].(map[string]any)["instance"] = "18446744073709551616"
			return r
		},
		"noncanonical": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_instance")["cache_instance"].(map[string]any)["instance"] = "01"
			return r
		},
		"empty code": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)["code"] = ""
			return r
		},
		"capacity": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_instance")["cache_instance"].(map[string]any)["peer_capacity"] = "1"
			return r
		},
		"declaration clock": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_instance")["t_mono_ns"] = 1
			return r
		},
		"negative operation clock": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["t_mono_ns"] = -1
			return r
		},
		"overlapping decisions": func(r []map[string]any) []map[string]any {
			o := cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)
			o["suppressed"] = o["targets"]
			return r
		},
		"duplicate candidate": func(r []map[string]any) []map[string]any {
			o := cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)
			a := o["candidates"].([]any)
			o["candidates"] = append(a, a[0])
			return r
		},
		"foreign target": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "cache_operation")["cache_operation"].(map[string]any)["targets"] = []string{"0xcc00000000000000000000000000000000000000"}
			return r
		},
		"foreign node": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "frame")["node"] = "0xcc00000000000000000000000000000000000000"
			return r
		},
		"reused attempt": func(r []map[string]any) []map[string]any {
			b, _ := json.Marshal(cacheTestRow(r, "frame"))
			var f map[string]any
			_ = json.Unmarshal(b, &f)
			f["seq"] = 8
			f["journal_offset"] = 900
			return append(r, f)
		},
		"unavailable attempt with identity": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "frame")["send_attempt"].(map[string]any)["available"] = false
			return r
		},
		"unavailable reference with coordinates": func(r []map[string]any) []map[string]any {
			cacheTestRow(r, "frame")["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)["source_available"] = false
			return r
		},
		"metadata wrong type": func(r []map[string]any) []map[string]any {
			f := cacheTestRow(r, "frame")
			f["cache_decision"] = f["send_attempt"].(map[string]any)["cache_decision"]
			return r
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			d := loadCacheRows(t, change(cacheFixtureRows(t)), nil)
			if v := Validate(d); len(v.Problems) == 0 {
				t.Fatal("malformed cache source accepted")
			}
		})
	}
	t.Run("nested duplicate", func(t *testing.T) {
		d := loadCacheRows(t, cacheFixtureRows(t), func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"instance":"1"`), []byte(`"instance":"1","instance":"1"`), 1)
		})
		if len(Validate(d).Problems) == 0 {
			t.Fatal("duplicate nested field accepted")
		}
	})
}

func TestCacheSourceSharesSchedulerDeclaration(t *testing.T) {
	d, err := Load("testdata/cache-source-combined")
	if err != nil {
		t.Fatal(err)
	}
	if v := Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	sources, problems := CacheSources(d)
	if len(problems) != 0 || len(sources) != 1 {
		t.Fatal(problems)
	}
	if sources[0].Declaration.Type != "scheduler_trace" || sources[0].Declaration.SchedulerTrace == nil {
		t.Fatal("shared raw declaration split or lost")
	}
	states := ReplayCache(sources[0])
	if !states[[2]string{"1", "1"}].Known || !states[[2]string{"1", "2"}].Known {
		t.Fatal("combined capability did not replay")
	}
}
func TestCacheSourceKeepsExactLargeCounters(t *testing.T) {
	rows := cacheFixtureRows(t)
	large := "18446744073709551614"
	for _, row := range rows {
		switch row["type"] {
		case "cache_instance":
			row["cache_instance"].(map[string]any)["instance"] = large
		case "cache_operation":
			row["cache_operation"].(map[string]any)["instance"] = large
		case "send_suppressed":
			row["cache_decision"].(map[string]any)["instance"] = large
		case "frame":
			a := row["send_attempt"].(map[string]any)
			a["sequence"] = large
			a["cache_decision"].(map[string]any)["instance"] = large
		}
	}
	d := loadCacheRows(t, rows, nil)
	if v := Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	sources, _ := CacheSources(d)
	if sources[0].Instances[0].CacheInstance.Instance != large {
		t.Fatal("large cache instance rounded")
	}
	for _, r := range d.Records {
		if r.SendAttempt != nil && r.SendAttempt.Sequence != large {
			t.Fatal("large attempt counter rounded")
		}
	}
}

func TestCacheSourceDoesNotRoundLargeRawSequences(t *testing.T) {
	rows := cacheFixtureRows(t)
	const base uint64 = 9007199254740993
	for _, row := range rows {
		old, err := strconv.ParseUint(string(row["seq"].(json.Number)), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		row["seq"] = base + old
		var ref map[string]any
		switch row["type"] {
		case "frame":
			ref = row["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
		case "send_suppressed":
			ref = row["cache_decision"].(map[string]any)
		}
		if ref != nil {
			n, err := strconv.ParseUint(ref["source_seq"].(string), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			ref["source_seq"] = strconv.FormatUint(base+n, 10)
		}
	}
	d := loadCacheRows(t, rows, nil)
	if v := Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	for _, r := range d.Records {
		if r.Type == "frame" {
			if r.Seq != base+7 || r.SendAttempt.Decision.Seq != strconv.FormatUint(base+4, 10) {
				t.Fatal("raw source counter rounded", r)
			}
		}
	}
}
func TestCacheSourceRejectsAttemptReuseAcrossDifferentPeers(t *testing.T) {
	rows := cacheFixtureRows(t)
	for _, r := range rows {
		if r["type"] == "cache_operation" && r["seq"] == json.Number("5") {
			r["cache_operation"].(map[string]any)["cause"] = "retry"
		}
	}
	cacheTestRow(rows, "send_suppressed")["cause"] = "retry"
	f := cloneCacheFrameRow(cacheTestRow(rows, "frame"))
	f["seq"] = 8
	f["journal_offset"] = 999
	f["peer"] = "0xcc00000000000000000000000000000000000000"
	ref := f["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
	ref["operation"], ref["source_seq"], ref["source_offset"] = "2", "5", "532"
	d := loadCacheRows(t, append(rows, f), nil)
	_, problems := CacheSources(d)
	if !strings.Contains(strings.Join(problems, ";"), "send attempt identity changed call context") {
		t.Fatal("attempt identity reused with a different operation", problems)
	}
}
func cloneCacheFrameRow(r map[string]any) map[string]any {
	b, _ := json.Marshal(r)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out
}

func TestCacheReplayNeverClaimsIncompletePrefixKnown(t *testing.T) {
	rows := cacheFixtureRows(t)
	cacheTestRow(rows, "cache_trace")["cache_trace"].(map[string]any)["complete"] = false
	for _, r := range rows {
		var ref map[string]any
		switch r["type"] {
		case "frame":
			ref = r["send_attempt"].(map[string]any)["cache_decision"].(map[string]any)
		case "send_suppressed":
			ref = r["cache_decision"].(map[string]any)
		}
		if ref != nil {
			ref["source_available"] = false
			delete(ref, "source_seq")
			delete(ref, "source_segment")
			delete(ref, "source_offset")
		}
	}
	d := loadCacheRows(t, rows, nil)
	if v := Validate(d); len(v.Problems) != 0 {
		t.Fatal(v.Problems)
	}
	sources, _ := CacheSources(d)
	for _, state := range ReplayCache(sources[0]) {
		if state.Known {
			t.Fatal("incomplete prefix became known cache state")
		}
	}
}
