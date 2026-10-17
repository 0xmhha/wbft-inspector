package frames

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadSyncFixture(t *testing.T, dir string) (*Dump, []SyncSource, []string) {
	t.Helper()
	d, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	sources, problems := SyncSources(d)
	return d, sources, problems
}

func TestSyncSourcesRetainPhysicalOrderAndExactRequestCoordinates(t *testing.T) {
	d, sources, problems := loadSyncFixture(t, "testdata/sync-combined")
	if len(problems) != 0 || len(sources) != 1 || !sources[0].Complete {
		t.Fatal(sources, problems)
	}
	if result := Validate(d); len(result.Problems) != 0 {
		t.Fatal("shared scheduler/cache/sync declaration rejected", result.Problems)
	}
	s := sources[0]
	if s.Declaration.SyncTrace.Requests != "2" || len(s.Requests) != 2 || len(s.Operations) != 3 || len(s.Records) != 6 {
		t.Fatal("source records or counts changed", s)
	}
	for i, original := range d.Records {
		if s.Records[i] != original {
			t.Fatal("physical source order changed")
		}
	}
	for i, line := range []int{3, 3, 5} {
		operation := s.Operations[i]
		request, ok := s.Request(operation)
		if !ok || request.Line != line || request.File != operation.File || request.Node != operation.Node || request.Run != operation.Run {
			t.Fatal("exact original request not retained", operation, request, ok)
		}
		if operation.SyncControl.RequestSource.Seq != operation.SyncControl.Request && operation.Seq == 2 {
			// Logical request IDs and physical journal sequences are different.
			if request.Seq != 3 || *request.JournalOffset != 219 {
				t.Fatal("request ID was used as its original source point")
			}
		}
	}
	if s.Operations[0].Seq != 2 || s.Requests[0].Seq != 3 || s.Operations[0].TMono <= s.Requests[0].TMono {
		t.Fatal("physical order or original clock regression rewritten")
	}
	foreign := *s.Operations[0]
	if _, ok := s.Request(&foreign); ok {
		t.Fatal("unretained operation accepted as a source member")
	}
	s.Operations[0].SyncControl.RequestSource.Offset = "220"
	if _, ok := s.Request(s.Operations[0]); ok {
		t.Fatal("mutated source coordinates accepted")
	}
}

func TestSyncSourcesKeepIncompleteWithoutInventingRequestLinks(t *testing.T) {
	d, sources, problems := loadSyncFixture(t, "testdata/sync-incomplete")
	if len(problems) != 0 || len(sources) != 1 || sources[0].Complete {
		t.Fatal(sources, problems)
	}
	if result := Validate(d); len(result.Problems) != 0 {
		t.Fatal(result.Problems)
	}
	s := sources[0]
	if len(s.Requests) != 0 || len(s.Operations) != 1 || s.Declaration.SyncTrace.Complete == nil || *s.Declaration.SyncTrace.Complete {
		t.Fatal("incomplete context changed", s)
	}
	if request, ok := s.Request(s.Operations[0]); ok || request != nil || *s.Operations[0].SyncControl.RequestSource.Available {
		t.Fatal("missing request inferred")
	}
	legacy, err := Load("testdata/scheduler-source")
	if err != nil {
		t.Fatal(err)
	}
	if got, problems := SyncSources(legacy); len(got) != 0 || len(problems) != 0 {
		t.Fatal("legacy snapshot gained sync context", got, problems)
	}
}

func mutatedSyncDump(t *testing.T, mutate func([]map[string]any)) string {
	t.Helper()
	b, err := os.ReadFile("testdata/sync-combined/frames-sync-control-combined.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r map[string]any
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, r)
	}
	mutate(rows)
	dir := t.TempDir()
	f, err := os.Create(filepath.Join(dir, "frames-sync-control-combined.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	encoder := json.NewEncoder(f)
	for _, r := range rows {
		if err := encoder.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSyncSourcesRejectForgedCompleteAndMalformedContext(t *testing.T) {
	control := func(rows []map[string]any, index int) map[string]any {
		return rows[index]["sync_control"].(map[string]any)
	}
	for name, mutate := range map[string]func([]map[string]any){
		"request-sequence": func(r []map[string]any) { control(r, 1)["request_source"].(map[string]any)["source_seq"] = "5" },
		"request-offset":   func(r []map[string]any) { control(r, 1)["request_source"].(map[string]any)["source_offset"] = "220" },
		"request-state":    func(r []map[string]any) { control(r, 2)["syncing"] = false },
		"request-duplicate": func(r []map[string]any) {
			control(r, 4)["request"] = "1"
		},
		"handling-duplicate": func(r []map[string]any) { control(r, 5)["operation"] = "1" },
		"snapshot-count":     func(r []map[string]any) { r[0]["sync_trace"].(map[string]any)["requests"] = "3" },
		"cursor-semantics":   func(r []map[string]any) { r[0]["sync_trace"].(map[string]any)["event_cursor"] = "inclusive" },
		"null-bool":          func(r []map[string]any) { control(r, 1)["success"] = nil },
		"missing-bool":       func(r []map[string]any) { delete(control(r, 1), "success") },
		"null-source":        func(r []map[string]any) { r[1]["journal_offset"] = nil },
		"missing-source":     func(r []map[string]any) { delete(r[1], "journal_segment") },
		"duplicate-sequence": func(r []map[string]any) { r[0]["seq"] = float64(2) },
		"duplicate-position": func(r []map[string]any) { r[1]["journal_offset"] = float64(219) },
		"mixed-file":         func(r []map[string]any) { r[1]["node"] = "0xbb00000000000000000000000000000000000000" },
		"unavailable-request": func(r []map[string]any) {
			control(r, 1)["request_source"] = map[string]any{"source_available": false}
		},
		"unknown-top-field": func(r []map[string]any) { r[1]["guessed"] = true },
		"unknown-metadata":  func(r []map[string]any) { control(r, 1)["guessed"] = true },
	} {
		t.Run(name, func(t *testing.T) {
			d, sources, problems := loadSyncFixture(t, mutatedSyncDump(t, mutate))
			if len(problems) == 0 || len(Validate(d).Problems) == 0 {
				t.Fatal("malformed or forged source accepted", sources)
			}
			for _, s := range sources {
				if s.Complete {
					t.Fatal("invalid context still claims complete", s)
				}
			}
		})
	}
}

func TestSyncSourcesRetainFailedControlWithEmptyMeasuredRange(t *testing.T) {
	dir := mutatedSyncDump(t, func(rows []map[string]any) {
		c := rows[5]["sync_control"].(map[string]any)
		c["event_after"] = c["event_before"]
		c["failed"], c["running_after"], c["first_after"] = true, false, false
	})
	d, sources, problems := loadSyncFixture(t, dir)
	if len(problems) != 0 || len(Validate(d).Problems) != 0 || len(sources) != 1 || !sources[0].Complete {
		t.Fatal("failed call with empty measured range was erased", sources, problems)
	}
	c := sources[0].Operations[2].SyncControl
	if !*c.Failed || !*c.EventsAvailable || c.EventBefore != c.EventAfter {
		t.Fatal("empty attempted-call evidence changed", c)
	}
}
