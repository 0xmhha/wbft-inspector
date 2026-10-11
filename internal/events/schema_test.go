package events

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// testdata/events-v1.json is the event schema of wbft
// (observe/event/schema/events-v1.json) at the commit in
// testdata/events-v1.ref. Update both together when wbft changes the file.

// schemaVocab is what the schema says: the fields of each kind and the
// values each field may take, over all kinds.
type schemaVocab struct {
	kinds  map[string]map[string]bool // kind -> field names, common fields included
	common map[string]bool
	values map[string]map[string]bool // field -> enum and const values (strings only)
}

func loadSchema(t *testing.T) schemaVocab {
	t.Helper()
	b, err := os.ReadFile("testdata/events-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	type prop struct {
		Ref   string `json:"$ref"`
		Enum  []any  `json:"enum"`
		Const any    `json:"const"`
	}
	type def struct {
		Properties map[string]prop `json:"properties"`
		AllOf      []prop          `json:"allOf"`
		Enum       []any           `json:"enum"`
	}
	var doc struct {
		Defs map[string]def `json:"$defs"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	v := schemaVocab{kinds: map[string]map[string]bool{}, common: map[string]bool{}, values: map[string]map[string]bool{}}
	for name := range doc.Defs["common"].Properties {
		v.common[name] = true
	}
	for _, d := range doc.Defs {
		k, ok := d.Properties["kind"].Const.(string)
		if !ok {
			continue
		}
		fields := maps.Clone(v.common)
		for name, p := range d.Properties {
			fields[name] = true
			enum := p.Enum
			if p.Ref != "" {
				enum = doc.Defs[strings.TrimPrefix(p.Ref, "#/$defs/")].Enum
			}
			if s, ok := p.Const.(string); ok && name != "kind" {
				enum = append(enum, s)
			}
			for _, e := range enum {
				if s, ok := e.(string); ok {
					if v.values[name] == nil {
						v.values[name] = map[string]bool{}
					}
					v.values[name][s] = true
				}
			}
		}
		v.kinds[k] = fields
	}
	return v
}

// TestSchemaKinds: the kinds this build knows are the kinds of the schema.
func TestSchemaKinds(t *testing.T) {
	v := loadSchema(t)
	got, want := slices.Sorted(maps.Keys(Known)), slices.Sorted(maps.Keys(v.kinds))
	if !slices.Equal(got, want) {
		t.Fatalf("Known %v\nschema %v", got, want)
	}
	if !maps.Equal(common, withSrc(v.common)) {
		t.Fatalf("common fields %v, schema %v", slices.Sorted(maps.Keys(common)), slices.Sorted(maps.Keys(v.common)))
	}
}

// withSrc adds "src", which the schema puts on application records only.
func withSrc(m map[string]bool) map[string]bool {
	m = maps.Clone(m)
	m["src"] = true
	return m
}

var (
	readField = regexp.MustCompile(`\.(?:Str|Int|Bool|Big|Has)\("([a-z_0-9]+)"\)`)
	compare   = regexp.MustCompile(`\.Str\("([a-z_0-9]+)"\)\s*(?:==|!=)\s*"([^"]*)"`)
)

// TestSchemaFields: every field name the checkers read from an event is a
// field of some kind of the schema, and every value they compare a field
// with is a value the schema allows for it. A field renamed in wbft (as
// EVIDENCE.kind became evidence_kind) or a value spelled differently then
// fails here instead of silently matching nothing.
func TestSchemaFields(t *testing.T) {
	v := loadSchema(t)
	known := map[string]bool{}
	for _, f := range v.kinds {
		maps.Copy(known, f)
	}
	var files []string
	for _, dir := range []string{".", "../check"} {
		err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() && strings.HasSuffix(p, ".go") && !strings.HasSuffix(p, "_test.go") {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	fields, values := 0, 0
	for _, p := range files {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range readField.FindAllStringSubmatch(string(b), -1) {
			fields++
			if !known[m[1]] {
				t.Errorf("%s reads field %q, which no kind of the schema has", p, m[1])
			}
		}
		for _, m := range compare.FindAllStringSubmatch(string(b), -1) {
			values++
			if allowed := v.values[m[1]]; allowed != nil && !allowed[m[2]] {
				t.Errorf("%s compares %s with %q, which the schema does not allow (%v)", p, m[1], m[2], slices.Sorted(maps.Keys(allowed)))
			}
		}
	}
	if fields == 0 || values == 0 {
		t.Fatalf("found %d field reads and %d comparisons; the patterns no longer match the code", fields, values)
	}
}
