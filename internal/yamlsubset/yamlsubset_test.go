package yamlsubset

import (
	"reflect"
	"testing"
)

// The negative and positive samples of the specification's reference
// checker (check_yaml_subset.py --self-test).
func TestRejectsConstructsOutsideTheSubset(t *testing.T) {
	bad := map[string]string{
		"comment":            "a: \"1\"  # c\n",
		"plain scalar":       "a: 1\n",
		"single quotes":      "a: '1'\n",
		"flow list":          "a: [\"1\"]\n",
		"anchor":             "a: &x \"1\"\n",
		"duplicate key":      "a: \"1\"\na: \"2\"\n",
		"tab":                "a:\n\t- \"1\"\n",
		"no final newline":   "a: \"1\"",
		"blank line":         "a: \"1\"\n\nb: \"2\"\n",
		"empty block":        "a:\nb: null\n",
		"odd indent":         "a:\n   b: \"1\"\n",
		"document separator": "---\na: \"1\"\n",
		"top-level list":     "- \"1\"\n",
		"uppercase key":      "A: \"1\"\n",
		"trailing space":     "a: \"1\" \n",
		"crlf":               "a: \"1\"\r\n",
		"number in list":     "a:\n  - 1\n",
		"key in sequence":    "a:\n  - \"1\"\n  b: \"2\"\n",
	}
	for name, text := range bad {
		if _, err := Parse([]byte(text)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParsesTheSubset(t *testing.T) {
	good := "a: \"0x00\"\nb:\n  - \"1\"\n  - k: null\n    l: []\n  -\n    - true\nc:\n  d: {}\n"
	got, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": "0x00", "b": []any{"1", map[string]any{"k": nil, "l": []any{}}, []any{true}}, "c": map[string]any{"d": map[string]any{}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v", got)
	}
}

func TestEscapesAreJSON(t *testing.T) {
	got, err := Parse([]byte("a: \"x\\u0041\\n\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got["a"] != "xA\n" {
		t.Fatalf("got %q", got["a"])
	}
}

func TestCheckValues(t *testing.T) {
	probs := CheckValues(map[string]any{"x": "0xABCD", "y": "0xabc", "z": []any{"0x00", "0x"}}, "t")
	if len(probs) != 2 {
		t.Fatalf("got %v", probs)
	}
}
