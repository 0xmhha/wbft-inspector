// Package vector runs the conformance vectors of wbft-spec against
// implementations through the adapter protocol wbft-vector/1 (A-11 §3.4,
// WBFT-VEC-033 .. WBFT-VEC-054).
//
// The runner reads vectors/<runner>/<handler>/<case>/{meta,input,expected}.yaml,
// rejects files outside the YAML subset (WBFT-VEC-013), records which files
// it opened (WBFT-VEC-012), sends every case to the adapters that list its
// handler, and decides each case: with expected.yaml the result must be "ok"
// with an output equal to it, key by key (WBFT-VEC-047); without it the
// operation must fail (WBFT-VEC-048, WBFT-VEC-010).
package vector

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/yamlsubset"
)

// Case is one vector case.
type Case struct {
	Path         string // <runner>/<handler>/<case>
	Runner       string
	Handler      string
	Name         string
	Kind         string
	Requirements []string
	Input        map[string]any
	Expected     map[string]any // nil when the operation must fail
	// Problem is set when the case is not a valid vector; it is then not
	// sent to any adapter and reported as failed.
	Problem string
}

// HasExpected reports whether the case has an expected.yaml.
func (c *Case) HasExpected() bool { return c.Expected != nil }

var (
	nameRe  = regexp.MustCompile(`^[a-z0-9_]+$`)
	reqIDRe = regexp.MustCompile(`^(WBFT|SNET)-[A-Z]+-[0-9]{3}$`)
	kinds   = map[string]bool{"pure": true, "chain": true, "steps": true}
	metaTop = []string{"runner", "handler", "case", "kind", "description", "requirements", "reference", "generator"}
)

// Selection limits a run to one runner and optionally one handler.
type Selection struct {
	Runner  string
	Handler string
}

func (s Selection) has(runner, handler string) bool {
	return (s.Runner == "" || s.Runner == runner) && (s.Handler == "" || s.Handler == handler)
}

// Load reads the selected cases of a vector directory. It returns the
// cases sorted by path and the files under the selection that no case
// read (WBFT-VEC-012), relative to dir.
func Load(dir string, sel Selection) ([]*Case, []string, error) {
	var all []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			all = append(all, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	sort.Strings(all)
	opened := map[string]bool{}
	byCase := map[string][]string{}
	var unaccessed []string
	for _, f := range all {
		parts := strings.Split(f, "/")
		if len(parts) >= 2 && !sel.has(parts[0], parts[1]) {
			continue
		}
		if len(parts) == 1 && (sel.Runner != "" || sel.Handler != "") {
			continue
		}
		if len(parts) != 4 {
			unaccessed = append(unaccessed, f)
			continue
		}
		key := strings.Join(parts[:3], "/")
		byCase[key] = append(byCase[key], parts[3])
	}
	var cases []*Case
	for key, files := range byCase {
		c := readCase(dir, key, files, opened)
		cases = append(cases, c)
		for _, f := range files {
			if !opened[key+"/"+f] {
				unaccessed = append(unaccessed, key+"/"+f)
			}
		}
	}
	sort.Slice(cases, func(i, j int) bool { return cases[i].Path < cases[j].Path })
	sort.Strings(unaccessed)
	return cases, unaccessed, nil
}

func readCase(dir, key string, files []string, opened map[string]bool) *Case {
	parts := strings.Split(key, "/")
	c := &Case{Path: key, Runner: parts[0], Handler: parts[1], Name: parts[2]}
	var problems []string
	for _, p := range parts {
		if !nameRe.MatchString(p) {
			problems = append(problems, fmt.Sprintf("directory name %q is not [a-z0-9_]+ (WBFT-VEC-016)", p))
		}
	}
	has := map[string]bool{}
	for _, f := range files {
		has[f] = true
	}
	read := func(name string) map[string]any {
		if !has[name] {
			return nil
		}
		opened[key+"/"+name] = true
		b, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(key), name))
		if err != nil {
			problems = append(problems, name+": "+err.Error())
			return nil
		}
		doc, err := yamlsubset.Parse(b)
		if err != nil {
			problems = append(problems, name+": "+err.Error()+" (WBFT-VEC-013)")
			return nil
		}
		if name != "meta.yaml" {
			problems = append(problems, yamlsubset.CheckValues(doc, name)...)
		}
		return doc
	}
	for _, need := range []string{"meta.yaml", "input.yaml"} {
		if !has[need] {
			problems = append(problems, "missing "+need)
		}
	}
	meta := read("meta.yaml")
	c.Input = read("input.yaml")
	c.Expected = read("expected.yaml")
	if has["expected.yaml"] && c.Expected == nil && len(problems) == 0 {
		problems = append(problems, "expected.yaml could not be read")
	}
	for _, f := range files {
		if f != "meta.yaml" && f != "input.yaml" && f != "expected.yaml" {
			problems = append(problems, "file not part of a case: "+f)
		}
	}
	if meta != nil {
		problems = append(problems, checkMeta(c, meta, has["expected.yaml"])...)
	}
	if len(problems) > 0 {
		c.Problem = strings.Join(problems, "; ")
	}
	return c
}

func checkMeta(c *Case, meta map[string]any, hasExpected bool) []string {
	var problems []string
	for _, f := range metaTop {
		if _, ok := meta[f]; !ok {
			problems = append(problems, "meta.yaml: missing field "+f+" (WBFT-VEC-015)")
		}
	}
	for f, want := range map[string]string{"runner": c.Runner, "handler": c.Handler, "case": c.Name} {
		if got, ok := meta[f].(string); ok && got != want {
			problems = append(problems, fmt.Sprintf("meta.yaml: %s is %q, the directory says %q", f, got, want))
		}
	}
	c.Kind, _ = meta["kind"].(string)
	if !kinds[c.Kind] {
		problems = append(problems, fmt.Sprintf("meta.yaml: kind %q is not pure, chain or steps", c.Kind))
	}
	reqs, _ := meta["requirements"].([]any)
	if len(reqs) == 0 {
		problems = append(problems, "meta.yaml: requirements must be a non-empty list")
	}
	for _, r := range reqs {
		s, ok := r.(string)
		if !ok || !reqIDRe.MatchString(s) {
			problems = append(problems, fmt.Sprintf("meta.yaml: %v is not a requirement ID", r))
			continue
		}
		c.Requirements = append(c.Requirements, s)
	}
	if _, ok := meta["expected_error"]; ok && hasExpected {
		problems = append(problems, "meta.yaml: expected_error in a case that has expected.yaml")
	}
	return problems
}
