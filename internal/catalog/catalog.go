// Package catalog holds what the inspector knows about the specification:
// the requirement list of the public specification (generated from the
// wbft-spec repository at the commit in data/requirements.json) and the
// checker catalog (data/checkers.yaml), which assigns a checker, a priority
// and optionally a severity to requirements.
//
// Packages compiled into another build can add requirements and rows with
// Register from an init function; the public build registers nothing. A
// requirement ID that is neither embedded nor registered is unknown to the
// build, and the inspector reports it as CANNOT_DECIDE with the reason
// NOT_IN_BUILD instead of deciding it.
package catalog

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/0xmhha/wbft-inspector/internal/yamlsubset"
)

//go:embed data/requirements.json data/checkers.yaml
var data embed.FS

// Requirement is one requirement of the specification.
type Requirement struct {
	ID        string   `json:"id"`
	Chapter   string   `json:"chapter"`
	Level     string   `json:"level"` // MUST, MUST NOT, SHOULD, SHOULD NOT, MAY or ""
	Tags      []string `json:"tags"`  // Observable: tags; empty when not observable
	Withdrawn bool     `json:"withdrawn,omitempty"`
}

// Observable reports whether the requirement carries Observable: tags.
func (r Requirement) Observable() bool { return len(r.Tags) > 0 }

// Row is one row of the checker catalog.
type Row struct {
	Requirement string `json:"requirement"`
	Checker     string `json:"checker"`
	Priority    string `json:"priority"`           // P0, P1, P2 or V
	Severity    string `json:"severity,omitempty"` // overrides the default severity
}

// Spec identifies the specification the embedded list was generated from.
type Spec struct {
	Repo            string `json:"repo"`
	Commit          string `json:"commit"`
	ReferenceCommit string `json:"reference_commit"`
}

// File is the format of data/requirements.json.
type File struct {
	Spec         Spec          `json:"spec"`
	Requirements []Requirement `json:"requirements"`
}

var (
	idRe       = regexp.MustCompile(`^(WBFT|SNET)-[A-Z]+-[0-9]{3}$`)
	priorities = map[string]bool{"P0": true, "P1": true, "P2": true, "V": true}
	severities = map[string]bool{"critical": true, "high": true, "medium": true, "low": true, "advisory": true}
)

// ValidID reports whether s has the form of a requirement ID.
func ValidID(s string) bool { return idRe.MatchString(s) }

var (
	mu         sync.Mutex
	loaded     bool
	spec       Spec
	reqs       = map[string]Requirement{}
	rows       = map[string]Row{}
	registered []string // IDs added by Register, for the catalog hash
)

func load() {
	if loaded {
		return
	}
	loaded = true
	var f File
	b, err := data.ReadFile("data/requirements.json")
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(b, &f); err != nil {
		panic(fmt.Sprintf("catalog: requirements.json: %v", err))
	}
	spec = f.Spec
	for _, r := range f.Requirements {
		reqs[r.ID] = r
	}
	y, err := data.ReadFile("data/checkers.yaml")
	if err != nil {
		panic(err)
	}
	rs, err := ParseRows(y)
	if err != nil {
		panic(fmt.Sprintf("catalog: checkers.yaml: %v", err))
	}
	for _, r := range rs {
		if _, ok := reqs[r.Requirement]; !ok {
			panic(fmt.Sprintf("catalog: checkers.yaml names %s, which the specification does not define", r.Requirement))
		}
		rows[r.Requirement] = r
	}
}

// ParseRows parses a checker catalog in the vector YAML subset:
//
//	rows:
//	  - requirement: "WBFT-SM-011"
//	    checker: "sm.relay_on_ok"
//	    priority: "P2"
func ParseRows(b []byte) ([]Row, error) {
	doc, err := yamlsubset.Parse(b)
	if err != nil {
		return nil, err
	}
	list, ok := doc["rows"].([]any)
	if !ok || len(doc) != 1 {
		return nil, fmt.Errorf("the document must have exactly the field rows, a list")
	}
	seen := map[string]bool{}
	var out []Row
	for i, x := range list {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("rows[%d]: not a mapping", i)
		}
		var r Row
		for k, v := range m {
			s, ok := v.(string)
			if !ok {
				return nil, fmt.Errorf("rows[%d].%s: not a string", i, k)
			}
			switch k {
			case "requirement":
				r.Requirement = s
			case "checker":
				r.Checker = s
			case "priority":
				r.Priority = s
			case "severity":
				r.Severity = s
			default:
				return nil, fmt.Errorf("rows[%d]: unknown field %s", i, k)
			}
		}
		switch {
		case !ValidID(r.Requirement):
			return nil, fmt.Errorf("rows[%d]: bad requirement %q", i, r.Requirement)
		case r.Checker == "":
			return nil, fmt.Errorf("rows[%d]: no checker", i)
		case !priorities[r.Priority]:
			return nil, fmt.Errorf("rows[%d]: bad priority %q", i, r.Priority)
		case r.Severity != "" && !severities[r.Severity]:
			return nil, fmt.Errorf("rows[%d]: bad severity %q", i, r.Severity)
		case seen[r.Requirement]:
			return nil, fmt.Errorf("rows[%d]: %s listed twice", i, r.Requirement)
		}
		seen[r.Requirement] = true
		out = append(out, r)
	}
	return out, nil
}

// Register adds requirements and catalog rows. It is meant for init
// functions of packages compiled into another build; it panics on a
// malformed entry or on a requirement that is already known.
func Register(add []Requirement, addRows []Row) {
	mu.Lock()
	defer mu.Unlock()
	load()
	for _, r := range add {
		if !ValidID(r.ID) {
			panic(fmt.Sprintf("catalog: bad requirement ID %q", r.ID))
		}
		if _, dup := reqs[r.ID]; dup {
			panic(fmt.Sprintf("catalog: %s is already known", r.ID))
		}
		if r.Tags == nil {
			r.Tags = []string{}
		}
		reqs[r.ID] = r
		registered = append(registered, r.ID)
	}
	for _, r := range addRows {
		if _, ok := reqs[r.Requirement]; !ok {
			panic(fmt.Sprintf("catalog: row for unknown requirement %s", r.Requirement))
		}
		if _, dup := rows[r.Requirement]; dup {
			panic(fmt.Sprintf("catalog: %s already has a row", r.Requirement))
		}
		if r.Checker == "" || !priorities[r.Priority] || (r.Severity != "" && !severities[r.Severity]) {
			panic(fmt.Sprintf("catalog: malformed row for %s", r.Requirement))
		}
		rows[r.Requirement] = r
	}
}

// SpecInfo returns the specification the embedded list was generated from.
func SpecInfo() Spec {
	mu.Lock()
	defer mu.Unlock()
	load()
	return spec
}

// Lookup returns a known requirement.
func Lookup(id string) (Requirement, bool) {
	mu.Lock()
	defer mu.Unlock()
	load()
	r, ok := reqs[id]
	return r, ok
}

// RowOf returns the catalog row of a requirement.
func RowOf(id string) (Row, bool) {
	mu.Lock()
	defer mu.Unlock()
	load()
	r, ok := rows[id]
	return r, ok
}

// Rows returns every catalog row, sorted by requirement ID.
func Rows() []Row {
	mu.Lock()
	defer mu.Unlock()
	load()
	out := make([]Row, 0, len(rows))
	for _, r := range rows {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Requirement < out[j].Requirement })
	return out
}

// Requirements returns every known requirement, sorted by ID.
func Requirements() []Requirement {
	mu.Lock()
	defer mu.Unlock()
	load()
	out := make([]Requirement, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Counts returns the number of known requirements and of observable ones.
func Counts() (all, observable int) {
	for _, r := range Requirements() {
		all++
		if r.Observable() && !r.Withdrawn {
			observable++
		}
	}
	return all, observable
}

// SHA256 is the hash of the effective catalog (requirements and rows,
// including registered ones), so two builds with different catalogs write
// different values to run.inspector.catalog_sha256.
func SHA256() string {
	v := struct {
		Spec         Spec          `json:"spec"`
		Requirements []Requirement `json:"requirements"`
		Rows         []Row         `json:"rows"`
	}{SpecInfo(), Requirements(), Rows()}
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// DefaultSeverity returns the severity of a failed requirement: the row's
// override, advisory for SHOULD, SHOULD NOT and MAY, and otherwise the
// default of the requirement's area.
func DefaultSeverity(id string) string {
	if row, ok := RowOf(id); ok && row.Severity != "" {
		return row.Severity
	}
	r, _ := Lookup(id)
	switch r.Level {
	case "SHOULD", "SHOULD NOT", "MAY":
		return "advisory"
	}
	area := id
	if i := strings.LastIndex(id, "-"); i > 0 {
		area = id[:i]
	}
	switch area {
	case "WBFT-VAL", "WBFT-EPOCH", "WBFT-SEC":
		return "critical"
	case "WBFT-MSG", "WBFT-SM", "WBFT-TIMER", "WBFT-NET", "WBFT-APP", "WBFT-PROTO", "WBFT-VEC", "SNET-SYNC":
		return "medium"
	case "SNET-RPC":
		return "low"
	}
	return "high"
}
