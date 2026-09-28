package catalog

import (
	"strings"
	"testing"
)

func TestEmbeddedCatalog(t *testing.T) {
	s := SpecInfo()
	if s.Commit == "" || s.ReferenceCommit == "" {
		t.Fatalf("spec info %+v", s)
	}
	all, obs := Counts()
	if all == 0 || obs == 0 || obs > all {
		t.Fatalf("counts %d %d", all, obs)
	}
	for _, r := range Rows() {
		req, ok := Lookup(r.Requirement)
		if !ok {
			t.Fatalf("%s has a row but is not in the specification", r.Requirement)
		}
		if !req.Observable() || req.Withdrawn {
			t.Errorf("%s has a row but is not an Observable requirement", r.Requirement)
		}
	}
	if DefaultSeverity("WBFT-SM-011") != "medium" || DefaultSeverity("WBFT-SM-080") != "advisory" {
		t.Error("default severities")
	}
}

func TestParseRowsRejects(t *testing.T) {
	for _, doc := range []string{
		"rows:\n  - requirement: \"X\"\n    checker: \"c\"\n    priority: \"P0\"\n",
		"rows:\n  - requirement: \"WBFT-SM-011\"\n    checker: \"c\"\n    priority: \"P9\"\n",
		"rows:\n  - requirement: \"WBFT-SM-011\"\n    priority: \"P0\"\n",
		"rows:\n  - requirement: \"WBFT-SM-011\"\n    checker: \"c\"\n    priority: \"P0\"\n    extra: \"x\"\n",
	} {
		if _, err := ParseRows([]byte(doc)); err == nil {
			t.Errorf("accepted %q", doc)
		}
	}
}

func TestRegisterChangesTheHash(t *testing.T) {
	before := SHA256()
	Register([]Requirement{{ID: "WBFT-ZZ-001", Chapter: "A-99", Level: "MUST", Tags: []string{"log"}}},
		[]Row{{Requirement: "WBFT-ZZ-001", Checker: "zz.test", Priority: "P1"}})
	if SHA256() == before {
		t.Fatal("registering a requirement did not change the catalog hash")
	}
	if _, ok := RowOf("WBFT-ZZ-001"); !ok {
		t.Fatal("registered row not found")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("registering a known requirement did not panic")
		}
	}()
	Register([]Requirement{{ID: "WBFT-ZZ-001"}}, nil)
}

func TestLevel(t *testing.T) {
	cases := map[string]string{
		"A node MUST send.":                     "MUST",
		"A node MUST NOT send.":                 "MUST NOT",
		"A node MUST NOT send, and MUST relay.": "MUST",
		"A node SHOULD send.":                   "SHOULD",
		"A node MAY send.":                      "MAY",
		"Informative.":                          "",
	}
	for s, want := range cases {
		if got := level(s); got != want {
			t.Errorf("%q: %q, want %q", s, got, want)
		}
	}
	if strings.Contains(level("mustard"), "MUST") {
		t.Error("lower case")
	}
}
