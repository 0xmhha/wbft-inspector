package syncobs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/complete.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
func rewrite(t *testing.T, raw string, line int, edit func(map[string]any)) string {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[line-1]), &row); err != nil {
		t.Fatal(err)
	}
	edit(row)
	b, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	lines[line-1] = string(b)
	return strings.Join(lines, "\n") + "\n"
}

func TestRetainOriginalOrderExactNumbersAndCoordinates(t *testing.T) {
	source, err := Load("testdata/complete.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	raw := fixture(t)
	digest := sha256.Sum256([]byte(raw))
	source.Input = "in-7"
	if !source.Complete || source.Lines != 8 || source.FooterLine != 8 || len(source.Notifications) != 6 || source.SHA256 != hex.EncodeToString(digest[:]) || source.Header.CoreStartSeq != "0" {
		t.Fatal(source)
	}
	if source.Notifications[3].Number != "9007199254740993" || source.Notifications[5].Number != "115792089237316195423570985008687907853269984665640564039457584007913129639935" {
		t.Fatal("large header numbers changed")
	}
	if source.Notifications[2].PostedAt != "2025-12-31T23:59:59Z" || source.Notifications[1].PostedAtAvailable || source.Notifications[1].PostedAt != "" {
		t.Fatal("unavailable or regressing clock was repaired")
	}
	for i, n := range source.Notifications {
		if n.Line != i+2 {
			t.Fatal(n)
		}
		p := source.Pointer(n.Line)
		if p.Kind != "log" || p.Input != "in-7" || p.Node != source.Header.Node || p.Line != i+2 || p.T != "" {
			t.Fatal(p)
		}
	}
}

func TestIncompleteSourceIsRetainedWithoutPromotingCoverage(t *testing.T) {
	raw := fixture(t)
	withoutFooter := raw[:strings.LastIndex(strings.TrimSuffix(raw, "\n"), "\n")+1]
	for name, input := range map[string]string{"missing-footer": withoutFooter, "truncated-final-LF": strings.TrimSuffix(raw, "\n"), "aborted": rewrite(t, rewrite(t, raw, 8, func(r map[string]any) { r["closed_normally"] = false; r["complete"] = false }), 8, func(r map[string]any) { r["core_complete"] = false; delete(r, "core_stop_seq") })} {
		t.Run(name, func(t *testing.T) {
			s, err := Read(strings.NewReader(input))
			if err != nil || s.Complete || len(s.Notifications) != 6 {
				t.Fatal(s, err)
			}
		})
	}
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	loss := strings.Join([]string{lines[0], lines[1], lines[3], lines[7]}, "\n") + "\n"
	loss = rewrite(t, loss, 4, func(r map[string]any) {
		r["observed"] = "3"
		r["written"] = "2"
		r["dropped"] = "1"
		r["complete"] = false
	})
	if s, err := Read(strings.NewReader(loss)); err != nil || s.Complete || s.Notifications[1].Sequence != "3" {
		t.Fatal(s, err)
	}
}

func TestRejectMalformedOrContradictorySource(t *testing.T) {
	raw := fixture(t)
	changes := []struct {
		name string
		line int
		edit func(map[string]any)
	}{
		{"unknown-header", 1, func(r map[string]any) { r["private_field"] = true }},
		{"case-alias", 1, func(r map[string]any) { r["Validator"] = false }},
		{"unsupported-format", 1, func(r map[string]any) { r["format"] = "wbft-sync-notifications/2" }},
		{"empty-run", 1, func(r map[string]any) { r["run"] = "" }},
		{"nonzero-start", 1, func(r map[string]any) { r["core_start_seq"] = "1" }},
		{"noncanonical-address", 1, func(r map[string]any) { r["node"] = "0xAA00000000000000000000000000000000000000" }},
		{"numeric-sequence", 2, func(r map[string]any) { r["sequence"] = 1 }},
		{"sequence-leading-zero", 2, func(r map[string]any) { r["sequence"] = "01" }},
		{"sequence-overflow", 2, func(r map[string]any) { r["sequence"] = "18446744073709551616" }},
		{"sequence-repeat", 3, func(r map[string]any) { r["sequence"] = "1" }},
		{"unknown-kind", 2, func(r map[string]any) { r["kind"] = "retry" }},
		{"invented-completion", 2, func(r map[string]any) { r["number"] = "1" }},
		{"missing-clock", 2, func(r map[string]any) { delete(r, "posted_at") }},
		{"unexpected-clock", 3, func(r map[string]any) { r["posted_at"] = "2026-01-01T00:00:00Z" }},
		{"invalid-clock", 2, func(r map[string]any) { r["posted_at"] = "tomorrow" }},
		{"invalid-header-number", 5, func(r map[string]any) { r["number"] = "-1" }},
		{"header-number-overflow", 7, func(r map[string]any) {
			r["number"] = "115792089237316195423570985008687907853269984665640564039457584007913129639936"
		}},
		{"missing-header-hash", 5, func(r map[string]any) { delete(r, "hash") }},
		{"invented-line", 2, func(r map[string]any) { r["Line"] = 99 }},
		{"null-optional", 3, func(r map[string]any) { r["posted_at"] = nil }},
		{"written-count", 8, func(r map[string]any) { r["written"] = "5" }},
		{"observed-count", 8, func(r map[string]any) { r["observed"] = "7" }},
		{"missing-stop", 8, func(r map[string]any) { delete(r, "core_stop_seq") }},
		{"zero-stop", 8, func(r map[string]any) { r["core_stop_seq"] = "0" }},
		{"invented-complete", 8, func(r map[string]any) { r["closed_normally"] = false }},
		{"contradictory-complete", 8, func(r map[string]any) { r["complete"] = false }},
		{"invented-exhaustion", 8, func(r map[string]any) { r["sequence_exhausted"] = true; r["complete"] = false }},
	}
	for _, c := range changes {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(rewrite(t, raw, c.line, c.edit))); err == nil {
				t.Fatal("malformed source accepted")
			}
		})
	}
	for _, field := range []struct {
		line int
		keys []string
	}{{1, []string{"validator"}}, {2, []string{"posted_at_available"}}, {8, []string{"sequence_exhausted", "core_complete", "closed_normally", "complete"}}} {
		for _, key := range field.keys {
			for _, null := range []bool{false, true} {
				t.Run(key+map[bool]string{true: "-null", false: "-missing"}[null], func(t *testing.T) {
					input := rewrite(t, raw, field.line, func(r map[string]any) {
						if null {
							r[key] = nil
						} else {
							delete(r, key)
						}
					})
					if _, err := Read(strings.NewReader(input)); err == nil {
						t.Fatal("unobserved boolean became false")
					}
				})
			}
		}
	}
	for name, input := range map[string]string{"duplicate-key": strings.Replace(raw, `"validator":true`, `"validator":true,"validator":false`, 1), "trailing-data": raw + "{}\n", "duplicate-header": raw + strings.Split(raw, "\n")[0] + "\n", "two-objects": strings.Replace(raw, "\n", " {}\n", 1), "blank-line": "\n" + raw, "empty": "", "no-header": raw[strings.Index(raw, "\n")+1:], "oversize-line": strings.Repeat("x", maxLine+1), "invalid-utf8": string([]byte{0xff}) + raw} {
		t.Run(name, func(t *testing.T) {
			if _, err := Read(strings.NewReader(input)); err == nil {
				t.Fatal("invalid source accepted")
			}
		})
	}
}
