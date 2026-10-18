package reconstructreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func fixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/review.json")
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func packet(t *testing.T) Packet {
	t.Helper()
	var p Packet
	if err := json.Unmarshal(fixture(t), &p); err != nil {
		t.Fatal(err)
	}
	return p
}
func TestReviewPreservesCoordinatesWithoutDecidingConformance(t *testing.T) {
	raw := fixture(t)
	hash := sha256.Sum256(raw)
	r, err := Read(bytes.NewReader(raw), hex.EncodeToString(hash[:]))
	if err != nil {
		t.Fatal(err)
	}
	if r.Format != ValidationFormat || !r.ExpectedChecksumVerified || r.ParentResultVerified || r.SourceTruthVerified || r.SpecificationVerdict != "not_evaluated" {
		t.Fatal(r)
	}
	in := r.Packet.Step.Input
	if in.Ordinal != "4" || in.Source.Sequence != "9007199254740993" || in.Instance != "2" || in.Round != "18446744073709551617" || in.ProcessingMono != "9007199254740999" || r.Packet.Position != 1 {
		t.Fatal("source positions or integers changed", in)
	}
	if len(r.Packet.Step.Differences) != 1 || r.Packet.Height.Status != "partial" {
		t.Fatal(r)
	}
	unbound, err := Read(bytes.NewReader(raw), "")
	if err != nil || unbound.ExpectedChecksumVerified {
		t.Fatal(unbound, err)
	}
}
func TestReviewRejectsMismatchedSourceDomainsAndClaims(t *testing.T) {
	changes := map[string]func(*Packet){
		"format":              func(p *Packet) { p.Format = "unknown" },
		"verdict":             func(p *Packet) { p.SpecificationVerdict = "PASS" },
		"improvements":        func(p *Packet) { p.AllImprovementsOff = false },
		"instance":            func(p *Packet) { p.Source.ProcessingInstance = "3" },
		"processing_run":      func(p *Packet) { p.Step.Input.Source.Run = "another" },
		"log_run":             func(p *Packet) { p.Step.Observed[1].Source.Run = "another" },
		"source_path":         func(p *Packet) { p.Step.Input.Source.File = "/private/source" },
		"ordinal":             func(p *Packet) { p.Step.Input.Source.Sequence = "01" },
		"wide_round":          func(p *Packet) { p.Step.Input.Round = "1e20" },
		"clock":               func(p *Packet) { p.Step.Input.ReceiveClock = "wire_arrival" },
		"kind":                func(p *Packet) { p.Step.Observed[0].Kind = "arbitrary" },
		"issue":               func(p *Packet) { p.Step.Issues = []string{"unbounded private error"} },
		"unbound_applied":     func(p *Packet) { p.Step.Input.Via = "unbound" },
		"incomplete_complete": func(p *Packet) { p.Height.Status = "complete"; p.Source.CaptureComplete = false },
		"missing_source":      func(p *Packet) { p.Source.FrameSHA = "" },
		"frame_scope": func(p *Packet) {
			p.Step.Input.Content = &Content{Peer: p.Node, PayloadSHA: strings.Repeat("a", 64), Source: Point{Kind: "frame", File: "frames-synthetic.jsonl", Line: 1, Sequence: "1", Run: "another"}}
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			p := packet(t)
			change(&p)
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = Read(bytes.NewReader(raw), ""); !errors.Is(err, ErrPacket) {
				t.Fatal("invalid packet accepted", err)
			}
		})
	}
}
func TestReviewRejectsUnknownDuplicateNullAndOversizeDocuments(t *testing.T) {
	raw := fixture(t)
	cases := [][]byte{
		append(append([]byte{}, raw...), raw...),
		[]byte(strings.Replace(string(raw), `"format":`, `"format":"unknown","format":`, 1)),
		[]byte(strings.Replace(string(raw), `"ordinal":`, `"payload":"opaque","ordinal":`, 1)),
		[]byte(strings.Replace(string(raw), `"line":`, `"line":7,"line":`, 1)),
		[]byte(strings.Replace(string(raw), `"core_applied": true`, `"core_applied": null`, 1)),
		[]byte(strings.Replace(string(raw), `"format":`, `"path":"/private/source","format":`, 1)),
		[]byte(strings.Repeat("[", 34) + "0" + strings.Repeat("]", 34)),
		[]byte(strings.Repeat("[", 33) + strings.Repeat("]", 33)),
		bytes.Repeat([]byte(" "), MaxBytes+1),
	}
	for i, body := range cases {
		if _, err := Read(bytes.NewReader(body), ""); !errors.Is(err, ErrPacket) {
			t.Fatal("invalid document accepted", i, err)
		}
	}
	if _, err := Read(bytes.NewReader(raw), strings.Repeat("f", 64)); !errors.Is(err, ErrChecksum) {
		t.Fatal("checksum mismatch accepted", err)
	}
}
func TestReviewKeepsUnappliedPartialStepUnavailable(t *testing.T) {
	p := packet(t)
	p.Step.CoreApplied = false
	p.Step.Input.Via = "unbound"
	p.Step.Issues = []string{"recorded_application_answer_missing"}
	p.Step.Computed = []Projection{}
	p.Source.CaptureComplete = false
	p.Source.CaptureIssues = []string{"sequence_gap"}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Read(bytes.NewReader(raw), "")
	if err != nil || r.Packet.Step.CoreApplied || r.Packet.Source.CaptureComplete || r.Packet.Height.Status != "partial" || r.SpecificationVerdict != "not_evaluated" {
		t.Fatal(r, err)
	}
}
