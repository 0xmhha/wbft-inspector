package reconstructreview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"regexp"
	"strconv"
)

var (
	ErrPacket      = errors.New("invalid reconstructed review packet")
	ErrChecksum    = errors.New("review packet checksum differs")
	shaPattern     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	commitPattern  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	addressPattern = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	hashPattern    = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	runPattern     = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
	codePattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,95}$`)
	framePattern   = regexp.MustCompile(`^frames-[A-Za-z0-9_.-]{1,128}\.jsonl$`)
)

// Read checks one bounded packet and, optionally, its independently supplied
// checksum. Parent result identity and source truth require separate evidence.
func Read(reader io.Reader, expectedSHA string) (Result, error) {
	if expectedSHA != "" && !shaPattern.MatchString(expectedSHA) {
		return Result{}, ErrPacket
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxBytes+1))
	if err != nil || len(raw) > MaxBytes {
		return Result{}, ErrPacket
	}
	hash := sha256.Sum256(raw)
	sum := hex.EncodeToString(hash[:])
	if expectedSHA != "" && sum != expectedSHA {
		return Result{}, ErrChecksum
	}
	tokens := json.NewDecoder(bytes.NewReader(raw))
	tokens.UseNumber()
	if unique(tokens, 0) != nil {
		return Result{}, ErrPacket
	}
	if _, err = tokens.Token(); err != io.EOF {
		return Result{}, ErrPacket
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var packet Packet
	if decoder.Decode(&packet) != nil || decoder.Decode(new(any)) != io.EOF || !valid(packet) {
		return Result{}, ErrPacket
	}
	return Result{Format: ValidationFormat, PacketSHA: sum, ExpectedChecksumVerified: expectedSHA != "", SpecificationVerdict: "not_evaluated", Packet: packet}, nil
}

// Optional fields are omitted, never null. Duplicate keys are rejected at
// every depth before a typed decoder can discard an earlier value.
func unique(d *json.Decoder, depth int) error {
	if depth > 32 {
		return ErrPacket
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return ErrPacket
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= 32 {
		return ErrPacket
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrPacket
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return ErrPacket
			}
			seen[name] = true
			if unique(d, depth+1) != nil {
				return ErrPacket
			}
		}
		last, err := d.Token()
		if err != nil || last != json.Delim('}') {
			return ErrPacket
		}
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 4096 || unique(d, depth+1) != nil {
				return ErrPacket
			}
		}
		last, err := d.Token()
		if err != nil || last != json.Delim(']') {
			return ErrPacket
		}
	default:
		return ErrPacket
	}
	return nil
}

func decimal(value string, bits int, positive bool) bool {
	n, ok := new(big.Int).SetString(value, 10)
	return ok && n.Sign() >= 0 && (!positive || n.Sign() > 0) && n.BitLen() <= bits && n.String() == value
}
func labels(xs []string) bool {
	if xs == nil || len(xs) > 64 {
		return false
	}
	for _, x := range xs {
		if !codePattern.MatchString(x) {
			return false
		}
	}
	return true
}
func optional(value string, match func(string) bool) bool { return value == "" || match(value) }

func valid(p Packet) bool {
	if p.Format != Format || p.Classification != "cross_implementation_candidate" || p.SpecificationVerdict != "not_evaluated" || p.ExecutionVersion != "wbft-reconstructed-execution/1" || p.ComparisonModel != "wbft-observable-state-actions/1" || !p.AllImprovementsOff || !shaPattern.MatchString(p.ResultSHA) || !commitPattern.MatchString(p.CoreVersion) || p.Position < 1 || !addressPattern.MatchString(p.Node) || !decimal(p.Network.ChainID, 512, false) || !hashPattern.MatchString(p.Network.Genesis) || !runPattern.MatchString(p.LogRun) || !decimal(p.Height.Height, 256, true) || !labels(p.Height.Issues) {
		return false
	}
	s := p.Source
	for _, sum := range []string{s.LogSHA, s.LogProfileSHA, s.ProcessingSHA, s.FrameSHA, s.ChainSHA, s.GenesisSHA, s.BinarySHA} {
		if !shaPattern.MatchString(sum) {
			return false
		}
	}
	if s.LogProfile != "gstable@740526d03" || s.LogNormalizer != "wbft-log-normalization/2" || s.ProcessingFormat != "wbft-input-observations/1" || s.ProcessingNormalizer != "wbft-input-observation-normalization/1" || !runPattern.MatchString(s.ProcessingRun) || !decimal(s.ProcessingInstance, 64, true) || !runPattern.MatchString(s.FrameRun) || !commitPattern.MatchString(s.SourceCommit) || !labels(s.CaptureIssues) {
		return false
	}
	switch p.Height.Status {
	case "complete":
		if !s.CaptureComplete || len(s.CaptureIssues) != 0 || !p.Step.CoreApplied || len(p.Step.Issues) != 0 {
			return false
		}
	case "partial":
	case "not_possible":
		if p.Step.CoreApplied {
			return false
		}
	default:
		return false
	}
	step, in := p.Step, p.Step.Input
	if !labels(step.Issues) || step.Observed == nil || step.Computed == nil || step.Differences == nil || len(step.Observed) > 1024 || len(step.Computed) > 1024 || len(step.Differences) > 1024 || in.Height != p.Height.Height || !decimal(in.Round, 256, false) || !decimal(in.Ordinal, 64, true) || in.Instance != s.ProcessingInstance || !decimal(in.ProcessingMono, 63, false) || in.Source.Kind != "processing_boundary" || !point(in.Source, p) || in.Source.Run != s.ProcessingRun || in.ReceiveClock != "actual_processing_boundary_not_wire_arrival" {
		return false
	}
	switch in.Kind {
	case "start", "stop", "head", "request", "message", "backlog", "round_timeout", "retry_timeout":
	default:
		return false
	}
	switch in.Via {
	case "unbound":
		if step.CoreApplied {
			return false
		}
	case "observed_processing_boundary", "derived_timer_generation", "unique_recorded_schedule", "derived_future_timer_schedule":
	default:
		return false
	}
	if !optional(in.DerivedTimerGeneration, func(v string) bool { return decimal(v, 64, true) }) || in.ContentModel != "" && in.ContentModel != "direct_processing_bytes_with_content_corroboration" {
		return false
	}
	if in.Content != nil {
		c := in.Content
		if !point(c.Source, p) || c.Source.Kind != "log" && c.Source.Kind != "frame" || !addressPattern.MatchString(c.Peer) || !shaPattern.MatchString(c.PayloadSHA) || !optional(c.Digest, hashPattern.MatchString) {
			return false
		}
	}
	for _, at := range []*Point{in.Head, in.Application} {
		if at != nil && (!point(*at, p) || at.Kind != "application_answer" || at.Sequence != in.Source.Sequence || at.Line < in.Source.Line) {
			return false
		}
	}
	if in.TimerArm != nil && !point(*in.TimerArm, p) {
		return false
	}
	for _, projections := range [][]Projection{step.Observed, step.Computed} {
		for _, value := range projections {
			if !projection(value, p) {
				return false
			}
		}
	}
	for _, difference := range step.Differences {
		if !codePattern.MatchString(difference.Kind) || difference.Expected == nil && difference.Actual == nil {
			return false
		}
		for _, value := range []*Projection{difference.Expected, difference.Actual} {
			if value != nil && !projection(*value, p) {
				return false
			}
		}
	}
	return true
}

func point(at Point, p Packet) bool {
	if at.Line < 1 || at.BlockIndex != "" {
		return false
	}
	switch at.Kind {
	case "log":
		return at.File == "log" && at.Run == p.LogRun && at.Sequence == ""
	case "frame":
		return framePattern.MatchString(at.File) && at.Run == p.Source.FrameRun && decimal(at.Sequence, 64, false)
	case "processing_boundary":
		return at.File == "input_observations" && at.Run == p.Source.ProcessingRun && decimal(at.Sequence, 64, true) && !at.ViewInferred
	case "application_answer":
		return at.File == "input_observations" && (at.Run == "" || at.Run == p.Source.ProcessingRun) && decimal(at.Sequence, 64, true) && !at.ViewInferred
	default:
		return false
	}
}

func projection(value Projection, p Packet) bool {
	switch value.Kind {
	case "state_before", "state_after", "state", "broadcast", "timer_arm", "header_handover", "application_binding":
	default:
		return false
	}
	if !optional(value.Height, func(v string) bool { return decimal(v, 256, false) }) || !optional(value.Round, func(v string) bool { return decimal(v, 256, false) }) || !optional(value.Proposer, addressPattern.MatchString) || !optional(value.Digest, hashPattern.MatchString) || !optional(value.Valset, hashPattern.MatchString) || !optional(value.ArgumentSHA, shaPattern.MatchString) {
		return false
	}
	if value.DurationNS != "" {
		n, err := strconv.ParseInt(value.DurationNS, 10, 64)
		if err != nil || strconv.FormatInt(n, 10) != value.DurationNS {
			return false
		}
	}
	if value.DurationSeconds != "" {
		n, err := strconv.ParseFloat(value.DurationSeconds, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || strconv.FormatFloat(n, 'g', -1, 64) != value.DurationSeconds {
			return false
		}
	}
	switch value.State {
	case "", "AcceptRequest", "Preprepared", "Prepared", "Committed", "unavailable":
	default:
		return false
	}
	switch value.Timer {
	case "", "round", "retry", "future":
	default:
		return false
	}
	switch value.Code {
	case "", "18", "19", "20", "21":
	default:
		return false
	}
	switch value.Method {
	case "", "head", "validators_at", "verify", "bad_block", "commit_header":
	default:
		return false
	}
	if value.Source != nil && !point(*value.Source, p) {
		return false
	}
	if params := value.Parameters; params != nil {
		for _, v := range []string{params.RequestTimeoutMS, params.BlockPeriodSeconds, params.Epoch, params.MaxRequestTimeoutSeconds, params.AllowedFutureBlockSeconds, params.ProposerPolicy} {
			if !decimal(v, 64, false) {
				return false
			}
		}
	}
	return true
}
