// Package syncobs reads a process's independently recorded typed downloader
// notifications. Coverage of this file is not a consensus-policy verdict.
package syncobs

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/0xmhha/wbft-inspector/internal/evidence"
)

const Format = "wbft-sync-notifications/1"
const maxRecords = 1_000_000
const maxLine = 64 * 1024

// Header binds this source to a core process, not to a timestamp window.
type Header struct {
	Format       string `json:"format"`
	Type         string `json:"type"`
	Node         string `json:"node"`
	Run          string `json:"run"`
	Validator    bool   `json:"validator"`
	CoreStartSeq string `json:"core_start_seq"`
}

type Notification struct {
	Type              string `json:"type"`
	Sequence          string `json:"sequence"`
	Kind              string `json:"kind"`
	PostedAtAvailable bool   `json:"posted_at_available"`
	PostedAt          string `json:"posted_at,omitempty"`
	Number            string `json:"number,omitempty"`
	Hash              string `json:"hash,omitempty"`
	Line              int    `json:"-"`
}

type Footer struct {
	Type              string `json:"type"`
	Observed          string `json:"observed"`
	Written           string `json:"written"`
	Dropped           string `json:"dropped"`
	Invalid           string `json:"invalid"`
	SequenceExhausted bool   `json:"sequence_exhausted"`
	CoreComplete      bool   `json:"core_complete"`
	CoreStopSeq       string `json:"core_stop_seq,omitempty"`
	ClosedNormally    bool   `json:"closed_normally"`
	Complete          bool   `json:"complete"`
}

type Source struct {
	Path          string
	SHA256        string
	Input         string
	Header        Header
	Notifications []Notification
	Footer        *Footer
	FooterLine    int
	Lines         int
	// Complete is recomputed from the retained file, including its final LF.
	Complete bool
}

// Pointer refers to the original JSON line without copying its payload.
func (s *Source) Pointer(line int) evidence.Pointer {
	return evidence.Pointer{Kind: "log", Input: s.Input, Node: s.Header.Node, Line: line}
}

// Load hashes and parses the same byte stream; it never repairs an incomplete
// recording, sorts notifications by time, or reads a producer's database.
func Load(path string) (*Source, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	h := sha256.New()
	s, err := Read(io.TeeReader(f, h))
	if err != nil {
		return nil, err
	}
	s.Path = path
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	return s, nil
}

func Read(reader io.Reader) (*Source, error) {
	s := &Source{}
	scan := bufio.NewScanner(reader)
	scan.Buffer(make([]byte, 4096), maxLine)
	// Keep the line terminator as part of the scan token to distinguish a
	// complete encoder output from a truncated final record.
	scan.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i+1], nil
		}
		if atEOF && len(data) > 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	var last uint64
	terminated := false
	for scan.Scan() {
		s.Lines++
		raw := scan.Bytes()
		terminated = len(raw) > 0 && raw[len(raw)-1] == '\n'
		if s.Lines > maxRecords+2 {
			return nil, errors.New("sync notification record limit exceeded")
		}
		fields, err := object(raw)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", s.Lines, err)
		}
		var kind string
		if json.Unmarshal(fields["type"], &kind) != nil {
			return nil, fmt.Errorf("line %d: missing record type", s.Lines)
		}
		if s.Footer != nil {
			return nil, fmt.Errorf("line %d: record after footer", s.Lines)
		}
		switch kind {
		case "header":
			if s.Lines != 1 {
				return nil, fmt.Errorf("line %d: header is not first", s.Lines)
			}
			if decode(raw, fields, &s.Header, "format", "type", "node", "run", "validator", "core_start_seq") != nil || s.Header.Format != Format || !hexValue(s.Header.Node, 20) || s.Header.Run == "" || len(s.Header.Run) > 128 || strings.IndexFunc(s.Header.Run, unicode.IsControl) >= 0 || s.Header.CoreStartSeq != "0" {
				return nil, errors.New("invalid sync notification header")
			}
		case "notification":
			if s.Lines == 1 {
				return nil, errors.New("missing sync notification header")
			}
			var n Notification
			if decode(raw, fields, &n, "type", "sequence", "kind", "posted_at_available") != nil {
				return nil, fmt.Errorf("line %d: invalid notification fields", s.Lines)
			}
			seq, ok := uintValue(n.Sequence)
			if !ok || seq == 0 || seq <= last {
				return nil, fmt.Errorf("line %d: invalid notification sequence", s.Lines)
			}
			last = seq
			_, hasTime := fields["posted_at"]
			_, hasNumber := fields["number"]
			_, hasHash := fields["hash"]
			if n.PostedAtAvailable != hasTime {
				return nil, fmt.Errorf("line %d: unavailable notification clock", s.Lines)
			}
			if hasTime {
				if t, err := time.Parse(time.RFC3339Nano, n.PostedAt); err != nil || t.IsZero() || t.UTC().Format(time.RFC3339Nano) != n.PostedAt {
					return nil, fmt.Errorf("line %d: invalid notification clock", s.Lines)
				}
			}
			switch n.Kind {
			case "start", "failed":
				if hasNumber || hasHash {
					return nil, fmt.Errorf("line %d: completion fields on another notification", s.Lines)
				}
			case "done":
				number, ok := new(big.Int).SetString(n.Number, 10)
				if !hasNumber || !hasHash || !ok || number.Sign() < 0 || number.BitLen() > 256 || number.String() != n.Number || !hexValue(n.Hash, 32) {
					return nil, fmt.Errorf("line %d: invalid completion header", s.Lines)
				}
			default:
				return nil, fmt.Errorf("line %d: unknown notification kind", s.Lines)
			}
			n.Line = s.Lines
			s.Notifications = append(s.Notifications, n)
		case "footer":
			if s.Lines == 1 {
				return nil, errors.New("missing sync notification header")
			}
			var f Footer
			if decode(raw, fields, &f, "type", "observed", "written", "dropped", "invalid", "sequence_exhausted", "core_complete", "closed_normally", "complete") != nil {
				return nil, fmt.Errorf("line %d: invalid footer fields", s.Lines)
			}
			observed, ok1 := uintValue(f.Observed)
			written, ok2 := uintValue(f.Written)
			dropped, ok3 := uintValue(f.Dropped)
			invalid, ok4 := uintValue(f.Invalid)
			if !ok1 || !ok2 || !ok3 || !ok4 || written != uint64(len(s.Notifications)) || last > observed {
				return nil, errors.New("inconsistent sync notification counts")
			}
			sum := new(big.Int).SetUint64(written)
			sum.Add(sum, new(big.Int).SetUint64(dropped))
			sum.Add(sum, new(big.Int).SetUint64(invalid))
			if (!f.SequenceExhausted && sum.Cmp(new(big.Int).SetUint64(observed)) != 0) || (f.SequenceExhausted && (observed != math.MaxUint64 || sum.Cmp(new(big.Int).SetUint64(observed)) < 0)) {
				return nil, errors.New("inconsistent sync notification loss counts")
			}
			_, hasStop := fields["core_stop_seq"]
			stop, ok := uintValue(f.CoreStopSeq)
			if hasStop && (!ok || stop == 0) || f.CoreComplete && !hasStop {
				return nil, errors.New("invalid sync notification stop identity")
			}
			complete := f.CoreComplete && f.ClosedNormally && !f.SequenceExhausted && dropped == 0 && invalid == 0
			if f.Complete != complete {
				return nil, errors.New("contradictory sync notification completeness")
			}
			if complete {
				for i, n := range s.Notifications {
					if n.Sequence != strconv.Itoa(i+1) {
						return nil, errors.New("complete sync notification source has a sequence gap")
					}
				}
			}
			s.Footer = &f
			s.FooterLine = s.Lines
		default:
			return nil, fmt.Errorf("line %d: unknown sync notification record", s.Lines)
		}
	}
	if err := scan.Err(); err != nil {
		return nil, err
	}
	if s.Lines == 0 {
		return nil, errors.New("empty sync notification source")
	}
	s.Complete = s.Footer != nil && s.Footer.Complete && terminated
	return s, nil
}

func uintValue(value string) (uint64, bool) {
	v, err := strconv.ParseUint(value, 10, 64)
	return v, err == nil && strconv.FormatUint(v, 10) == value
}
func hexValue(value string, size int) bool {
	if len(value) != 2+size*2 || !strings.HasPrefix(value, "0x") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[2:])
	return err == nil
}

// Records are flat closed objects. Reject duplicate keys and explicit nulls
// before decoding booleans, so omitted false cannot become observed false.
func object(raw []byte) (map[string]json.RawMessage, error) {
	if !utf8.Valid(raw) {
		return nil, errors.New("invalid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("record must be an object")
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, err
		}
		key, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid field name")
		}
		if _, exists := fields[key]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return nil, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return nil, errors.New("null field")
		}
		fields[key] = value
	}
	if _, err := d.Token(); err != nil {
		return nil, err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing record data")
	}
	return fields, nil
}
func decode(raw []byte, fields map[string]json.RawMessage, dst any, required ...string) error {
	for _, key := range required {
		if _, ok := fields[key]; !ok {
			return errors.New("missing required field")
		}
	}
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
	}
	switch dst.(type) {
	case *Notification:
		for _, key := range []string{"posted_at", "number", "hash"} {
			allowed[key] = true
		}
	case *Footer:
		allowed["core_stop_seq"] = true
	}
	for key := range fields {
		if !allowed[key] {
			return errors.New("unknown field")
		}
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	return d.Decode(dst)
}
