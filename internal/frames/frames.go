// Package frames reads and validates frame dumps in the R-01 format (the
// istanbul frames a node sent and received, wbft requirements-on-nodes R-01):
//
//	<dir>/frames-<run>.jsonl    one record per line
//	<dir>/payloads/<ab>/<sha256> raw payload bytes, content-addressed
//
// The record types are frame, outcome, send_suppressed, conn and dropped.
// Every record has the common fields v (format version 1), type, node, run,
// seq, t_wall (RFC 3339 with nanoseconds) and t_mono_ns. seq is unique
// within a run; it need not increase along the file, since a node may write
// an outcome after the frame it belongs to with the seq it got earlier.
//
// The wbft node writes this format with wbft-journal export --format r01.
// Validate checks the rules a consumer relies on; the checkers that decide
// requirements from frames build on Load.
package frames

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
)

// FormatVersion is the dump format this package reads.
const FormatVersion = 1

// Record is one line of a dump. Optional fields are pointers or empty.
type Record struct {
	Input string `json:"-"` // input id of the dump in a report
	File  string `json:"-"` // file name in the dump directory
	Line  int    `json:"-"` // 1-based line

	V     int    `json:"v"`
	Type  string `json:"type"`
	Node  string `json:"node"`
	Run   string `json:"run"`
	Seq   uint64 `json:"seq"`
	TWall string `json:"t_wall"`
	TMono int64  `json:"t_mono_ns"`

	// frame
	Dir        string  `json:"dir"`
	Peer       *string `json:"peer"`
	PeerID     string  `json:"peer_id"`
	Code       string  `json:"code"`
	WireCode   *uint64 `json:"wire_code"`
	Size       *int64  `json:"size"`
	Payload    string  `json:"payload_sha256"`
	DedupKey   string  `json:"dedup_key"`
	Outcome    string  `json:"outcome"`
	WriteError string  `json:"write_error"`
	Cause      string  `json:"cause"`
	RelayOf    *uint64 `json:"relay_of"`
	Engine     string  `json:"engine"`

	// outcome
	Of         *uint64 `json:"of"`
	Check      string  `json:"check"`
	ErrorClass *string `json:"error_class"`
	Via        string  `json:"via"`
	Row        *int64  `json:"row"`
	Reason     string  `json:"reason"`

	// conn
	Event string `json:"event"`

	// dropped
	Count *uint64 `json:"count"`

	present map[string]bool // the top-level fields the line has
}

// Has reports whether the line had the field.
func (r *Record) Has(field string) bool { return r.present[field] }

// Where is "file:line".
func (r *Record) Where() string { return fmt.Sprintf("%s:%d", r.File, r.Line) }

// Dump is the content of one dump directory.
type Dump struct {
	Input   string // input id in a report (SetInput)
	Dir     string
	Files   []string
	Records []*Record
	// Malformed lists the lines that are not a JSON object.
	Malformed []string
}

// SetInput sets the input id of the dump and its records.
func (d *Dump) SetInput(id string) {
	d.Input = id
	for _, r := range d.Records {
		r.Input = id
	}
}

// Load reads the frames-*.jsonl files of dir in name order.
func Load(dir string) (*Dump, error) {
	names, err := filepath.Glob(filepath.Join(dir, "frames-*.jsonl"))
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("frames: no frames-*.jsonl in %s", dir)
	}
	sort.Strings(names)
	d := &Dump{Dir: dir}
	for _, path := range names {
		if err := d.read(path); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *Dump) read(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	name := filepath.Base(path)
	d.Files = append(d.Files, name)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for line := 1; sc.Scan(); line++ {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var fields map[string]json.RawMessage
		r := &Record{File: name, Line: line}
		if err := json.Unmarshal(b, &fields); err != nil {
			d.Malformed = append(d.Malformed, fmt.Sprintf("%s:%d: %v", name, line, err))
			continue
		}
		if err := json.Unmarshal(b, r); err != nil {
			d.Malformed = append(d.Malformed, fmt.Sprintf("%s:%d: %v", name, line, err))
			continue
		}
		r.present = map[string]bool{}
		for k := range fields {
			r.present[k] = true
		}
		d.Records = append(d.Records, r)
	}
	return sc.Err()
}

// Value sets of the format.
var (
	recordTypes     = []string{"frame", "outcome", "send_suppressed", "conn", "dropped"}
	frameOutcomes   = []string{"PENDING", "ACCEPT", "IGNORE", "DROP_SILENT", "DISCONNECT"}
	outcomeClasses  = []string{"ACCEPT", "IGNORE", "DROP_SILENT", "DISCONNECT"}
	causes          = []string{"broadcast", "gossip", "relay", "retry", "reconnect", "replay", "direct"}
	engineStates    = []string{"running", "stopped", "syncing"}
	connEvents      = []string{"handshake", "hello", "eth_registered", "istanbul_attached", "closed"}
	checkClasses    = []string{"", "PROCESS", "FUTURE", "OLD", "INVALID", "EXTRA_SEAL", "TOO_FAR", "prefilter"}
	outcomeVias     = []string{"direct", "backlog", "future_block", "self"}
	addressPattern  = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
	hashPattern     = regexp.MustCompile(`^0x[0-9a-f]{64}$`)
	sha256Pattern   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	codePattern     = regexp.MustCompile(`^0x[0-9a-f]+$`)
	tWallLayout     = "2006-01-02T15:04:05.999999999Z07:00"
	commonFields    = []string{"v", "type", "node", "run", "seq", "t_wall", "t_mono_ns"}
	frameFields     = []string{"dir", "peer", "code", "wire_code", "size", "dedup_key"}
	outcomeFields   = []string{"of", "outcome", "check", "via"}
	suppressFields  = []string{"peer", "dedup_key", "reason"}
	connFields      = []string{"event", "peer"}
	droppedFields   = []string{"count"}
	fieldsByType    = map[string][]string{"frame": frameFields, "outcome": outcomeFields, "send_suppressed": suppressFields, "conn": connFields, "dropped": droppedFields}
	payloadsDirName = "payloads"
)

// Result is what Validate reports.
type Result struct {
	Files    int            `json:"files"`
	Records  map[string]int `json:"records"`
	Payloads int            `json:"payloads"` // payload files checked
	Problems []string       `json:"problems"`
}

// Validate checks the dump: every line is a record of a known type with the
// common fields and the fields of its type, values are in their sets, a
// file holds one node and one run, seq is unique within a run, outcome.of
// and frame.relay_of name a received frame of the run, a relay names its
// frame, and every frame's payload file exists with the frame's sha256,
// size and dedup key.
func Validate(d *Dump) *Result {
	res := &Result{Files: len(d.Files), Records: map[string]int{}, Problems: []string{}}
	add := func(r *Record, format string, args ...any) {
		res.Problems = append(res.Problems, r.Where()+": "+fmt.Sprintf(format, args...))
	}
	res.Problems = append(res.Problems, d.Malformed...)

	type runKey struct{ file, run string }
	seqs := map[runKey]map[uint64]*Record{}
	fileIdentity := map[string][2]string{}
	checked := map[string]bool{}
	for _, r := range d.Records {
		res.Records[r.Type]++
		if r.V != FormatVersion {
			add(r, "v %d, want %d", r.V, FormatVersion)
		}
		if !slices.Contains(recordTypes, r.Type) {
			add(r, "unknown type %q", r.Type)
			continue
		}
		for _, f := range append(slices.Clone(commonFields), fieldsByType[r.Type]...) {
			if !r.Has(f) {
				add(r, "%s record without %s", r.Type, f)
			}
		}
		if !addressPattern.MatchString(r.Node) {
			add(r, "node %q is not a lower-case address", r.Node)
		}
		if r.Run == "" {
			add(r, "empty run")
		}
		if _, err := time.Parse(tWallLayout, r.TWall); err != nil {
			add(r, "t_wall %q is not RFC 3339: %v", r.TWall, err)
		}
		if id, ok := fileIdentity[r.File]; !ok {
			fileIdentity[r.File] = [2]string{r.Node, r.Run}
		} else if id != [2]string{r.Node, r.Run} {
			add(r, "node %s run %s in a file of node %s run %s", r.Node, r.Run, id[0], id[1])
		}
		k := runKey{r.File, r.Run}
		if seqs[k] == nil {
			seqs[k] = map[uint64]*Record{}
		}
		if prev := seqs[k][r.Seq]; prev != nil {
			add(r, "seq %d also at %s", r.Seq, prev.Where())
		} else {
			seqs[k][r.Seq] = r
		}
		if r.Peer != nil && !addressPattern.MatchString(*r.Peer) {
			add(r, "peer %q is not a lower-case address", *r.Peer)
		}
		if r.DedupKey != "" && !hashPattern.MatchString(r.DedupKey) {
			add(r, "dedup_key %q is not a 32-byte hex value", r.DedupKey)
		}
		switch r.Type {
		case "frame":
			validateFrame(d, r, add, checked, &res.Payloads)
		case "outcome":
			if !slices.Contains(outcomeClasses, r.Outcome) {
				add(r, "outcome %q", r.Outcome)
			}
			if !slices.Contains(checkClasses, r.Check) {
				add(r, "check %q", r.Check)
			}
			if !slices.Contains(outcomeVias, r.Via) {
				add(r, "via %q", r.Via)
			}
		case "conn":
			if !slices.Contains(connEvents, r.Event) {
				add(r, "conn event %q", r.Event)
			}
		case "send_suppressed":
			if r.Cause != "" && !slices.Contains(causes, r.Cause) {
				add(r, "cause %q", r.Cause)
			}
		}
	}
	// References to received frames of the same run.
	for _, r := range d.Records {
		run := seqs[runKey{r.File, r.Run}]
		ref := func(field string, seq *uint64) {
			if seq == nil {
				return
			}
			f := run[*seq]
			if f == nil || f.Type != "frame" || f.Dir != "in" {
				add(r, "%s %d is not a received frame of the run", field, *seq)
			}
		}
		switch r.Type {
		case "outcome":
			ref("of", r.Of)
		case "frame":
			ref("relay_of", r.RelayOf)
		}
	}
	return res
}

func validateFrame(d *Dump, r *Record, add func(*Record, string, ...any), checked map[string]bool, payloads *int) {
	switch r.Dir {
	case "in":
		if !slices.Contains(frameOutcomes, r.Outcome) {
			add(r, "received frame with outcome %q", r.Outcome)
		}
		if r.Engine != "" && !slices.Contains(engineStates, r.Engine) {
			add(r, "engine %q", r.Engine)
		}
	case "out":
		if r.Has("outcome") {
			add(r, "sent frame with an outcome")
		}
		if r.Cause != "" && !slices.Contains(causes, r.Cause) {
			add(r, "cause %q", r.Cause)
		}
		if (r.Cause == "relay") != (r.RelayOf != nil) {
			add(r, "cause %q with relay_of %v", r.Cause, r.RelayOf)
		}
	default:
		add(r, "dir %q", r.Dir)
	}
	if !codePattern.MatchString(r.Code) {
		add(r, "code %q is not a hex string", r.Code)
	}
	if r.Payload == "" {
		return // a frame recorded without its bytes (too large)
	}
	if !sha256Pattern.MatchString(r.Payload) {
		add(r, "payload_sha256 %q", r.Payload)
		return
	}
	b, err := os.ReadFile(filepath.Join(d.Dir, payloadsDirName, r.Payload[:2], r.Payload))
	if err != nil {
		add(r, "payload file: %v", err)
		return
	}
	if !checked[r.Payload] {
		checked[r.Payload] = true
		*payloads++
		if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != r.Payload {
			add(r, "payload file %s has sha256 %x", r.Payload, s)
		}
	}
	if r.Size != nil && *r.Size != int64(len(b)) {
		add(r, "size %d, payload has %d bytes", *r.Size, len(b))
	}
	if k := keccak.DedupKey(b); r.DedupKey != "" && !strings.EqualFold(r.DedupKey, "0x"+hex.EncodeToString(k[:])) {
		add(r, "dedup_key %s, the payload's is 0x%x", r.DedupKey, k)
	}
}
