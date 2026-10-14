// Package observations reads runtime sidecars without treating them as native
// engine events or evidence of remote delivery.
package observations

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const MaxBytes = 64 << 20
const MaxRecords = 100000

type Config struct {
	Address                   string
	Height                    string
	RequestTimeoutMS          string
	BlockPeriodSeconds        string
	Epoch                     string
	AllowedFutureBlockSeconds string
	MaxRequestTimeoutSeconds  string
	ProposerPolicy            string
	Transitions               uint64
	SystemContractUpgrades    uint64
}
type Record struct {
	ParentID      uint64  `json:"parent_id,omitempty"`
	Line          int     `json:"line"`
	V             int     `json:"v"`
	Type          string  `json:"type"`
	Node          string  `json:"node"`
	Run           string  `json:"run"`
	Seq           uint64  `json:"seq"`
	Wall          string  `json:"t_wall"`
	Mono          uint64  `json:"t_mono_ns"`
	Config        *Config `json:"config,omitempty"`
	ID            uint64  `json:"id,omitempty"`
	Operation     string  `json:"operation,omitempty"`
	Stage         string  `json:"stage,omitempty"`
	Height        string  `json:"height,omitempty"`
	Hash          string  `json:"hash,omitempty"`
	Count         uint64  `json:"count,omitempty"`
	Result        string  `json:"result,omitempty"`
	Index         uint64  `json:"index,omitempty"`
	EngineStopped *bool   `json:"engine_stopped,omitempty"`
	Dropped       uint64  `json:"dropped,omitempty"`
}
type Call struct {
	ID          string `json:"id"`
	Operation   string `json:"operation"`
	StartLine   int    `json:"start_line"`
	EndLine     int    `json:"end_line"`
	Nanoseconds string `json:"nanoseconds"`
	Result      string `json:"result"`
	Height      string `json:"height"`
	Hash        string `json:"hash"`
}
type Result struct {
	Startups                           []Record `json:"startups"`
	Engines                            []Engine `json:"engines"`
	Tasks                              []Task   `json:"tasks"`
	Format                             string   `json:"format"`
	Node                               string   `json:"node"`
	Run                                string   `json:"run"`
	Records                            []Record `json:"records"`
	Calls                              []Call   `json:"calls"`
	SequenceGaps                       string   `json:"sequence_gaps"`
	Unavailable                        []string `json:"unavailable"`
	CaptureComplete                    bool     `json:"capture_complete"`
	RuntimeModelComplete               bool     `json:"runtime_model_complete"`
	DeliveryCoverageProven             bool     `json:"delivery_coverage_proven"`
	ApplicationRequestCompletionProven bool     `json:"application_request_completion_proven"`
}

var address = regexp.MustCompile(`^0x[0-9a-f]{40}$`)
var hash = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var identity = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)

// object refuses duplicate keys recursively before decoding closed fields.
func object(d *json.Decoder) error {
	t, e := d.Token()
	if e != nil {
		return e
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				key, ok := k.(string)
				if !ok || seen[key] {
					return errors.New("duplicate or invalid key")
				}
				seen[key] = true
				if e = object(d); e != nil {
					return e
				}
			}
		case '[':
			for d.More() {
				if e = object(d); e != nil {
					return e
				}
			}
		default:
			return errors.New("invalid delimiter")
		}
		_, e = d.Token()
		return e
	}
	return nil
}
func fields(raw []byte, want []string) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if e := object(d); e != nil {
		return nil, e
	}
	if _, e := d.Token(); e != io.EOF {
		return nil, errors.New("trailing input")
	}
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || m == nil || len(m) != len(want) {
		return nil, errors.New("invalid fields")
	}
	for _, k := range want {
		v, ok := m[k]
		if !ok || bytes.Equal(v, []byte("null")) {
			return nil, errors.New("missing or null field")
		}
	}
	return m, nil
}
func decode(raw []byte, line int) (Record, error) {
	var kind struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &kind) != nil {
		return Record{}, errors.New("invalid record")
	}
	keys := []string{"v", "type", "node", "run", "seq", "t_wall", "t_mono_ns"}
	switch kind.Type {
	case "runtime_start":
		keys = append(keys, "config")
	case "runtime_stop":
		keys = append(keys, "result")
	case "runtime_close":
		keys = append(keys, "engine_stopped")
	case "operation_start":
		keys = append(keys, "id", "operation", "height", "hash", "count")
	case "operation_end":
		keys = append(keys, "id", "result", "height", "hash", "index")
	case "operation_stage":
		keys = append(keys, "id", "stage", "height", "hash")
	case "engine_config":
		keys = append(keys, "id", "parent_id", "config")
	case "engine_created":
		keys = append(keys, "id", "parent_id")
	case "engine_stage":
		keys = append(keys, "id", "parent_id", "stage")
	case "capture_end":
		keys = append(keys, "dropped")
	default:
		return Record{}, errors.New("unknown record type")
	}
	m, e := fields(raw, keys)
	if e != nil {
		return Record{}, e
	}
	var r Record
	if json.Unmarshal(raw, &r) != nil {
		return r, errors.New("invalid field type")
	}
	r.Line = line
	if r.V != 1 || !address.MatchString(r.Node) || !identity.MatchString(r.Run) || r.Mono > (^uint64(0)>>1) {
		return r, errors.New("invalid identity or clock")
	}
	if _, e = time.Parse(time.RFC3339Nano, r.Wall); e != nil || !strings.HasSuffix(r.Wall, "Z") {
		return r, errors.New("invalid wall clock")
	}
	switch r.Type {
	case "runtime_start", "engine_config":
		if r.Type == "engine_config" && (r.ID == 0 || r.ParentID == 0) {
			return r, errors.New("invalid engine configuration identity")
		}
		ckeys := []string{"Address", "Height", "RequestTimeoutMS", "BlockPeriodSeconds", "Epoch", "AllowedFutureBlockSeconds", "MaxRequestTimeoutSeconds", "ProposerPolicy", "Transitions", "SystemContractUpgrades"}
		if _, e = fields(m["config"], ckeys); e != nil {
			return r, e
		}
		c := r.Config
		if c == nil || strings.ToLower(c.Address) != r.Node {
			return r, errors.New("config identity mismatch")
		}
		for _, v := range []string{c.Height, c.RequestTimeoutMS, c.BlockPeriodSeconds, c.Epoch, c.AllowedFutureBlockSeconds, c.MaxRequestTimeoutSeconds} {
			if !decimal.MatchString(v) {
				return r, errors.New("invalid scalar config")
			}
		}
		if c.ProposerPolicy != "" && !decimal.MatchString(c.ProposerPolicy) {
			return r, errors.New("invalid proposer policy")
		}
	case "engine_created", "engine_stage":
		if r.ID == 0 || r.Type == "engine_created" && r.ParentID == 0 {
			return r, errors.New("invalid engine identity")
		}
		if r.Type == "engine_stage" && !engineStage(r.Stage) {
			return r, errors.New("invalid engine stage")
		}
	case "runtime_close":
		if r.EngineStopped == nil || *r.EngineStopped {
			return r, errors.New("close does not establish engine stop")
		}
	case "runtime_stop":
		if r.Result != "ok" && r.Result != "error" {
			return r, errors.New("invalid runtime result")
		}
	case "operation_start", "operation_end", "operation_stage":
		if r.ID == 0 || r.Height != "" && !decimal.MatchString(r.Height) || r.Hash != "" && !hash.MatchString(r.Hash) {
			return r, errors.New("invalid operation identity")
		}
		if r.Type == "operation_stage" {
			if r.Height == "" || r.Hash == "" {
				return r, errors.New("task stage identity unavailable")
			}
			switch r.Stage {
			case "task_offer", "task_sent", "task_received", "task_duplicate", "task_skipped", "task_abandoned", "seal_enter", "seal_return", "seal_unsupported", "request_post_enter", "request_post_return", "seal_result", "seal_cancel":
			default:
				return r, errors.New("invalid task stage")
			}
		}
		if r.Type == "operation_start" {
			switch r.Operation {
			case "backend_start", "backend_stop", "worker_commit_work", "insert_chain", "write_block_and_set_head":
			default:
				return r, errors.New("invalid operation")
			}
		}
		if r.Type == "operation_end" {
			switch r.Result {
			case "ok", "error", "returned", "syncing", "missing_etherbase", "prepare_error", "new_head_discard", "commit_error":
			default:
				return r, errors.New("invalid operation result")
			}
		}
	}
	return r, nil
}

// Read preserves known call boundaries and missing evidence separately. It
// never converts complete capture bytes into a complete execution model.
func Read(input io.Reader) (Result, error) {
	out := Result{Format: "wbft-tap-observations/1", Records: []Record{}, Startups: []Record{}, Calls: []Call{}, Unavailable: []string{}}
	limited := &io.LimitedReader{R: input, N: MaxBytes + 1}
	scan := bufio.NewScanner(limited)
	scan.Buffer(make([]byte, 65536), 65537)
	starts, ends := map[uint64]Record{}, map[uint64]Record{}
	var previous, gaps uint64
	var final *Record
	runtimeStart, stop := false, false
	for scan.Scan() {
		line := len(out.Records) + 1
		if line > MaxRecords {
			return out, errors.New("observation record limit exceeded")
		}
		r, e := decode(scan.Bytes(), line)
		if e != nil {
			return out, fmt.Errorf("invalid observation at line %d", line)
		}
		if final != nil {
			return out, errors.New("record after capture end")
		}
		if line == 1 {
			out.Node, out.Run = r.Node, r.Run
			gaps = r.Seq
		} else {
			if r.Node != out.Node || r.Run != out.Run || r.Seq <= previous {
				return out, errors.New("observation identity or sequence changed")
			}
			delta := r.Seq - previous - 1
			if gaps > ^uint64(0)-delta {
				return out, errors.New("gap overflow")
			}
			gaps += delta
		}
		previous = r.Seq
		switch r.Type {
		case "runtime_start":
			out.Startups = append(out.Startups, r)
			runtimeStart = true
		case "runtime_stop", "runtime_close":
			stop = true
		case "operation_start":
			if _, ok := starts[r.ID]; ok {
				return out, errors.New("duplicate operation start")
			}
			starts[r.ID] = r
		case "operation_end":
			if _, ok := ends[r.ID]; ok {
				return out, errors.New("duplicate operation end")
			}
			ends[r.ID] = r
		case "capture_end":
			copy := r
			final = &copy
		}
		out.Records = append(out.Records, r)
	}
	if scan.Err() != nil || limited.N <= 0 {
		return out, errors.New("observation input limit or read failure")
	}
	out.SequenceGaps = strconv.FormatUint(gaps, 10)
	if !runtimeStart {
		out.Unavailable = append(out.Unavailable, "runtime_start_absent")
	}
	if !stop {
		out.Unavailable = append(out.Unavailable, "runtime_stop_or_close_absent")
	}
	if final == nil {
		out.Unavailable = append(out.Unavailable, "capture_end_absent")
	} else {
		if final.Dropped != gaps {
			return out, errors.New("gaps differ from dropped count")
		}
		if final.Dropped > 0 {
			out.Unavailable = append(out.Unavailable, "records_dropped")
		}
	}
	for _, start := range out.Records {
		if start.Type != "operation_start" {
			continue
		}
		end, ok := ends[start.ID]
		if !ok {
			out.Unavailable = append(out.Unavailable, "operation_end_absent")
			continue
		}
		if end.Line <= start.Line || end.Mono < start.Mono {
			return out, errors.New("operation interval reversed")
		}
		out.Calls = append(out.Calls, Call{ID: strconv.FormatUint(start.ID, 10), Operation: start.Operation, StartLine: start.Line, EndLine: end.Line, Nanoseconds: strconv.FormatUint(end.Mono-start.Mono, 10), Result: end.Result, Height: end.Height, Hash: end.Hash})
	}
	out.Tasks = []Task{}
	groups := map[uint64][]Record{}
	order := []uint64{}
	for _, r := range out.Records {
		if r.Type != "operation_stage" {
			continue
		}
		start, ok := starts[r.ID]
		if !ok || start.Operation != "worker_commit_work" || start.Line >= r.Line {
			return out, errors.New("task stage without exact worker call")
		}
		if len(groups[r.ID]) == 0 {
			order = append(order, r.ID)
		}
		groups[r.ID] = append(groups[r.ID], r)
	}
	for _, id := range order {
		task := projectTask(id, groups[id])
		start := starts[id]
		end, ok := ends[id]
		task.StartLine = start.Line
		task.EndLine = end.Line
		if !ok {
			task.State = "incomplete"
		} else if (start.Height != "" && start.Height != groups[id][0].Height) || (end.Height != "" && end.Height != groups[id][0].Height) || (start.Hash != "" && start.Hash != groups[id][0].Hash) || (end.Hash != "" && end.Hash != groups[id][0].Hash) {
			task.State = "ambiguous"
		}
		out.Tasks = append(out.Tasks, task)
	}
	if len(out.Tasks) > 0 {
		out.Format = "wbft-tap-observations/2"
	}
	for id := range ends {
		if _, ok := starts[id]; !ok {
			out.Unavailable = append(out.Unavailable, "operation_start_absent")
		}
	}
	out.CaptureComplete = len(out.Unavailable) == 0
	var engineError error
	out.Engines, engineError = projectEngines(out.Records, starts, ends, out.CaptureComplete)
	if engineError != nil {
		return out, engineError
	}
	if len(out.Engines) > 0 {
		out.Format = "wbft-tap-observations/3"
	}
	for _, engine := range out.Engines {
		if len(engine.Configs) > 0 {
			out.Format = "wbft-tap-observations/4"
			break
		}
	}
	return out, nil
}
