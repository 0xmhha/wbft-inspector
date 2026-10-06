// Package logs reads a node's JSON log lines as events, through the
// implementation profile the node's build publishes (wbft-log-profile/1,
// written by wbft's cmd/wbft-logprofile; its ID is wbft_nodeInfo.logProfile
// and NODE_START.log_profile). It is for a node whose event stream is not
// available: a line is matched to an event kind by its message and module,
// and its level must be the profile's.
//
// Events read from logs differ from an event stream (events.Event.FromLog):
// there is no monotonic time, the records a module's level dropped are
// missing without a gap, and node and run are not in the lines. The caller
// names the node; each file is one run.
package logs

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/0xmhha/wbft-inspector/internal/events"
)

// ProfileFormat is the profile layout this package reads.
const ProfileFormat = "wbft-log-profile/1"

// Profile maps log lines to event kinds.
type Profile struct {
	Format  string   `json:"format"`
	ID      string   `json:"id"`
	Keys    []string `json:"keys"`
	Entries []Entry  `json:"entries"`

	byLine  map[[2]string]Entry
	modules map[string]bool
}

// Entry is one line of the profile.
type Entry struct {
	Kind   string `json:"kind"`
	Module string `json:"module"`
	Level  string `json:"level"`
	Msg    string `json:"msg"`
}

// LoadProfile reads a profile file.
func LoadProfile(path string) (*Profile, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if p.Format != ProfileFormat {
		return nil, fmt.Errorf("%s: profile format %q, want %q", path, p.Format, ProfileFormat)
	}
	p.byLine, p.modules = map[[2]string]Entry{}, map[string]bool{}
	for _, e := range p.Entries {
		k := [2]string{e.Msg, e.Module}
		if _, dup := p.byLine[k]; dup {
			return nil, fmt.Errorf("%s: two entries for %q of %s", path, e.Msg, e.Module)
		}
		p.byLine[k] = e
		p.modules[e.Module] = true
	}
	return &p, nil
}

// levels are the level spellings of JSON lines by the profile's level
// names: slog's (key "level") and go-stablenet's log.JSONHandler (key
// "lvl", log.LevelString).
var levels = map[string]string{
	"DEBUG-4": "trace", "DEBUG": "debug", "INFO": "info", "WARN": "warn", "ERROR": "error",
	"trace": "trace", "debug": "debug", "info": "info", "warn": "warn", "error": "error",
}

// lineKeys are the keys of a log line that are not the record's fields.
var lineKeys = map[string]bool{"time": true, "t": true, "level": true, "lvl": true, "msg": true, "module": true,
	"h": true, "r": true, "step": true}

// File is a log file of a node.
type File struct {
	Node string
	Path string
}

// Load reads log files with profile p into an event set: one run per file,
// input ids log-1, log-2, ... A line of a module the profile names that the
// profile does not map, or at another level, is an error; lines of other
// modules (an application's) are skipped.
func Load(p *Profile, files []File) (*events.Set, error) {
	s := &events.Set{Nodes: map[string]*events.NodeInfo{}, UnknownKinds: map[string]int{}}
	for i, lf := range files {
		id := fmt.Sprintf("log-%d", i+1)
		f, err := os.Open(lf.Path)
		if err != nil {
			return nil, err
		}
		in, run, err := read(p, s, f, id, lf.Path, lf.Node)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("%s: %w", lf.Path, err)
		}
		if len(run.Events) > 0 {
			run.Complete = complete(run)
			s.Add(in, run)
		} else {
			s.Inputs = append(s.Inputs, in)
		}
	}
	sort.SliceStable(s.Runs, func(i, j int) bool { return s.Runs[i].ID < s.Runs[j].ID })
	return s, nil
}

// consensusModules are the modules whose lines are the consensus events.
var consensusModules = []string{"consensus.round", "consensus.msg"}

// complete reports whether no record of the run can be missing: its first
// event is the log settings record, and every log settings record puts
// both consensus modules at trace.
func complete(r *events.Run) bool {
	if r.Events[0].Kind != "LOG_CONFIG" {
		return false
	}
	for _, e := range r.Events {
		if e.Kind != "LOG_CONFIG" {
			continue
		}
		var modules map[string]string
		_ = json.Unmarshal(e.F["modules"], &modules)
		for _, m := range consensusModules {
			lv, ok := modules[m]
			if !ok {
				lv = e.Str("level")
			}
			if lv != "trace" {
				return false
			}
		}
	}
	return true
}

func read(p *Profile, s *events.Set, r io.Reader, id, path, node string) (events.Input, *events.Run, error) {
	h := sha256.New()
	br := bufio.NewReaderSize(io.TeeReader(r, h), 1<<20)
	in := events.Input{ID: id, Path: path, Nodes: []string{node}}
	run := &events.Run{Node: node, ID: id, Input: id, FromLog: true}
	for no := 1; ; no++ {
		line, err := br.ReadBytes('\n')
		if len(bytes.TrimSpace(line)) > 0 {
			if e := parse(p, s, line, id, no); e != nil {
				e.Node, e.Run, e.Seq = node, id, uint64(len(run.Events))
				run.Events = append(run.Events, e)
				in.Records++
				if in.FirstWall == "" {
					in.FirstWall = e.TWall
				}
				in.LastWall = e.TWall
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return in, nil, err
		}
	}
	in.SHA256 = hex.EncodeToString(h.Sum(nil))
	return in, run, nil
}

// levelName is the profile's name of a level spelling, or "unknown".
func levelName(lv string) string {
	if n, ok := levels[lv]; ok {
		return n
	}
	return "unknown"
}

func parse(p *Profile, s *events.Set, line []byte, id string, no int) *events.Event {
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(line))
	d.UseNumber()
	if err := d.Decode(&m); err != nil {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: not a JSON object: %v", id, no, err))
		return nil
	}
	str := func(k string) string {
		var v string
		_ = json.Unmarshal(m[k], &v)
		return v
	}
	module, msg := str("module"), str("msg")
	if !p.modules[module] {
		return nil // another module's line
	}
	ent, ok := p.byLine[[2]string{msg, module}]
	if !ok {
		if module == "node" {
			return nil // node lines other than the log settings are not events
		}
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: %s line %q is not in profile %s", id, no, module, msg, p.ID))
		return nil
	}
	lv := str("level")
	if lv == "" {
		lv = str("lvl")
	}
	if levels[lv] != ent.Level {
		s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: %s line at level %q (%s), the profile has %s", id, no, ent.Kind, lv, levelName(lv), ent.Level))
		return nil
	}
	e := &events.Event{Input: id, Line: no, Kind: ent.Kind, Src: "log", FromLog: true, F: map[string]json.RawMessage{}}
	if e.TWall = str("time"); e.TWall == "" {
		e.TWall = str("t")
	}
	if _, ok := m["h"]; ok {
		e.View = &events.View{Seq: str("h"), Round: str("r")}
		if e.View.SeqBig() == nil || e.View.RoundBig() == nil {
			s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: malformed view h=%s r=%s", id, no, m["h"], m["r"]))
			return nil
		}
	}
	if raw, ok := m["step"]; ok {
		var st uint64
		if json.Unmarshal(raw, &st) != nil {
			s.Errors = append(s.Errors, fmt.Sprintf("%s:%d: malformed step %s", id, no, raw))
			return nil
		}
		e.Step = &st
	}
	for k, raw := range m {
		if !lineKeys[k] {
			e.F[k] = raw
		}
	}
	// The log settings line writes the event's "level" as "base_level":
	// "level" is the line's own level.
	if raw, ok := e.F["base_level"]; ok && e.Kind == "LOG_CONFIG" {
		e.F["level"] = raw
		delete(e.F, "base_level")
	}
	return e
}
