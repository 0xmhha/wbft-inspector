// Package rejections reads a node's rejected blocks and proposals (R-09):
// the records of `wbft_rejections`, either as the RPC response or as the
// node's store directory.
//
// A record is the JSON object
//
//	{"number": "12", "hash": "0x…", "step": "P3", "errorClass": "…",
//	 "path": "preprepare", "time": "2026-10-11T02:18:43.123Z"}
//
// with number a decimal string, hash 32 bytes in hex, path one of
// "preprepare", "sealed_locally", "imported", "synced" or "unknown", and step and
// errorClass empty when the node did not know them.
package rejections

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Record is one rejection.
type Record struct {
	Input string `json:"-"` // input id in a report
	Node  string `json:"-"`
	Line  int    `json:"-"` // 1-based record number in the input

	Number string `json:"number"`
	Hash   string `json:"hash"`
	Step   string `json:"step"`
	Class  string `json:"errorClass"`
	Path   string `json:"path"`
	Time   string `json:"time"`

	At time.Time `json:"-"` // Time parsed
}

// Set is the rejections of one node.
type Set struct {
	Node    string
	Path    string
	SHA256  string
	Records []*Record
	// Problems are the records that were left out, with the reason.
	Problems []string
}

// The files of the node's store, oldest first (wbft observe/rejection).
var storeFiles = []string{"rejections.prev.jsonl", "rejections.jsonl"}

// Load reads the rejections of node from path: a `wbft_rejections`
// response (a JSON array of records, or a JSON-RPC response object whose
// result is one), a file of JSON Lines records, or the node's store
// directory (with no file when the node rejected nothing).
func Load(node, path string) (*Set, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	var data [][]byte
	if st.IsDir() {
		for _, name := range storeFiles {
			b, err := os.ReadFile(filepath.Join(path, name))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				return nil, err
			}
			data = append(data, b)
		}
		// A node creates the directory when it starts; it holds no file
		// until the node rejects something.
	} else {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		data = append(data, b)
	}
	s := &Set{Node: strings.ToLower(node), Path: path}
	h := sha256.New()
	for _, b := range data {
		h.Write(b)
		if err := s.parse(b); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	s.SHA256 = hex.EncodeToString(h.Sum(nil))
	return s, nil
}

// SetInput sets the report input id of the set and its records.
func (s *Set) SetInput(id string) {
	for _, r := range s.Records {
		r.Input = id
	}
}

// parse reads a sequence of JSON values: records, arrays of records or
// JSON-RPC response objects.
func (s *Set) parse(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	for {
		var v json.RawMessage
		if err := dec.Decode(&v); errors.Is(err, io.EOF) {
			return nil
		} else if err != nil {
			return err
		}
		v = bytes.TrimSpace(v)
		switch {
		case len(v) > 0 && v[0] == '[':
			var items []json.RawMessage
			if err := json.Unmarshal(v, &items); err != nil {
				return err
			}
			for _, it := range items {
				s.add(it)
			}
		default:
			var resp struct {
				Result *json.RawMessage `json:"result"`
				Error  *json.RawMessage `json:"error"`
			}
			if err := json.Unmarshal(v, &resp); err != nil {
				s.add(v) // not an object: a problem of its own
				continue
			}
			if resp.Error != nil {
				return fmt.Errorf("the response is an error: %s", *resp.Error)
			}
			if resp.Result == nil {
				s.add(v)
				continue
			}
			var items []json.RawMessage
			if err := json.Unmarshal(*resp.Result, &items); err != nil {
				return fmt.Errorf("result: %w", err)
			}
			for _, it := range items {
				s.add(it)
			}
		}
	}
}

// add appends one record, or a problem when it is malformed.
func (s *Set) add(raw json.RawMessage) {
	n := len(s.Records) + len(s.Problems) + 1
	r := &Record{Node: s.Node, Line: n}
	bad := func(format string, a ...any) {
		s.Problems = append(s.Problems, fmt.Sprintf("record %d: ", n)+fmt.Sprintf(format, a...))
	}
	if err := json.Unmarshal(raw, r); err != nil {
		bad("%v", err)
		return
	}
	if v, ok := new(big.Int).SetString(r.Number, 10); !ok || v.Sign() < 0 {
		bad("number %q is not a decimal", r.Number)
		return
	}
	r.Hash = strings.ToLower(r.Hash)
	if b, err := hex.DecodeString(strings.TrimPrefix(r.Hash, "0x")); err != nil || len(b) != 32 || !strings.HasPrefix(r.Hash, "0x") {
		bad("hash %q is not 32 bytes in hex", r.Hash)
		return
	}
	switch r.Path {
	case "preprepare", "sealed_locally", "imported", "synced", "unknown":
	default:
		bad("path %q is not known", r.Path)
		return
	}
	t, err := time.Parse(time.RFC3339Nano, r.Time)
	if err != nil {
		bad("time %q: %v", r.Time, err)
		return
	}
	r.At = t
	s.Records = append(s.Records, r)
}
