package frames

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const ownFixture = "../../testdata/frames/own-input"

func copyOwnFixture(t *testing.T) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(ownFixture, func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(ownFixture, path)
		if err != nil {
			return err
		}
		if e.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0700)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestOwnInputProducerFixture(t *testing.T) {
	d, err := Load(ownFixture)
	if err != nil {
		t.Fatal(err)
	}
	res := Validate(d)
	if len(res.Problems) != 0 {
		t.Fatal(res.Problems)
	}
	if res.Records["own_input"] != 1 || res.Records["outcome"] != 1 || res.Records["frame"] != 1 || res.Payloads != 1 {
		t.Fatal(res)
	}
}

func TestOwnInputRejectsUnprovedProvenance(t *testing.T) {
	for _, name := range []string{"wrong-engine", "wrong-step", "peer-input", "wrong-peer", "wrong-key", "wrong-code", "no-payload", "null-size", "no-position", "zero-offset", "zero-generation", "missing-input", "wrong-outcome", "unaccepted", "both-sources", "not-relay", "wrong-run", "wrong-node", "reversed-order", "loss", "bad-signature", "other-signer", "duplicate-field"} {
		t.Run(name, func(t *testing.T) {
			dir := copyOwnFixture(t)
			editLines(t, dir, func(_ int, r map[string]any) map[string]any {
				typ := r["type"]
				if typ == "own_input" {
					switch name {
					case "peer-input":
						r["via"] = "peer"
					case "wrong-peer":
						r["peer"] = "0xbb00000000000000000000000000000000000000"
					case "wrong-key":
						r["dedup_key"] = "0x" + strings.Repeat("0", 64)
					case "no-payload":
						delete(r, "payload_sha256")
					case "null-size":
						r["size"] = nil
					case "no-position":
						delete(r, "journal_offset")
					case "zero-offset":
						r["journal_offset"] = 0
					case "zero-generation":
						r["engine_run"] = 0
					case "missing-input":
						return nil
					case "wrong-run":
						r["run"] = "different"
					case "wrong-node":
						r["node"] = "0xbb00000000000000000000000000000000000000"
					case "reversed-order":
						r["seq"] = 1
					}
				}
				if typ == "outcome" {
					switch name {
					case "wrong-engine":
						r["engine_run"] = 2
					case "wrong-step":
						r["step"] = 8
					case "wrong-outcome":
						r["via"] = "direct"
					case "unaccepted":
						r["outcome"] = "IGNORE"
					case "reversed-order":
						r["input_of"] = 1
					}
				}
				if typ == "frame" {
					switch name {
					case "wrong-code":
						r["code"] = "0x14"
					case "both-sources":
						r["relay_of"] = 99
					case "not-relay":
						r["cause"] = "broadcast"
					}
				}
				if name == "other-signer" {
					r["node"] = "0xbb00000000000000000000000000000000000000"
					if typ == "own_input" || typ == "outcome" {
						r["peer"] = r["node"]
					}
				}
				return r
			})
			if name == "loss" {
				p := filepath.Join(dir, "frames-own-fixture.jsonl")
				raw, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				d, err := Load(dir)
				if err != nil {
					t.Fatal(err)
				}
				r := d.Records[0]
				line, err := json.Marshal(map[string]any{"v": 1, "type": "dropped", "seq": 9, "node": r.Node, "run": r.Run, "t_wall": r.TWall, "t_mono_ns": r.TMono, "count": 1})
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(p, append(raw, append(line, '\n')...), 0600); err != nil {
					t.Fatal(err)
				}
			}

			if name == "bad-signature" {
				d, err := Load(dir)
				if err != nil {
					t.Fatal(err)
				}
				var body []byte
				for _, r := range d.Records {
					if r.Type == "own_input" {
						body, err = d.Payload(r)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				body[len(body)-1] = 9
				sum := sha256.Sum256(body)
				sha := hex.EncodeToString(sum[:])
				key := keccak.DedupKey(body)
				if err := os.MkdirAll(filepath.Join(dir, "payloads", sha[:2]), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "payloads", sha[:2], sha), body, 0600); err != nil {
					t.Fatal(err)
				}
				editLines(t, dir, func(_ int, r map[string]any) map[string]any {
					if r["type"] != "conn" {
						r["dedup_key"] = "0x" + hex.EncodeToString(key[:])
						if r["type"] != "outcome" {
							r["payload_sha256"] = sha
						}
					}
					return r
				})
			}
			if name == "duplicate-field" {
				p := filepath.Join(dir, "frames-own-fixture.jsonl")
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				s := strings.Replace(string(b), `"input_of":5`, `"input_of":4,"input_of":5`, 1)
				if s == string(b) {
					t.Fatal("missing mutation target")
				}
				if err = os.WriteFile(p, []byte(s), 0600); err != nil {
					t.Fatal(err)
				}
			}
			d, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			if res := Validate(d); len(res.Problems) == 0 {
				b, _ := json.Marshal(d.Records)
				t.Fatal("unproved evidence accepted", name, string(b))
			}
		})
	}
}

func TestOwnInputRejectsAmbiguousWitnesses(t *testing.T) {
	for _, name := range []string{"same-engine-step", "same-bytes-new-engine", "same-source-position", "two-outcomes"} {
		t.Run(name, func(t *testing.T) {
			dir := copyOwnFixture(t)
			p := filepath.Join(dir, "frames-own-fixture.jsonl")
			raw, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			var input, outcome map[string]any
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var r map[string]any
				if err = json.Unmarshal([]byte(line), &r); err != nil {
					t.Fatal(err)
				}
				switch r["type"] {
				case "own_input":
					input = r
				case "outcome":
					outcome = r
				}
			}
			outcome["seq"] = 6
			if name == "two-outcomes" {
				outcome["seq"] = 1
			} else {
				input["seq"] = 7
				outcome["input_of"] = 7
				switch name {
				case "same-bytes-new-engine":
					input["engine_run"] = 2
					outcome["engine_run"] = 2
					input["journal_offset"] = 1000
				case "same-engine-step":
					input["journal_offset"] = 1000
				case "same-source-position":
					input["step"] = 8
					outcome["step"] = 8
				}
			}
			addition, err := json.Marshal(outcome)
			if err != nil {
				t.Fatal(err)
			}
			raw = append(raw, append(addition, '\n')...)
			if name != "two-outcomes" {
				addition, err = json.Marshal(input)
				if err != nil {
					t.Fatal(err)
				}
				raw = append(raw, append(addition, '\n')...)
			}
			if err = os.WriteFile(p, raw, 0600); err != nil {
				t.Fatal(err)
			}
			d, err := Load(dir)
			if err != nil {
				t.Fatal(err)
			}
			res := Validate(d)
			if len(res.Problems) == 0 {
				t.Fatal("ambiguous provenance accepted", name)
			}
		})
	}
}
