package headers

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/rpc"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

func config(t *testing.T) *params.Config {
	t.Helper()
	raw, err := os.ReadFile("testdata/config.json")
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := params.ParseGenesis(raw)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
func fixture(t *testing.T, n uint64) *header.Header {
	t.Helper()
	s := &Source{Context: context.Background(), Blocks: "testdata"}
	h, err := s.Read(n)
	if err != nil {
		t.Fatal(err)
	}
	return h
}
func TestIndependentJSONAndHash(t *testing.T) {
	for n := 0; n < 5; n++ {
		raw, err := os.ReadFile(fmt.Sprintf("testdata/%d.json", n))
		if err != nil {
			t.Fatal(err)
		}
		encoded, reported, err := JSONHeader(raw)
		if err != nil {
			t.Fatal(err)
		}
		h, err := header.Decode(encoded)
		if err != nil || h.Hash() != reported || fixture(t, uint64(n)).Hash() != reported {
			t.Fatal(n, h, err)
		}
	}
	raw, err := os.ReadFile("testdata/1.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	m["gasUsed"] = "0x00"
	bad, _ := json.Marshal(m)
	if _, _, err := JSONHeader(bad); err == nil {
		t.Fatal("noncanonical RPC quantity accepted")
	}
}
func TestEveryContentPredicateHasAFailingMutation(t *testing.T) {
	h := fixture(t, 1)
	cfg := config(t)
	fields, err := rlp.Items(RawFields(h))
	if err != nil {
		t.Fatal(err)
	}
	original := make([][]byte, len(fields))
	for i, f := range fields {
		original[i] = f.Raw
	}
	for _, p := range Predicates(h, cfg) {
		if !p.Valid || p.Unknown != "" {
			t.Fatal(p)
		}
	}
	cases := []struct {
		id     string
		change func([][]byte) [][]byte
	}{
		{"WBFT-HDR-011", func(f [][]byte) [][]byte { f[7] = rlp.EncodeUint(2); return f }},
		{"SNET-BHDR-001", func(f [][]byte) [][]byte { f[1] = rlp.EncodeBytes(make([]byte, 32)); return f }},
		{"SNET-BHDR-002", func(f [][]byte) [][]byte {
			f[9] = rlp.EncodeBytes(new(big.Int).Lsh(big.NewInt(1), 63).Bytes())
			return f
		}},
		{"SNET-BHDR-004", func(f [][]byte) [][]byte { return append(f, rlp.EncodeBytes(make([]byte, 32))) }},
		{"SNET-BHDR-006", func(f [][]byte) [][]byte { return append(f, rlp.EncodeBytes(make([]byte, 32)), rlp.EncodeUint(0)) }},
		{"SNET-BHDR-007", func(f [][]byte) [][]byte {
			limit, _ := fields[9].Uint()
			f[10] = rlp.EncodeBytes(new(big.Int).Add(limit, big.NewInt(1)).Bytes())
			return f
		}},
		{"WBFT-ENC-021", func(f [][]byte) [][]byte { f[12] = rlp.EncodeBytes(rlp.EncodeList()); return f }},
		{"WBFT-HDR-014", func(f [][]byte) [][]byte {
			addr := make([]byte, 20)
			addr[19] = 1
			f[2] = rlp.EncodeBytes(addr)
			return f
		}},
	}
	for _, tc := range cases {
		t.Run(tc.id, func(t *testing.T) {
			changed := tc.change(append([][]byte{}, original...))
			mutant, err := header.Decode(rlp.EncodeList(changed...))
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, p := range Predicates(mutant, cfg) {
				if p.Requirement == tc.id {
					found = true
					if p.Valid || p.Unknown != "" {
						t.Fatalf("mutation not detected: %+v", p)
					}
				}
			}
			if !found {
				t.Fatal("predicate missing")
			}
		})
	}
}
func TestCacheReplayAndIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var requests []struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&requests); err != nil {
			t.Error(err)
		}
		replies := []map[string]any{}
		for _, q := range requests {
			var result json.RawMessage
			switch q.Method {
			case "eth_chainId":
				result = json.RawMessage(`"0x205b"`)
			case "eth_getBlockByNumber":
				var n string
				_ = json.Unmarshal(q.Params[0], &n)
				index, _ := strconv.ParseUint(n[2:], 16, 64)
				var err error
				result, err = os.ReadFile(fmt.Sprintf("testdata/%d.json", index))
				if err != nil {
					result = json.RawMessage("null")
				}
			default:
				replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "error": map[string]any{"code": -32601, "message": "unavailable"}})
				continue
			}
			replies = append(replies, map[string]any{"jsonrpc": "2.0", "id": q.ID, "result": result})
		}
		_ = json.NewEncoder(w).Encode(replies)
	}))
	defer server.Close()
	cache := t.TempDir()
	client, _ := rpc.New(server.URL, 5)
	client.Interval = 0
	live := &Range{Source: &Source{Context: context.Background(), Client: client, Cache: cache}, From: 1, To: 3, Node: "a", Input: "in-1"}
	if err := live.Prepare(); err != nil {
		t.Fatal(err)
	}
	first, err := live.Analyze(config(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Findings) == 0 {
		t.Fatal("known late seal fixtures produced no observation")
	}
	for _, f := range first.Findings {
		if f.Kind != "late_seal" {
			continue
		}
		for i := 0; i < len(f.Evidence); i += 2 {
			previous, own := f.Evidence[i], f.Evidence[i+1]
			n, _ := strconv.ParseUint(own.Number, 10, 64)
			addresses, err := live.Validators(n, config(t))
			if err != nil {
				t.Fatal(err)
			}
			index := -1
			for j, a := range addresses {
				if a == own.Address {
					index = j
				}
			}
			current, _ := live.Source.Read(n)
			child, _ := live.Source.Read(n + 1)
			x, _ := current.Extra()
			cx, _ := child.Extra()
			observed, proof := x.Prepared, cx.PrevPrepared
			if strings.Contains(own.Field, "committed") {
				observed, proof = x.Committed, cx.PrevCommitted
			}
			if index < 0 || previous.Address != own.Address || header.Included(observed, index) || !header.Included(proof, index) {
				t.Fatal("late observation contradicts the header copies", f)
			}
		}
	}

	offline := &Range{Source: &Source{Context: context.Background(), Cache: cache, Offline: true}, From: 1, To: 3, Node: "a", Input: "in-1"}
	if err := offline.Prepare(); err != nil {
		t.Fatal(err)
	}
	second, err := offline.Analyze(config(t))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) || live.GenesisHash != offline.GenesisHash || offline.ChainID != "8283" {
		t.Fatal("cache replay differs", string(a), string(b))
	}
	wrong := &Range{Source: &Source{Context: context.Background(), Cache: cache, Offline: true}, From: 1, To: 3, Node: "other"}
	if err := wrong.Prepare(); err == nil {
		t.Fatal("another node reused the copy cache")
	}
	p := filepath.Join(cache, "00000000000000000001.header.rlp")
	raw, _ := os.ReadFile(p)
	raw[len(raw)-1] ^= 1
	_ = os.WriteFile(p, raw, 0600)
	if _, err := (&Source{Cache: cache, Offline: true}).Read(1); err == nil {
		t.Fatal("corrupt cached header accepted")
	}
}
func TestEpochRotationAndNilNormalization(t *testing.T) {
	cfg := config(t)
	for n, want := range map[uint64]uint64{0: 0, 139: 0, 140: 140, 141: 140, 279: 140} {
		got, err := LastEpoch(cfg, n)
		if err != nil || got != want {
			t.Fatal(n, got, err)
		}
	}
	cfg.Transitions = []params.Transition{{Block: big.NewInt(17), EpochLength: 3}}
	if n, err := LastEpoch(cfg, 23); err != nil || n != 23 {
		t.Fatal(n, err)
	}
	addresses := []string{"a", "b", "c"}
	if Proposer(addresses, "b", 0, 0) != "c" || Proposer(addresses, "b", 0, 1) != "b" || Proposer(addresses, "0x0000000000000000000000000000000000000000", 1, 0) != "b" {
		t.Fatal("rotation differs")
	}
	h := fixture(t, 1)
	fields, _ := rlp.Items(RawFields(h))
	items := make([][]byte, len(fields))
	for i, f := range fields {
		items[i] = f.Raw
	}
	x, _ := rlp.Items(fields[12].Content)
	xs := make([][]byte, len(x))
	for i, f := range x {
		xs[i] = f.Raw
	}
	xs[3] = rlp.EncodeBytes(nil)
	xs[4] = rlp.EncodeBytes(nil)
	xs[9] = rlp.EncodeBytes(nil)
	items[12] = rlp.EncodeBytes(rlp.EncodeList(xs...))
	normalized, err := header.Decode(rlp.EncodeList(items...))
	if err != nil || normalized.Hash() != h.Hash() {
		t.Fatal(normalized, err)
	}
	decoded, _ := hex.DecodeString(h.Hash()[2:])
	if len(decoded) != 32 {
		t.Fatal("wrong hash width")
	}
}
