// Package headers supplies immutable header inputs for independent spec checks.
package headers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/rpc"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

type Source struct {
	Context       context.Context
	Client        *rpc.Client
	Cache, Blocks string
	Offline       bool
	Err           error
	cached        map[uint64]*header.Header
	order         []uint64
}
type Range struct {
	Capabilities         []rpc.Capability
	Source               *Source
	From, To             uint64
	Node, Input          string
	ChainID, GenesisHash string
}

func (s *Source) remember(n uint64, h *header.Header) {
	if s.cached == nil {
		s.cached = map[uint64]*header.Header{}
	}
	if s.cached[n] == nil {
		s.order = append(s.order, n)
	}
	s.cached[n] = h
	for len(s.order) > 1024 {
		delete(s.cached, s.order[0])
		s.order = s.order[1:]
	}
}
func (s *Source) Read(n uint64) (*header.Header, error) {
	if h := s.cached[n]; h != nil {
		return h, nil
	}
	var raw []byte
	var err error
	if s.Blocks != "" {
		raw, err = os.ReadFile(filepath.Join(s.Blocks, fmt.Sprintf("%012d.rlp", n)))
		if err != nil {
			return nil, err
		}
		items, e := rlp.Items(raw)
		if e != nil || len(items) < 3 {
			return nil, errors.New("block must be a header/body list")
		}
		raw = items[0].Raw
	} else if s.Cache != "" {
		raw, err = s.cacheBytes(n)
	}
	if len(raw) > 0 && err == nil {
		h, err := header.Decode(raw)
		if err != nil {
			return nil, err
		}
		if h.Number.Uint64() != n {
			return nil, errors.New("cache canonical index differs from full header number")
		}
		s.remember(n, h)
		return h, nil
	}
	if s.Offline || s.Client == nil {
		return nil, fmt.Errorf("header %d unavailable offline", n)
	}
	if err = s.Prefetch(n, n); err != nil {
		return nil, err
	}
	return s.cached[n], nil
}
func (s *Source) Prefetch(from, to uint64) error {
	if to < from || to-from >= 100 {
		return errors.New("header batches contain 1..100 indices")
	}
	if s.Client == nil || s.Offline || s.Blocks != "" {
		for n := from; ; n++ {
			if _, err := s.Read(n); err != nil {
				return err
			}
			if n == to {
				break
			}
		}
		return nil
	}
	requests := []rpc.Request{}
	indices := []uint64{}
	for n := from; ; n++ {
		if s.cached[n] == nil {
			have := false
			if s.Cache != "" {
				raw, err := s.cacheBytes(n)
				if err == nil {
					h, err := header.Decode(raw)
					if err != nil || h.Number.Uint64() != n {
						return fmt.Errorf("invalid cached header at %d", n)
					}
					s.remember(n, h)
					have = true
				}
			}
			if !have {
				requests = append(requests, rpc.Request{Method: "eth_getBlockByNumber", Params: []any{"0x" + strconv.FormatUint(n, 16), false}})
				indices = append(indices, n)
			}
		}
		if n == to {
			break
		}
	}
	if len(requests) == 0 {
		return nil
	}
	answers, err := s.Client.Batch(s.Context, requests)
	if err != nil {
		return err
	}
	for i, a := range answers {
		if a.Error != nil {
			return a.Error
		}
		raw, reported, err := JSONHeader(a.Result)
		if err != nil {
			return err
		}
		h, err := header.Decode(raw)
		if err != nil {
			return err
		}
		n := indices[i]
		if h.Number.Uint64() != n {
			return errors.New("RPC canonical index differs from full number")
		}
		if h.Hash() != reported {
			return fmt.Errorf("RPC header %d does not reproduce its reported hash", n)
		}
		s.remember(n, h)
		if s.Cache != "" {
			if err = os.MkdirAll(s.Cache, 0700); err != nil {
				return err
			}
			f, err := os.CreateTemp(s.Cache, ".header-*")
			if err != nil {
				return err
			}
			name := f.Name()
			if _, err = f.Write(raw); err != nil {
				_ = f.Close()
				_ = os.Remove(name)
				return err
			}
			if err = f.Close(); err != nil {
				_ = os.Remove(name)
				return err
			}
			if err = os.Rename(name, filepath.Join(s.Cache, fmt.Sprintf("%020d.header.rlp", n))); err != nil {
				_ = os.Remove(name)
				return err
			}
			sum := sha256.Sum256(raw)
			if err = os.WriteFile(filepath.Join(s.Cache, fmt.Sprintf("%020d.sha256", n)), []byte(hex.EncodeToString(sum[:])+"\n"), 0600); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Source) Get(n uint64) *header.Header {
	h, err := s.Read(n)
	if err != nil {
		s.Err = err
	}
	return h
}
func (s *Source) Endpoint() string {
	if s.Client == nil {
		return ""
	}
	u, err := url.Parse(s.Client.URL)
	if err != nil {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

type cacheManifest struct {
	Version      int              `json:"v"`
	ChainID      string           `json:"chain_id"`
	GenesisHash  string           `json:"genesis_hash"`
	Node         string           `json:"node"`
	Endpoint     string           `json:"endpoint"`
	Capabilities []rpc.Capability `json:"capabilities"`
}

func (r *Range) Prepare() error {
	if r.To < r.From || r.To == ^uint64(0) || r.To-r.From >= 1_000_000 {
		return errors.New("header range must contain 1..1000000 indices with room for a child")
	}
	var saved *cacheManifest
	if r.Source.Cache != "" {
		raw, err := os.ReadFile(filepath.Join(r.Source.Cache, "manifest.json"))
		if err == nil {
			if err = json.Unmarshal(raw, &saved); err != nil || saved == nil || saved.Version != 1 {
				return errors.New("invalid header cache manifest")
			}
			if saved.Node != r.Node {
				return errors.New("header cache belongs to another node copy")
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	g, err := r.Source.Read(0)
	if err != nil {
		return err
	}
	r.GenesisHash = g.Hash()
	if saved != nil {
		if saved.GenesisHash != r.GenesisHash {
			return errors.New("cached genesis differs from its manifest")
		}
		r.ChainID = saved.ChainID
	}
	if r.Source.Client != nil && !r.Source.Offline {
		var id string
		if err := r.Source.Client.Call(r.Source.Context, &id, "eth_chainId"); err != nil {
			return err
		}
		n, err := quantity(id, 0)
		if err != nil {
			return err
		}
		r.ChainID = n.String()
		// A cache does not turn a new endpoint into the original node or network.
		answers, err := r.Source.Client.Batch(r.Source.Context, []rpc.Request{{Method: "eth_getBlockByNumber", Params: []any{"0x0", false}}})
		if err != nil {
			return err
		}
		if answers[0].Error != nil {
			return answers[0].Error
		}
		raw, reported, err := JSONHeader(answers[0].Result)
		if err != nil {
			return err
		}
		fresh, err := header.Decode(raw)
		if err != nil {
			return err
		}
		if fresh.Hash() != reported || fresh.Hash() != r.GenesisHash {
			return errors.New("RPC genesis differs from the header cache")
		}
		if saved != nil && (saved.ChainID != r.ChainID || saved.Endpoint != r.Source.Endpoint()) {
			return errors.New("header cache belongs to another RPC source or chain")
		}
		caps, err := r.Source.Client.Capabilities(r.Source.Context)
		if err != nil {
			return err
		}
		manifest := cacheManifest{Version: 1, ChainID: r.ChainID, GenesisHash: r.GenesisHash, Node: r.Node, Endpoint: r.Source.Endpoint(), Capabilities: caps}
		r.Capabilities = caps
		if r.Source.Cache != "" {
			data, _ := json.Marshal(manifest)
			if err = os.WriteFile(filepath.Join(r.Source.Cache, "manifest.json"), append(data, '\n'), 0600); err != nil {
				return err
			}
		}
	} else if saved != nil {
		r.Capabilities = saved.Capabilities
	}
	return nil
}

func quantity(s string, bits int) (*big.Int, error) {
	if !strings.HasPrefix(s, "0x") || len(s) < 3 || (len(s) > 3 && s[2] == '0') {
		return nil, errors.New("invalid JSON hex quantity")
	}
	for _, c := range s[2:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return nil, errors.New("invalid JSON hex digit")
		}
	}
	n, ok := new(big.Int).SetString(s[2:], 16)
	if !ok || (bits > 0 && n.BitLen() > bits) {
		return nil, errors.New("JSON quantity exceeds its width")
	}
	return n, nil
}
func bytesOf(s string, size int) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("hex bytes require 0x")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil || (size >= 0 && len(b) != size) {
		return nil, errors.New("hex byte field has wrong size")
	}
	return b, nil
}

// JSONHeader rebuilds the Ethereum RLP list of A-03 ENC-070. The independent
// spec model reproduces its reported WBFT hash before it enters the cache.
func JSONHeader(data []byte) ([]byte, string, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, "", err
	}
	if fields == nil {
		return nil, "", errors.New("header unavailable")
	}
	names := []string{"parentHash", "sha3Uncles", "miner", "stateRoot", "transactionsRoot", "receiptsRoot", "logsBloom", "difficulty", "number", "gasLimit", "gasUsed", "timestamp", "extraData", "mixHash", "nonce", "baseFeePerGas", "withdrawalsRoot", "blobGasUsed", "excessBlobGas", "parentBeaconBlockRoot"}
	sizes := []int{32, 32, 20, 32, 32, 32, 256, -2, -2, -3, -3, -3, -1, 32, 8, -2, 32, -3, -3, 32}
	last := 14
	for i := 15; i < len(names); i++ {
		if raw := fields[names[i]]; len(raw) > 0 && string(raw) != "null" {
			last = i
		}
	}
	out := make([][]byte, last+1)
	for i, name := range names[:last+1] {
		raw := fields[name]
		if len(raw) == 0 || string(raw) == "null" {
			if i < 15 {
				return nil, "", fmt.Errorf("required header field %s missing", name)
			}
			out[i] = rlp.EncodeBytes(nil)
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil {
			return nil, "", err
		}
		if sizes[i] <= -2 {
			bits := 0
			if sizes[i] == -3 {
				bits = 64
			}
			n, err := quantity(value, bits)
			if err != nil {
				return nil, "", err
			}
			out[i] = rlp.EncodeBytes(n.Bytes())
		} else {
			b, err := bytesOf(value, sizes[i])
			if err != nil {
				return nil, "", err
			}
			out[i] = rlp.EncodeBytes(b)
		}
	}
	var hash string
	if err := json.Unmarshal(fields["hash"], &hash); err != nil {
		return nil, "", err
	}
	if _, err := bytesOf(hash, 32); err != nil {
		return nil, "", err
	}
	return rlp.EncodeList(out...), strings.ToLower(hash), nil
}

func (s *Source) cacheBytes(n uint64) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(s.Cache, fmt.Sprintf("%020d.header.rlp", n)))
	if err != nil {
		return nil, err
	}
	checksum, err := os.ReadFile(filepath.Join(s.Cache, fmt.Sprintf("%020d.sha256", n)))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if strings.TrimSpace(string(checksum)) != hex.EncodeToString(sum[:]) {
		return nil, errors.New("cached header checksum differs")
	}
	return raw, nil
}
