// Package params is the consensus configuration of wbft-spec A-01 §6: the
// base parameters of the genesis section anzeon.wbft, the transitions of
// B-01, and config_at, the configuration that governs a height.
//
// The code follows the specification text, not an implementation.
package params

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
)

// WBFT is the genesis section anzeon.wbft. Pointer fields distinguish an
// absent value from an explicit 0 (WBFT-PARAM-051).
type WBFT struct {
	RequestTimeoutSeconds    uint64
	BlockPeriodSeconds       uint64
	EpochLength              uint64
	AllowedFutureBlockTime   uint64
	ProposerPolicy           *uint64
	MaxRequestTimeoutSeconds *uint64
}

// Transition changes parameters from Block on (B-01 §6). A zero
// RequestTimeoutSeconds, BlockPeriodSeconds or EpochLength leaves the
// current value; a present ProposerPolicy or MaxRequestTimeoutSeconds
// overrides it even when 0. AllowedFutureBlockTime is ignored.
type Transition struct {
	Block                    *big.Int
	RequestTimeoutSeconds    uint64
	BlockPeriodSeconds       uint64
	EpochLength              uint64
	AllowedFutureBlockTime   uint64
	ProposerPolicy           *uint64
	MaxRequestTimeoutSeconds *uint64
}

// Config is a base configuration with its transitions, sorted by block with
// a stable sort as the reference does when it creates the engine.
type Config struct {
	Base        WBFT
	Transitions []Transition
}

// New returns a configuration with the transitions sorted by block.
func New(base WBFT, ts []Transition) (*Config, error) {
	for i, t := range ts {
		if t.Block == nil {
			return nil, fmt.Errorf("params: transition %d has no block", i)
		}
	}
	sorted := append([]Transition(nil), ts...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Block.Cmp(sorted[j].Block) < 0 })
	return &Config{Base: base, Transitions: sorted}, nil
}

// Resolved is the configuration that governs one height.
type Resolved struct {
	RequestTimeoutMs         uint64  // request_timeout, milliseconds (uint64 arithmetic)
	BlockPeriodSeconds       uint64  // block_period
	Epoch                    uint64  // epoch
	ProposerPolicy           *uint64 // proposer policy identifier, nil when absent
	MaxRequestTimeoutSeconds uint64  // 0 when absent (no cap)
	AllowedFutureBlockTime   uint64  // from the base configuration only
}

// At is config_at(number) of A-01 §6.5 (WBFT-PARAM-050 .. WBFT-PARAM-052).
func (c *Config) At(number *big.Int) Resolved {
	r := Resolved{
		RequestTimeoutMs:       c.Base.RequestTimeoutSeconds * 1000, // uint64 wrap, WBFT-PARAM-052
		BlockPeriodSeconds:     c.Base.BlockPeriodSeconds,
		Epoch:                  c.Base.EpochLength,
		ProposerPolicy:         c.Base.ProposerPolicy,
		AllowedFutureBlockTime: c.Base.AllowedFutureBlockTime,
	}
	if c.Base.MaxRequestTimeoutSeconds != nil {
		r.MaxRequestTimeoutSeconds = *c.Base.MaxRequestTimeoutSeconds
	}
	for _, t := range c.Transitions {
		if t.Block.Cmp(number) > 0 {
			break
		}
		if t.RequestTimeoutSeconds != 0 {
			r.RequestTimeoutMs = t.RequestTimeoutSeconds * 1000
		}
		if t.BlockPeriodSeconds != 0 {
			r.BlockPeriodSeconds = t.BlockPeriodSeconds
		}
		if t.EpochLength != 0 {
			r.Epoch = t.EpochLength
		}
		if t.ProposerPolicy != nil {
			r.ProposerPolicy = t.ProposerPolicy
		}
		if t.MaxRequestTimeoutSeconds != nil {
			r.MaxRequestTimeoutSeconds = *t.MaxRequestTimeoutSeconds
		}
	}
	return r
}

// ParseGenesis reads the consensus part of a chain configuration: either a
// genesis file (its "config" object is used) or the configuration object
// itself, with the camel-case field names of the genesis file
// (anzeon.wbft.requestTimeoutSeconds, transitions[].block, ...).
func ParseGenesis(raw []byte) (*Config, error) {
	var top map[string]json.RawMessage
	if err := decode(raw, &top); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	if c, ok := top["config"]; ok {
		raw = c
	}
	var cc struct {
		Anzeon *struct {
			WBFT *wbftJSON `json:"wbft"`
		} `json:"anzeon"`
		Transitions []transitionJSON `json:"transitions"`
	}
	if err := decode(raw, &cc); err != nil {
		return nil, fmt.Errorf("params: %w", err)
	}
	if cc.Anzeon == nil || cc.Anzeon.WBFT == nil {
		return nil, fmt.Errorf("params: anzeon.wbft is missing")
	}
	base, err := cc.Anzeon.WBFT.toWBFT()
	if err != nil {
		return nil, err
	}
	var ts []Transition
	for i, t := range cc.Transitions {
		w, err := t.toWBFT()
		if err != nil {
			return nil, fmt.Errorf("params: transitions[%d]: %w", i, err)
		}
		if t.Block == nil {
			return nil, fmt.Errorf("params: transitions[%d]: no block", i)
		}
		b, ok := new(big.Int).SetString(t.Block.String(), 10)
		if !ok || b.Sign() < 0 {
			return nil, fmt.Errorf("params: transitions[%d]: bad block %s", i, t.Block)
		}
		ts = append(ts, Transition{Block: b, RequestTimeoutSeconds: w.RequestTimeoutSeconds, BlockPeriodSeconds: w.BlockPeriodSeconds,
			EpochLength: w.EpochLength, AllowedFutureBlockTime: w.AllowedFutureBlockTime, ProposerPolicy: w.ProposerPolicy,
			MaxRequestTimeoutSeconds: w.MaxRequestTimeoutSeconds})
	}
	return New(base, ts)
}

func decode(raw []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(v)
}

type wbftJSON struct {
	RequestTimeoutSeconds    *json.Number `json:"requestTimeoutSeconds"`
	BlockPeriodSeconds       *json.Number `json:"blockPeriodSeconds"`
	EpochLength              *json.Number `json:"epochLength"`
	AllowedFutureBlockTime   *json.Number `json:"allowedFutureBlockTime"`
	ProposerPolicy           *json.Number `json:"proposerPolicy"`
	MaxRequestTimeoutSeconds *json.Number `json:"maxRequestTimeoutSeconds"`
}

type transitionJSON struct {
	Block *json.Number `json:"block"`
	wbftJSON
}

func (w *wbftJSON) toWBFT() (WBFT, error) {
	var out WBFT
	var err error
	u := func(n *json.Number, name string) uint64 {
		if n == nil || err != nil {
			return 0
		}
		v, ok := new(big.Int).SetString(n.String(), 10)
		if !ok || v.Sign() < 0 || !v.IsUint64() {
			err = fmt.Errorf("params: %s: not a uint64: %s", name, n)
			return 0
		}
		return v.Uint64()
	}
	p := func(n *json.Number, name string) *uint64 {
		if n == nil {
			return nil
		}
		v := u(n, name)
		return &v
	}
	out.RequestTimeoutSeconds = u(w.RequestTimeoutSeconds, "requestTimeoutSeconds")
	out.BlockPeriodSeconds = u(w.BlockPeriodSeconds, "blockPeriodSeconds")
	out.EpochLength = u(w.EpochLength, "epochLength")
	out.AllowedFutureBlockTime = u(w.AllowedFutureBlockTime, "allowedFutureBlockTime")
	out.ProposerPolicy = p(w.ProposerPolicy, "proposerPolicy")
	out.MaxRequestTimeoutSeconds = p(w.MaxRequestTimeoutSeconds, "maxRequestTimeoutSeconds")
	return out, err
}
