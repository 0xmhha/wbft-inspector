// Command self is a wbft-vector/1 adapter around the inspector's own model
// of the specification. Running it with the vector runner checks that the
// model the checkers use computes what the reference computes:
//
//	wbft-inspector vectors --impl ./bin/self-adapter --vectors <wbft-spec>/spec/vectors --runner timers --handler round_timeout
//	wbft-inspector vectors --impl ./bin/self-adapter --vectors <wbft-spec>/spec/vectors --runner chain --handler config_at
//
// It supports timers/round_timeout (A-06 §4.1) and chain/config_at (A-01
// §6.5) and answers "unsupported" for every other handler.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/0xmhha/wbft-inspector/internal/buildinfo"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/spec/timers"
)

func main() {
	if err := serve(os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "self adapter:", err)
		os.Exit(1)
	}
}

var handlers = map[string]func(map[string]any) (map[string]any, error){
	"timers/round_timeout": roundTimeout,
	"chain/config_at":      configAt,
}

func serve(r io.Reader, w io.Writer) error {
	br := bufio.NewReaderSize(r, 1<<20)
	out := bufio.NewWriter(w)
	send := func(v any) error {
		b, err := json.Marshal(v)
		if err != nil {
			return err
		}
		if _, err := out.Write(append(b, '\n')); err != nil {
			return err
		}
		return out.Flush()
	}
	for {
		line, err := br.ReadBytes('\n')
		if errors.Is(err, io.EOF) && len(line) == 0 {
			return nil
		}
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		var msg struct {
			Type    string          `json:"type"`
			ID      json.RawMessage `json:"id"`
			Runner  json.RawMessage `json:"runner"` // an object in hello, a name in case
			Handler string          `json:"handler"`
			Input   map[string]any  `json:"input"`
		}
		if err := json.Unmarshal(line, &msg); err != nil {
			return fmt.Errorf("bad message: %w", err)
		}
		switch msg.Type {
		case "hello":
			names := []string{"chain/config_at", "timers/round_timeout"}
			if err := send(map[string]any{"type": "hello", "protocol": "wbft-vector/1",
				"impl":     map[string]string{"name": "wbft-inspector-self", "version": buildinfo.Version, "commit": buildinfo.Commit(), "lang": "go", "build": "nocgo"},
				"handlers": names, "improvements": []string{}}); err != nil {
				return err
			}
		case "case":
			var runner string
			_ = json.Unmarshal(msg.Runner, &runner)
			h := handlers[runner+"/"+msg.Handler]
			res := map[string]any{"type": "result", "id": msg.ID}
			if h == nil {
				res["status"] = "unsupported"
			} else if o, err := h(msg.Input); err != nil {
				res["status"], res["error_class"], res["message"] = "error", "input", err.Error()
			} else {
				res["status"], res["output"] = "ok", o
			}
			if err := send(res); err != nil {
				return err
			}
		case "bye":
			return nil
		default:
			return fmt.Errorf("unexpected message type %q", msg.Type)
		}
	}
}

func str(m map[string]any, k string) (string, error) {
	s, ok := m[k].(string)
	if !ok {
		return "", fmt.Errorf("%s: not a string", k)
	}
	return s, nil
}

func u64(m map[string]any, k string) (uint64, error) {
	s, err := str(m, k)
	if err != nil {
		return 0, err
	}
	b, ok := new(big.Int).SetString(s, 10)
	if !ok || b.Sign() < 0 || !b.IsUint64() {
		return 0, fmt.Errorf("%s: not a uint64: %s", k, s)
	}
	return b.Uint64(), nil
}

func optU64(m map[string]any, k string) (*uint64, error) {
	if v, ok := m[k]; !ok || v == nil {
		return nil, nil
	}
	x, err := u64(m, k)
	return &x, err
}

func roundTimeout(in map[string]any) (map[string]any, error) {
	rt, err := u64(in, "request_timeout")
	if err != nil {
		return nil, err
	}
	mrt, err := u64(in, "max_request_timeout_seconds")
	if err != nil {
		return nil, err
	}
	s, err := str(in, "round")
	if err != nil {
		return nil, err
	}
	r, ok := new(big.Int).SetString(s, 10)
	if !ok || r.Sign() < 0 {
		return nil, fmt.Errorf("round: not a non-negative integer: %s", s)
	}
	ns, warn := timers.RoundTimeout(rt, mrt, r)
	return map[string]any{"timeout": fmt.Sprint(ns), "warning": warn}, nil
}

func configAt(in map[string]any) (map[string]any, error) {
	cfg, ok := in["config"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config: not an object")
	}
	w, ok := cfg["wbft"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("config.wbft: not an object")
	}
	base, err := wbftOf(w)
	if err != nil {
		return nil, err
	}
	list, _ := cfg["transitions"].([]any)
	var ts []params.Transition
	for i, x := range list {
		t, ok := x.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("transitions[%d]: not an object", i)
		}
		p, err := wbftOf(t)
		if err != nil {
			return nil, fmt.Errorf("transitions[%d]: %w", i, err)
		}
		bs, err := str(t, "block")
		if err != nil {
			return nil, fmt.Errorf("transitions[%d]: %w", i, err)
		}
		b, ok := new(big.Int).SetString(bs, 10)
		if !ok {
			return nil, fmt.Errorf("transitions[%d].block: %s", i, bs)
		}
		ts = append(ts, params.Transition{Block: b, RequestTimeoutSeconds: p.RequestTimeoutSeconds, BlockPeriodSeconds: p.BlockPeriodSeconds,
			EpochLength: p.EpochLength, AllowedFutureBlockTime: p.AllowedFutureBlockTime, ProposerPolicy: p.ProposerPolicy,
			MaxRequestTimeoutSeconds: p.MaxRequestTimeoutSeconds})
	}
	c, err := params.New(base, ts)
	if err != nil {
		return nil, err
	}
	ns, err := str(in, "number")
	if err != nil {
		return nil, err
	}
	n, ok := new(big.Int).SetString(ns, 10)
	if !ok {
		return nil, fmt.Errorf("number: %s", ns)
	}
	r := c.At(n)
	var policy any
	if r.ProposerPolicy != nil {
		policy = fmt.Sprint(*r.ProposerPolicy)
	}
	return map[string]any{
		"request_timeout":             fmt.Sprint(r.RequestTimeoutMs),
		"block_period":                fmt.Sprint(r.BlockPeriodSeconds),
		"epoch":                       fmt.Sprint(r.Epoch),
		"proposer_policy":             policy,
		"max_request_timeout_seconds": fmt.Sprint(r.MaxRequestTimeoutSeconds),
		"allowed_future_block_time":   fmt.Sprint(r.AllowedFutureBlockTime),
	}, nil
}

func wbftOf(m map[string]any) (params.WBFT, error) {
	var w params.WBFT
	var err error
	if w.RequestTimeoutSeconds, err = u64(m, "request_timeout_seconds"); err != nil {
		return w, err
	}
	if w.BlockPeriodSeconds, err = u64(m, "block_period_seconds"); err != nil {
		return w, err
	}
	if w.EpochLength, err = u64(m, "epoch_length"); err != nil {
		return w, err
	}
	if w.AllowedFutureBlockTime, err = u64(m, "allowed_future_block_time"); err != nil {
		return w, err
	}
	if w.ProposerPolicy, err = optU64(m, "proposer_policy"); err != nil {
		return w, err
	}
	if w.MaxRequestTimeoutSeconds, err = optU64(m, "max_request_timeout_seconds"); err != nil {
		return w, err
	}
	return w, nil
}
