package rpc

import "context"

type Capability struct {
	Method    string `json:"method"`
	Available bool   `json:"available"`
}

// Capabilities probes optional read methods at a fixed historical height.
// A method error is an unavailable capability, not a successful empty input.
func (c *Client) Capabilities(ctx context.Context) ([]Capability, error) {
	requests := []Request{{Method: "debug_getRawHeader", Params: []any{"0x0"}}, {Method: "istanbul_getWbftExtraInfo", Params: []any{"0x0"}}, {Method: "istanbul_status", Params: []any{"0x1", "0x1"}}, {Method: "wbft_nodeInfo", Params: []any{}}}
	answers, err := c.Batch(ctx, requests)
	if err != nil {
		return nil, err
	}
	out := make([]Capability, len(requests))
	for i, a := range answers {
		out[i] = Capability{Method: requests[i].Method, Available: a.Error == nil && string(a.Result) != "null"}
	}
	return out, nil
}
