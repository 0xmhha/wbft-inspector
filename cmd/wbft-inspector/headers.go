package main

import (
	"context"
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/headers"
	"github.com/0xmhha/wbft-inspector/internal/report"
	"github.com/0xmhha/wbft-inspector/internal/rpc"
)

type headerOptions struct {
	RPC, Blocks, Cache, From, To, Node, Name string
	Offline                                  bool
	Rate                                     float64
}

func loadHeaders(ctx context.Context, in *check.Inputs, rep *report.Report, o headerOptions) (string, error) {
	a, e1 := strconv.ParseUint(o.From, 10, 64)
	b, e2 := strconv.ParseUint(o.To, 10, 64)
	if e1 != nil || e2 != nil || b < a || b == ^uint64(0) || b-a >= 1_000_000 || o.Node == "" || (o.RPC != "" && o.Blocks != "") {
		return "", fmt.Errorf("headers require --from/--to, --header-node and one RPC or block source")
	}
	if o.Offline && o.Cache == "" && o.Blocks == "" {
		return "", fmt.Errorf("--offline requires --header-cache or --blocks")
	}
	src := &headers.Source{Context: ctx, Blocks: o.Blocks, Cache: o.Cache, Offline: o.Offline}
	if o.RPC != "" {
		client, err := rpc.New(o.RPC, o.Rate)
		if err != nil {
			return "", err
		}
		src.Client = client
	}
	r := &headers.Range{Source: src, From: a, To: b, Node: o.Node, Input: fmt.Sprintf("in-%d", len(rep.Run.Inputs)+1)}
	if err := r.Prepare(); err != nil {
		return "", err
	}
	if in.Config != nil && in.Config.ChainID != nil {
		if r.ChainID != "" && r.ChainID != in.Config.ChainID.String() {
			return "", fmt.Errorf("RPC and configuration chain IDs differ")
		}
		r.ChainID = in.Config.ChainID.String()
	}
	if r.ChainID == "" {
		return "", fmt.Errorf("offline headers need chainId in --chain-config")
	}
	rep.Run.Options = map[string]any{"header_capabilities": r.Capabilities}
	scan, err := r.Analyze(in.Config)
	if err != nil {
		return "", err
	}
	in.Headers = r
	in.Given[check.Headers] = true
	rep.Run.Network = &report.Network{Name: o.Name, ChainID: r.ChainID, GenesisHash: r.GenesisHash}
	rep.Run.Range = &report.BlockRange{From: o.From, To: o.To}
	kind, path := "rpc", o.Cache
	if src.Client == nil || o.Offline {
		kind = "cache"
	}
	if o.Blocks != "" {
		path = o.Blocks
	}
	rep.Run.Inputs = append(rep.Run.Inputs, report.Input{ID: r.Input, Kind: kind, Node: o.Node, Endpoint: src.Endpoint(), Path: path, SHA256: scan.SHA256, Records: scan.Count})
	rep.Run.Nodes = append(rep.Run.Nodes, report.Node{ID: o.Node, Role: "observer", Inputs: []string{r.Input}})
	for _, f := range scan.Findings {
		rep.Observations = append(rep.Observations, report.Observation{ID: fmt.Sprintf("OBS-%04d", len(rep.Observations)+1), Kind: f.Kind, Imp: []string{}, Checker: "headers.observations", Node: o.Node, Count: f.Count, Note: f.Note, Evidence: f.Evidence})
	}
	return scan.SHA256 + ":" + o.Node, nil
}
