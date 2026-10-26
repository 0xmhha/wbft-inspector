package hdr

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/headers"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

var contentRequirements = []string{"WBFT-HDR-011", "WBFT-HDR-014", "WBFT-ENC-021", "SNET-BHDR-001", "SNET-BHDR-002", "SNET-BHDR-004", "SNET-BHDR-006", "SNET-BHDR-007"}

func init() {
	check.Register(headerContent{check.Base{ID: "hdr.canonical_content", Reqs: contentRequirements, Kinds: []check.Kind{check.Headers}}})
}

type headerContent struct{ check.Base }

// Canonical content is checked independently of node rejection-order rules.
// Genesis is outside proposal/import verification. The signature check keeps
// the unobserved binding to the actual node key separate from recovery.
func (c headerContent) Run(ctx context.Context, in *check.Inputs, out check.Emitter) error {
	r := in.Headers
	for from := r.From; ; {
		to := from + 99
		if to < from || to > r.To {
			to = r.To
		}
		if err := r.Source.Prefetch(from, to); err != nil {
			return err
		}
		batch := make([][]headers.Predicate, int(to-from)+1)
		headerBatch := make([]*header.Header, len(batch))
		for n := from; n <= to; n++ {
			h, err := r.Source.Read(n)
			if err != nil {
				return err
			}
			headerBatch[n-from] = h
		}
		parents := make([]*header.Header, len(batch))
		if in.Config != nil && in.Config.BLSRandaoAt != nil {
			for i := range headerBatch {
				if i > 0 {
					parents[i] = headerBatch[i-1]
				} else if from > 0 {
					parents[i], _ = r.Source.Read(from - 1)
				}
			}
		}
		workers := min(runtime.GOMAXPROCS(0), 8, len(batch))
		jobs := make(chan int)
		var wg sync.WaitGroup
		for worker := 0; worker < workers; worker++ {
			wg.Go(func() {
				for i := range jobs {
					batch[i] = headers.PredicatesWithParent(headerBatch[i], in.Config, parents[i])
				}
			})
		}
		for i := range batch {
			jobs <- i
		}
		close(jobs)
		wg.Wait()
		for n := from; ; n++ {
			if err := ctx.Err(); err != nil {
				return err
			}
			h, err := r.Source.Read(n)
			if err != nil {
				return err
			}
			if h.Number.Sign() != 0 {
				for _, p := range batch[n-from] {
					instance := verdict.Instance{Requirement: p.Requirement, Node: r.Node, Key: fmt.Sprintf("header:%020d:%s", n, p.Requirement), Source: r.Input, Verdict: verdict.Pass, Evidence: []evidence.Pointer{{Kind: "block", Input: r.Input, Node: r.Node, Number: h.Number.String(), Hash: h.Hash(), Field: p.Field}}}
					if p.Unknown != "" {
						instance.Verdict = verdict.CannotDecide
						instance.Reason = verdict.MissingData
						if p.ObserverScope {
							instance.Reason = verdict.ObserverScope
						}
						instance.Message = p.Unknown
					} else if !p.Valid {
						instance.Verdict = verdict.Fail
						instance.Message = "canonical header content violates the specified field invariant"
					}
					out.Emit(instance)
					if p.Requirement == "WBFT-HDR-014" && p.Unknown == "" && p.Valid {
						instance.Key += ":node_key_scope"
						instance.Verdict = verdict.CannotDecide
						instance.Reason = verdict.ObserverScope
						instance.Message = "Signature recovers to Coinbase; the observer cannot bind that address to the proposer's declared node key from headers alone."
						out.Emit(instance)
					}
				}
			}
			if n == to {
				break
			}
		}
		if to == r.To {
			break
		}
		from = to + 1
	}
	return nil
}
