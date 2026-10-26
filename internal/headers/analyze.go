package headers

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"sort"
	"strings"

	"github.com/0xmhha/wbft-inspector/internal/evidence"
	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

type Finding struct {
	Count           int
	Kind, Note, Key string
	Evidence        []evidence.Pointer
}
type Scan struct {
	Findings []Finding
	SHA256   string
	Count    int
}

// Analyze emits header-only observations, without turning a legitimate
// schedule difference or a late seal into a requirement failure.
func (r *Range) Analyze(cfg *params.Config) (Scan, error) {
	out := Scan{Findings: []Finding{}}
	digest := sha256.New()
	findings := map[string]*Finding{}
	add := func(f Finding) {
		x := findings[f.Key]
		if x == nil {
			x = &Finding{Kind: f.Kind, Note: f.Note, Key: f.Key, Evidence: []evidence.Pointer{}}
			findings[f.Key] = x
		}
		x.Count++
		if len(x.Evidence)+len(f.Evidence) <= 20 {
			x.Evidence = append(x.Evidence, f.Evidence...)
		}
	}

	for from := r.From; ; {
		to := from + 99
		if to < from || to > r.To {
			to = r.To
		}
		if err := r.Source.Prefetch(from, to); err != nil {
			return out, err
		}
		for n := from; ; n++ {
			h, err := r.Source.Read(n)
			if err != nil {
				return out, err
			}
			_, _ = fmt.Fprintf(digest, "%d:", n)
			_, _ = digest.Write(RawFields(h))
			out.Count++
			x, err := h.Extra()
			if err == nil && n > 0 && cfg != nil {
				addresses, err := r.Validators(n, cfg)
				if err != nil {
					return out, err
				}
				parent, err := r.Source.Read(n - 1)
				if err != nil {
					return out, err
				}
				if parent.Hash() != h.ParentHash() {
					return out, fmt.Errorf("header %d does not extend its source parent", n)
				}
				child, childErr := r.Source.Read(n + 1)
				var cx *header.Extra
				if childErr == nil && child.ParentHash() == h.Hash() {
					cx, _ = child.Extra()
				}
				round := x.Round
				if cx != nil {
					round = cx.PrevRound
				}
				pol := cfg.At(h.Number).ProposerPolicy
				if pol != nil && len(addresses) > 0 {
					last := parent.Coinbase()
					if parent.Number.Sign() == 0 {
						last = "0x" + strings.Repeat("0", 40)
					}
					planned := Proposer(addresses, last, uint64(round), *pol)
					if planned != h.Coinbase() {
						add(Finding{Kind: "proposer_schedule_diff", Key: "proposer_schedule_diff", Note: fmt.Sprintf("Coinbase %s differs from the scheduled proposer %s at decision round %d; headers do not explain why.", h.Coinbase(), planned, round), Evidence: []evidence.Pointer{{Kind: "block", Input: r.Input, Node: r.Node, Number: h.Number.String(), Hash: h.Hash(), Field: "Coinbase"}}})
					}
				}
				if cx != nil {
					for i, a := range addresses {
						for _, s := range []struct {
							phase         string
							own, previous []byte
						}{{"prepared", x.Prepared, cx.PrevPrepared}, {"committed", x.Committed, cx.PrevCommitted}} {
							if header.Included(s.previous, i) && !header.Included(s.own, i) {
								add(Finding{Kind: "late_seal", Key: "late_seal:" + s.phase + ":" + a, Note: fmt.Sprintf("Validator %s is included in the child's previous %s seal but absent from this node's header copy.", a, s.phase), Evidence: []evidence.Pointer{{Kind: "block", Input: r.Input, Node: r.Node, Number: child.Number.String(), Hash: child.Hash(), Address: a, Field: "extra.prev_" + s.phase + "_seal.sealers"}, {Kind: "block", Input: r.Input, Node: r.Node, Number: h.Number.String(), Hash: h.Hash(), Address: a, Field: "extra." + s.phase + "_seal.sealers"}}})
							}
						}
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
	for _, f := range findings {
		shown := len(f.Evidence)
		if f.Kind == "late_seal" {
			shown /= 2
		}
		if f.Count > shown {
			f.Note += fmt.Sprintf(" Evidence samples show the first %d of %d occurrences.", shown, f.Count)
		}
		out.Findings = append(out.Findings, *f)
	}
	sort.Slice(out.Findings, func(i, j int) bool { return out.Findings[i].Key < out.Findings[j].Key })
	out.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return out, nil
}
func LastEpoch(cfg *params.Config, n uint64) (uint64, error) {
	anchor := uint64(0)
	length := cfg.Base.EpochLength
	for _, t := range cfg.Transitions {
		if t.Block.Cmp(new(big.Int).SetUint64(n)) > 0 {
			break
		}
		if t.EpochLength != 0 {
			if !t.Block.IsUint64() {
				return 0, fmt.Errorf("epoch anchor outside canonical domain")
			}
			anchor = t.Block.Uint64()
			length = t.EpochLength
		}
	}
	if length == 0 {
		return 0, fmt.Errorf("epoch length is zero")
	}
	return n - (n-anchor)%length, nil
}
func (r *Range) Validators(n uint64, cfg *params.Config) ([]string, error) {
	index := uint64(0)
	if n > 0 {
		var err error
		index, err = LastEpoch(cfg, n-1)
		if err != nil {
			return nil, err
		}
	}
	h, err := r.Source.Read(index)
	if err != nil {
		return nil, err
	}
	x, err := h.Extra()
	if err != nil {
		return nil, err
	}
	if x.Epoch == nil {
		return nil, fmt.Errorf("governing epoch header %d has no epoch info", index)
	}
	return x.Epoch.Addresses()
}

// Proposer is A-04's ordered rotation. It uses the epoch's order, without
// sorting addresses or assuming a mismatching Coinbase is invalid.
func Proposer(addresses []string, last string, round, policy uint64) string {
	if len(addresses) == 0 {
		return ""
	}
	seed := round
	if last != "0x"+strings.Repeat("0", 40) {
		offset := uint64(0)
		for i, a := range addresses {
			if a == last {
				offset = uint64(i)
				break
			}
		}
		seed += offset
		if policy != 1 {
			seed++
		}
	}
	return addresses[seed%uint64(len(addresses))]
}

type Predicate struct {
	Requirement, Field string
	Valid              bool
	Unknown            string
	ObserverScope      bool
}

// Predicates check only observable content invariants. Node rejection order,
// proposal clock, execution state and aggregate signatures are outside scope.
func Predicates(h *header.Header, cfg *params.Config) []Predicate {
	return PredicatesWithParent(h, cfg, nil)
}

// PredicatesWithParent binds a declared reveal profile to checked ancestry.
func PredicatesWithParent(h *header.Header, cfg *params.Config, parent *header.Header) []Predicate {
	uintField := func(i int) *big.Int {
		f, _ := h.Field(i)
		n, err := f.Uint()
		if err != nil {
			return nil
		}
		return n
	}
	equalBytes := func(i int, want string) bool {
		f, _ := h.Field(i)
		return !f.List && hex.EncodeToString(f.Content) == want
	}
	diff := uintField(7)
	limit := uintField(9)
	used := uintField(10)
	_, withdrawals := h.Field(16)
	_, blob := h.Field(17)
	out := []Predicate{
		{Requirement: "WBFT-HDR-011", Field: "Difficulty", Valid: diff != nil && diff.Cmp(big.NewInt(1)) == 0},
		{Requirement: "SNET-BHDR-001", Field: "UncleHash", Valid: equalBytes(1, "1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")},
		{Requirement: "SNET-BHDR-002", Field: "GasLimit", Valid: limit != nil && limit.BitLen() <= 63},
		{Requirement: "SNET-BHDR-004", Field: "WithdrawalsHash", Valid: !withdrawals},
		{Requirement: "SNET-BHDR-006", Field: "BlobGasUsed", Valid: !blob},
		{Requirement: "SNET-BHDR-007", Field: "GasUsed", Valid: limit != nil && used != nil && used.Cmp(limit) <= 0},
	}
	x, err := h.Extra()
	out = append(out, Predicate{Requirement: "WBFT-ENC-021", Field: "Extra", Valid: err == nil})
	out = append(out, revealPredicate(h, cfg, parent, x, err))
	return out
}

// RawFields fingerprints the node copy, including seals the block hash excludes.
func RawFields(h *header.Header) []byte {
	var fields [][]byte
	for i := 0; ; i++ {
		f, ok := h.Field(i)
		if !ok {
			break
		}
		fields = append(fields, f.Raw)
	}
	return rlp.EncodeList(fields...)
}
