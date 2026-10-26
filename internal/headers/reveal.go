package headers

import (
	"encoding/hex"
	"math/big"

	"github.com/0xmhha/wbft-inspector/internal/spec/header"
	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/spec/params"
	"github.com/0xmhha/wbft-inspector/internal/spec/secp256k1"
)

func revealPredicate(h *header.Header, cfg *params.Config, parent *header.Header, x *header.Extra, extraErr error) Predicate {
	out := Predicate{Requirement: "WBFT-HDR-014", Field: "extra.randao_reveal"}
	if cfg == nil || cfg.ChainID == nil {
		out.Unknown = "chain ID is unavailable"
		return out
	}
	if extraErr != nil {
		out.Unknown = "extra cannot be decoded"
		return out
	}
	if cfg.BLSRandaoAt != nil {
		if parent == nil || parent.Hash() != h.ParentHash() {
			out.Unknown = "declared reveal activation requires a matching parent"
			return out
		}
		at := new(big.Int).Add(parent.Number, big.NewInt(1))
		if at.Cmp(h.Number) != 0 {
			out.Unknown = "declared reveal activation requires the full parent-successor height"
			return out
		}
		if at.Cmp(cfg.BLSRandaoAt) >= 0 {
			if len(x.Randao) != 96 {
				return out
			}
			out.Unknown = "BLS reveal signature requires an independent cryptographic verifier and the registered proposer key"
			out.ObserverScope = true
			return out
		}
	}
	pre := header.RandaoData(cfg.ChainID, h.Number)
	signer, err := secp256k1.Recover(keccak.Sum256(pre[:]), x.Randao)
	out.Valid = err == nil && "0x"+hex.EncodeToString(signer[:]) == h.Coinbase()
	return out
}
