package headers

import (
	"math/big"
	"testing"
)

func TestDeclaredRevealNeedsParentAndPreservesLegacyBeforeActivation(t *testing.T) {
	cfg := config(t)
	cfg.BLSRandaoAt = big.NewInt(3)
	h, parent := fixture(t, 1), fixture(t, 0)
	find := func(xs []Predicate) Predicate {
		for _, p := range xs {
			if p.Requirement == "WBFT-HDR-014" {
				return p
			}
		}
		t.Fatal("reveal predicate absent")
		return Predicate{}
	}
	if p := find(Predicates(h, cfg)); p.Unknown == "" || p.Valid {
		t.Fatal("header selected its own declared activation", p)
	}
	if p := find(PredicatesWithParent(h, cfg, parent)); p.Unknown != "" || !p.Valid {
		t.Fatal("ordinary pre-activation ECDSA rejected", p)
	}
	cfg.BLSRandaoAt = big.NewInt(1)
	if p := find(PredicatesWithParent(h, cfg, parent)); p.Valid || p.Unknown != "" {
		t.Fatal("ordinary ECDSA wire format accepted after BLS activation", p)
	}
}
