package timers

import (
	"math"
	"math/big"
	"testing"
)

// The worked examples of wbft-spec A-06 §4.2.
func TestWorkedExamples(t *testing.T) {
	cases := []struct {
		rtMs, capS uint64
		round      int64
		want       int64
		warn       string
	}{
		{2000, 0, 3, 16_000_000_000, WarnNone},              // 1: mainnet preset, round 3
		{2000, 10, 3, 10_000_000_000, WarnNone},             // 2: capped at 10 s
		{1_000_000, 4, 0, 1_000_000_000_000, WarnNone},      // 3: --dev, round 0 lasts base
		{1_000_000, 4, 1, 4_000_000_000, WarnCapGuard},      // 3: --dev, round 1 uses cap
		{2000, 0, 33, math.MaxInt64, WarnClamp},             // 4: clamp
		{2000, 0, 32, 8_589_934_592_000_000_000, WarnNone},  // 4: still in range
		{2000, 10_000_000_000, 3, 16_000_000_000, WarnNone}, // 5: cap wraps negative, uncapped
	}
	for i, c := range cases {
		got, warn := RoundTimeout(c.rtMs, c.capS, big.NewInt(c.round))
		if got != c.want || warn != c.warn {
			t.Errorf("case %d: got %d %s, want %d %s", i, got, warn, c.want, c.warn)
		}
	}
}

func TestHugeRound(t *testing.T) {
	r := new(big.Int).Lsh(big.NewInt(1), 70) // taken modulo 2^64: 0
	if got, _ := RoundTimeout(2000, 0, r); got != 2_000_000_000 {
		t.Fatalf("round 2^70: got %d", got)
	}
	r = new(big.Int).SetUint64(math.MaxUint64)
	if got, warn := RoundTimeout(2000, 10, r); got != 10_000_000_000 || warn != WarnNone {
		t.Fatalf("round 2^64-1 capped: got %d %s", got, warn)
	}
}
