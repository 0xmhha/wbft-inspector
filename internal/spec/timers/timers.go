// Package timers implements round_timeout of wbft-spec A-06 §4.1, including
// the 64-bit wrap-around and the binary64 arithmetic of the uncapped branch,
// because the result is observable: it decides when ROUND-CHANGE messages
// are sent.
package timers

import (
	"math"
	"math/big"
)

// Warnings of round_timeout: the Warn records of WBFT-TIMER-007 and
// WBFT-TIMER-008, as the vector handler timers/round_timeout names them.
const (
	WarnNone     = "none"
	WarnCapGuard = "cap_overflow_guard"
	WarnClamp    = "max_int64_clamp"
)

const (
	nsPerMs = 1_000_000
	nsPerS  = 1_000_000_000
)

var two64 = new(big.Int).Lsh(big.NewInt(1), 64)

// RoundTimeout returns round_timeout(config, round) in nanoseconds for
// request_timeout requestTimeoutMs (milliseconds, as config_at gives it) and
// maxRequestTimeoutSeconds, and which warning the reference logs.
func RoundTimeout(requestTimeoutMs, maxRequestTimeoutSeconds uint64, round *big.Int) (int64, string) {
	r := new(big.Int).Mod(round, two64).Uint64() // big.Int.Uint64 of the round
	// Go signed arithmetic wraps, as time.Duration(ms) * time.Millisecond does.
	base := int64(requestTimeoutMs) * nsPerMs
	limit := int64(maxRequestTimeoutSeconds) * nsPerS
	if limit > 0 {
		t := base
		// After 64 doublings any value has wrapped to 0 and stays 0, so
		// iterating min(r, 130) times gives the result of r iterations.
		n := r
		if n > 130 {
			n = 130
		}
		for i := uint64(0); i < n; i++ {
			t *= 2
			if t > limit {
				t = limit
				break
			}
		}
		if t < base {
			return limit, WarnCapGuard
		}
		return t, WarnNone
	}
	e := int(r)
	if r > 2000 {
		e = 2000 // 2^r is +Inf in binary64 for every r >= 1024
	}
	f := math.Ldexp(1, e) * float64(base)
	if math.IsNaN(f) || math.IsInf(f, 0) || f > float64(math.MaxInt64) {
		return math.MaxInt64, WarnClamp
	}
	if f < math.MinInt64 {
		// Go's conversion is implementation-specific here; amd64 and arm64
		// give MinInt64 (A-06 §4.1). A negative duration fires at once.
		return math.MinInt64, WarnNone
	}
	return int64(f), WarnNone
}
