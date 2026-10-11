package secp256k1

import (
	"encoding/hex"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/yamlsubset"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestRecover recovers the signer of the wbft-spec case high_s_twin
// (crypto/ecdsa_recover) and of its low-S twin, and refuses the malformed
// signatures of A-02 §8.2.
func TestRecover(t *testing.T) {
	hash := keccak.Sum256([]byte("wbft"))
	want := "376ab524a47492d1c8222c67c0cff8d5fec34112"
	high := unhex(t, "20a777b74c9e9838257309f91fd348d53485fb0bedbdcabf4a41faeb17b8ce359ae7d0420b2d1958096b6e1cafac4ccccaab8aa87851f35dcb773bd0e282cbc501")
	// The low-S twin: (R, n - S, V xor 1).
	low := append([]byte(nil), high...)
	s := new(big.Int).SetBytes(high[32:64])
	new(big.Int).Sub(n, s).FillBytes(low[32:64])
	low[64] ^= 1
	for name, sig := range map[string][]byte{"high S": high, "low S": low} {
		a, err := Recover(hash, sig)
		if err != nil || hex.EncodeToString(a[:]) != want {
			t.Fatalf("%s: %x %v", name, a, err)
		}
	}
	bad := map[string][]byte{"64 bytes": high[:64], "V = 4": append(append([]byte(nil), high[:64]...), 4)}
	rn := append([]byte(nil), high...)
	n.FillBytes(rn[:32])
	bad["R = n"] = rn
	zero := append([]byte(nil), high...)
	clear(zero[32:64])
	bad["S = 0"] = zero
	for name, sig := range bad {
		if _, err := Recover(hash, sig); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// TestSpecVectors runs every case of crypto/ecdsa_recover in the wbft-spec
// vector directory WBFT_SPEC_VECTORS names: a case with an expected file
// recovers its address, a case without one is refused.
func TestSpecVectors(t *testing.T) {
	dir := os.Getenv("WBFT_SPEC_VECTORS")
	if dir == "" {
		t.Skip("WBFT_SPEC_VECTORS is not set")
	}
	cases, err := filepath.Glob(filepath.Join(dir, "crypto", "ecdsa_recover", "*"))
	if err != nil || len(cases) == 0 {
		t.Fatalf("no cases: %v", err)
	}
	for _, c := range cases {
		read := func(name string) map[string]any {
			b, err := os.ReadFile(filepath.Join(c, name))
			if err != nil {
				return nil
			}
			m, err := yamlsubset.Parse(b)
			if err != nil {
				t.Fatalf("%s/%s: %v", c, name, err)
			}
			return m
		}
		in, exp := read("input.yaml"), read("expected.yaml")
		data, _ := in["data"].(string)
		sig, _ := in["signature"].(string)
		a, err := Recover(keccak.Sum256(unhex(t, data)), unhex(t, sig))
		switch {
		case exp == nil && err == nil:
			t.Errorf("%s: accepted, recovered %x", filepath.Base(c), a)
		case exp != nil && (err != nil || "0x"+hex.EncodeToString(a[:]) != exp["address"]):
			t.Errorf("%s: %x %v, want %v", filepath.Base(c), a, err, exp["address"])
		}
	}
	t.Logf("%d cases", len(cases))
}

// BenchmarkRecover measures one recovery; a frame dump of a run holds
// thousands of received frames.
func BenchmarkRecover(b *testing.B) {
	hash := keccak.Sum256([]byte("wbft"))
	sig, _ := hex.DecodeString("20a777b74c9e9838257309f91fd348d53485fb0bedbdcabf4a41faeb17b8ce359ae7d0420b2d1958096b6e1cafac4ccccaab8aa87851f35dcb773bd0e282cbc501")
	for b.Loop() {
		if _, err := Recover(hash, sig); err != nil {
			b.Fatal(err)
		}
	}
}
