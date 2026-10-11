package header

import (
	"encoding/hex"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

// vectorHeader returns the items of the wbft-spec preprepare_round0
// proposal header.
func vectorHeader(t *testing.T) []rlp.Item {
	t.Helper()
	b, err := os.ReadFile("testdata/header.txt")
	if err != nil {
		t.Fatal(err)
	}
	var line string
	for _, l := range strings.Split(string(b), "\n") {
		if l != "" && !strings.HasPrefix(l, "#") {
			line = l
		}
	}
	raw, err := hex.DecodeString(line)
	if err != nil {
		t.Fatal(err)
	}
	f, err := rlp.Items(raw)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// encode returns the header list of items, with field i replaced by the
// encoding repl[i] and extra encodings appended.
func encode(f []rlp.Item, repl map[int][]byte, extra ...[]byte) []byte {
	var raws [][]byte
	for i, it := range f {
		if r, ok := repl[i]; ok {
			raws = append(raws, r)
			continue
		}
		raws = append(raws, it.Raw)
	}
	return rlp.EncodeList(append(raws, extra...)...)
}

// str is the RLP encoding of a byte string of at most 55 bytes.
func str(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return b
	}
	return append([]byte{0x80 + byte(len(b))}, b...)
}

// bytesItem is the RLP encoding of a byte string of any length.
func bytesItem(b []byte) []byte {
	if len(b) <= 55 {
		return str(b)
	}
	n := new(big.Int).SetInt64(int64(len(b))).Bytes()
	return append(append([]byte{0xb7 + byte(len(n))}, n...), b...)
}

// TestFirstFailure: the vector header passes, and a header changed to
// break one rule, or two, gives the first broken step of A-08 §6.2.
func TestFirstFailure(t *testing.T) {
	f := vectorHeader(t)
	h, err := Decode(encode(f, nil))
	if err != nil {
		t.Fatal(err)
	}
	if h.Number.Int64() != 2 || h.FirstFailure(nil) != nil {
		t.Fatalf("vector header: number %s, failure %+v", h.Number, h.FirstFailure(nil))
	}
	big64 := str([]byte{0x80, 0, 0, 0, 0, 0, 0, 0}) // 2^63
	cases := []struct {
		name  string
		repl  map[int][]byte
		extra [][]byte
		step  string
	}{
		{"uncle hash", map[int][]byte{fUncleHash: str(make([]byte, 32))}, nil, "H3"},
		{"difficulty 2", map[int][]byte{fDifficulty: rlp.EncodeUint(2)}, nil, "H4"},
		{"difficulty 0", map[int][]byte{fDifficulty: rlp.EncodeUint(0)}, nil, "H4"},
		{"difficulty before gas", map[int][]byte{fDifficulty: rlp.EncodeUint(2), fGasUsed: big64}, nil, "H4"},
		{"gas limit 2^63", map[int][]byte{fGasLimit: big64}, nil, "H5"},
		{"withdrawals hash", nil, [][]byte{str(make([]byte, 32))}, "H7"},
		{"gas used above limit", map[int][]byte{fGasUsed: big64}, nil, "H13"},
		{"extra not a list", map[int][]byte{fExtra: str([]byte{0x01, 0x02})}, nil, "H16"},
		{"extra of nine", map[int][]byte{fExtra: str(rlp.EncodeList(rlp.EncodeUint(0), rlp.EncodeUint(0), rlp.EncodeUint(0), rlp.EncodeUint(0),
			rlp.EncodeUint(0), rlp.EncodeUint(0), rlp.EncodeUint(0), rlp.EncodeUint(0), rlp.EncodeUint(0)))}, nil, "H16"},
		{"number 0 skips H13", map[int][]byte{fNumber: rlp.EncodeUint(0), fGasUsed: big64}, nil, ""},
	}
	for _, c := range cases {
		h, err := Decode(encode(f, c.repl, c.extra...))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := ""
		if x := h.FirstFailure(nil); x != nil {
			got = x.Step
		}
		if got != c.step {
			t.Errorf("%s: step %q, want %q", c.name, got, c.step)
		}
	}
	// The vector header has BaseFee (16 fields). Without it the header
	// passes too; with WithdrawalsHash and BlobGasUsed, H7 comes first.
	if h, err := Decode(encode(f[:nRequired], nil)); err != nil || h.FirstFailure(nil) != nil {
		t.Errorf("without BaseFee: %v", err)
	}
	h, _ = Decode(encode(f, nil, str(make([]byte, 32)), rlp.EncodeUint(0)))
	if x := h.FirstFailure(nil); x == nil || x.Step != "H7" {
		t.Errorf("withdrawals and blob gas: %+v", x)
	}
	if _, err := Decode(rlp.EncodeList(f[0].Raw)); err == nil {
		t.Error("a header of one field decoded")
	}
}

// TestRandaoData checks randao_data against the vectors of wbft-spec
// A-02 §8.5.
func TestRandaoData(t *testing.T) {
	for _, c := range []struct {
		chain, number int64
		want          string
	}{
		{8282, 0, "f6c98387ef170854e352073e846537b9947cfe23ddb4fa79932c3c248577ebd2"},
		{8282, 1, "48516c21b70c7a85c71e6fe34cd724419d7803fb58bc1cf3f69a76eb85d98b3f"},
		{8282, 256, "50ee1ee4f218972dbf488dd8f6eee54beb17e0b75169d1cdc543ac439516951c"},
		{8283, 1, "2536b43be46ffc0db54c300982998c0476b79a0c13bc5558e84887db975a046a"},
	} {
		d := RandaoData(big.NewInt(c.chain), big.NewInt(c.number))
		if got := hex.EncodeToString(d[:]); got != c.want {
			t.Errorf("randao_data(%d, %d) = %s, want %s", c.chain, c.number, got, c.want)
		}
	}
}

// TestRandaoReveal: the vector header, whose reveal is key 0's signature
// of randao_data(8282, 2) and whose Coinbase is key 0's address, passes
// H18 with chain id 8282 and fails it with another chain id, another
// Coinbase or a broken reveal. A reveal that is a list fails H16 first,
// with or without a chain id.
func TestRandaoReveal(t *testing.T) {
	f := vectorHeader(t)
	x, err := rlp.Items(f[fExtra].Content)
	if err != nil || len(x) != extraElements {
		t.Fatalf("vector extra: %d elements, %v", len(x), err)
	}
	withReveal := func(reveal []byte) []byte {
		var raws [][]byte
		for i, it := range x {
			if i == xRandaoReveal {
				raws = append(raws, reveal)
				continue
			}
			raws = append(raws, it.Raw)
		}
		return bytesItem(rlp.EncodeList(raws...))
	}
	sig := append([]byte(nil), x[xRandaoReveal].Content...)
	badV := append([]byte(nil), sig...)
	badV[64] = 4
	zeroR := append(make([]byte, 32), sig[32:]...)
	sig65 := func(b []byte) []byte { return bytesItem(b) }
	other := str(make([]byte, 20))
	cases := []struct {
		name  string
		chain int64
		repl  map[int][]byte
		step  string
	}{
		{"vector", 8282, nil, ""},
		{"other chain id", 8283, nil, "H18"},
		{"other coinbase", 8282, map[int][]byte{fCoinbase: other}, "H18"},
		{"recovery id 4", 8282, map[int][]byte{fExtra: withReveal(sig65(badV))}, "H18"},
		{"r zero", 8282, map[int][]byte{fExtra: withReveal(sig65(zeroR))}, "H18"},
		{"short reveal", 8282, map[int][]byte{fExtra: withReveal(str(sig[:20]))}, "H18"},
		{"reveal a list", 8282, map[int][]byte{fExtra: withReveal(rlp.EncodeList())}, "H16"},
		{"number 2^64 skips H18", 8283, map[int][]byte{fNumber: str([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0})}, ""},
	}
	for _, c := range cases {
		h, err := Decode(encode(f, c.repl))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		got := ""
		if x := h.FirstFailure(big.NewInt(c.chain)); x != nil {
			got = x.Step
		}
		if got != c.step {
			t.Errorf("%s: step %q, want %q", c.name, got, c.step)
		}
	}
	// Without a chain id H18 is left out, and the list reveal still fails H16.
	h, _ := Decode(encode(f, map[int][]byte{fCoinbase: other}))
	if x := h.FirstFailure(nil); x != nil {
		t.Errorf("other coinbase without a chain id: %+v", x)
	}
	h, _ = Decode(encode(f, map[int][]byte{fExtra: withReveal(rlp.EncodeList())}))
	if x := h.FirstFailure(nil); x == nil || x.Step != "H16" {
		t.Errorf("list reveal without a chain id: %+v", x)
	}
}

// TestOrder places the steps in the order a node applies them.
func TestOrder(t *testing.T) {
	steps := []string{"P1", "P2", "P3", "V0a", "P4", "P5", "P6", "H1", "H4", "H15a", "H15b", "H16", "H21", "P7"}
	prev := -1
	for _, s := range steps {
		p, ok := Order(s)
		if !ok || p < prev {
			t.Fatalf("%s at %d after %d (ok %v)", s, p, prev, ok)
		}
		prev = p
	}
	for _, s := range []string{"", "P8", "H22", "H0", "SNET-BHDR-003", "h4"} {
		if _, ok := Order(s); ok {
			t.Errorf("%q has an order", s)
		}
	}
}
