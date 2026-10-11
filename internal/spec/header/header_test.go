package header

import (
	"encoding/hex"
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

// TestFirstFailure: the vector header passes, and a header changed to
// break one rule, or two, gives the first broken step of A-08 §6.2.
func TestFirstFailure(t *testing.T) {
	f := vectorHeader(t)
	h, err := Decode(encode(f, nil))
	if err != nil {
		t.Fatal(err)
	}
	if h.Number.Int64() != 2 || h.FirstFailure() != nil {
		t.Fatalf("vector header: number %s, failure %+v", h.Number, h.FirstFailure())
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
		if x := h.FirstFailure(); x != nil {
			got = x.Step
		}
		if got != c.step {
			t.Errorf("%s: step %q, want %q", c.name, got, c.step)
		}
	}
	// The vector header has BaseFee (16 fields). Without it the header
	// passes too; with WithdrawalsHash and BlobGasUsed, H7 comes first.
	if h, err := Decode(encode(f[:nRequired], nil)); err != nil || h.FirstFailure() != nil {
		t.Errorf("without BaseFee: %v", err)
	}
	h, _ = Decode(encode(f, nil, str(make([]byte, 32)), rlp.EncodeUint(0)))
	if x := h.FirstFailure(); x == nil || x.Step != "H7" {
		t.Errorf("withdrawals and blob gas: %+v", x)
	}
	if _, err := Decode(rlp.EncodeList(f[0].Raw)); err == nil {
		t.Error("a header of one field decoded")
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
