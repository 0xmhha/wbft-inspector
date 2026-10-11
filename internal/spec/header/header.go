// Package header decides the header rules of wbft-spec A-08 §6.2 that need
// nothing but the header itself: no parent, state, validator set, chain
// configuration or clock.
package header

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

// Field positions in the header list (A-03): the fifteen fields every
// header has, then the optional ones, each present only with those before
// it.
const (
	fUncleHash        = 1
	fDifficulty       = 7
	fNumber           = 8
	fGasLimit         = 9
	fGasUsed          = 10
	fTime             = 11
	fExtra            = 12
	nRequired         = 15
	fWithdrawalsHash  = 16
	extraElements     = 10
	maxGasLimitBitLen = 63
)

// emptyUncleHash is keccak256(rlp([])).
var emptyUncleHash, _ = hex.DecodeString("1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347")

// Header is a decoded header.
type Header struct {
	fields []rlp.Item
	Number *big.Int
	Time   *big.Int
}

// Decode reads the RLP encoding of a header. It fails when the encoding
// is not a list of at least fifteen items or Number or Time is not an
// integer; a node rejects such a block at P1 already.
func Decode(raw []byte) (*Header, error) {
	f, err := rlp.Items(raw)
	if err != nil {
		return nil, err
	}
	if len(f) < nRequired {
		return nil, fmt.Errorf("header: %d fields, want at least %d", len(f), nRequired)
	}
	h := &Header{fields: f}
	if h.Number, err = f[fNumber].Uint(); err != nil {
		return nil, fmt.Errorf("header: number: %w", err)
	}
	if h.Time, err = f[fTime].Uint(); err != nil {
		return nil, fmt.Errorf("header: time: %w", err)
	}
	return h, nil
}

// Failure is a rule a header breaks.
type Failure struct {
	Step string // "H3" .. "H16"
	Why  string
}

// FirstFailure returns the first of the steps H3, H4, H5, H7, H13 and H16
// that the header fails, in the order of A-08 §6.2, or nil. The other
// steps need more than the header; a node may fail one of them first,
// which comes before or after the returned step as Order says. H13 and
// H16 are not reached by a block number 0 mod 2^64 (H10 returns), so they
// are not checked for one.
func (h *Header) FirstFailure() *Failure {
	f := h.fields
	if f[fUncleHash].List || !bytes.Equal(f[fUncleHash].Content, emptyUncleHash) {
		return &Failure{"H3", "UncleHash is not the hash of an empty list"}
	}
	if d, err := f[fDifficulty].Uint(); err != nil || d.Cmp(big.NewInt(1)) != 0 {
		return &Failure{"H4", fmt.Sprintf("Difficulty is %s, not 1", value(f[fDifficulty]))}
	}
	limit, err := f[fGasLimit].Uint()
	if err != nil || limit.BitLen() > maxGasLimitBitLen {
		return &Failure{"H5", fmt.Sprintf("GasLimit %s is above 2^63-1", value(f[fGasLimit]))}
	}
	// The optional fields are positional, so the H9 fields (BlobGasUsed,
	// ExcessBlobGas, ParentBeaconRoot) come only after WithdrawalsHash:
	// a header with one of them fails H7 first.
	if len(f) > fWithdrawalsHash {
		return &Failure{"H7", "WithdrawalsHash is present"}
	}
	if new(big.Int).And(h.Number, new(big.Int).SetUint64(^uint64(0))).Sign() == 0 {
		return nil
	}
	if used, err := f[fGasUsed].Uint(); err != nil || used.Cmp(limit) > 0 {
		return &Failure{"H13", fmt.Sprintf("GasUsed %s is above GasLimit %s", value(f[fGasUsed]), limit)}
	}
	if f[fExtra].List {
		return &Failure{"H16", "Extra is a list, not bytes"}
	}
	if x, err := rlp.Items(f[fExtra].Content); err != nil || len(x) != extraElements {
		return &Failure{"H16", fmt.Sprintf("Extra does not decode as ten list elements (%d, %v)", len(x), err)}
	}
	return nil
}

// value formats an integer field, or its bytes when it is not one.
func value(it rlp.Item) string {
	if v, err := it.Uint(); err == nil {
		return v.String()
	}
	return "0x" + hex.EncodeToString(it.Content)
}

var stepRE = regexp.MustCompile(`^(P[1-7]|V0[ab]|H([1-9]|1[0-9]|2[01])[ab]?)$`)

// Order returns the position of a verification step in the order a node
// applies them (A-08 §5 and §6): P1 .. P5, then the header steps H1 ..
// H21 inside P6, then P7. The validator-set steps V0a and V0b belong to
// P3. ok is false for an empty or unknown step.
func Order(step string) (pos int, ok bool) {
	m := stepRE.FindStringSubmatch(step)
	if m == nil {
		return 0, false
	}
	switch step[0] {
	case 'V':
		return 300, true
	case 'P':
		n, _ := strconv.Atoi(step[1:2])
		if n == 7 {
			return 900, true
		}
		return n * 100, true
	default:
		n, _ := strconv.Atoi(m[2])
		return 600 + n, true
	}
}
