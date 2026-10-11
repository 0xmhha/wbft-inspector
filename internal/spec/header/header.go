// Package header decides the header rules of wbft-spec A-08 §6.2 that need
// nothing but the header itself and, for the randao reveal, the chain id:
// no parent, state, validator set, other chain configuration or clock.
package header

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
	"github.com/0xmhha/wbft-inspector/internal/spec/secp256k1"
)

// Field positions in the header list (A-03): the fifteen fields every
// header has, then the optional ones, each present only with those before
// it.
const (
	fUncleHash        = 1
	fCoinbase         = 2
	fDifficulty       = 7
	fNumber           = 8
	fGasLimit         = 9
	fGasUsed          = 10
	fTime             = 11
	fExtra            = 12
	nRequired         = 15
	fWithdrawalsHash  = 16
	extraElements     = 10
	xRandaoReveal     = 1 // position of the randao reveal in the extra (A-03)
	randaoVersion     = 1
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
	Step string // "H3" .. "H18"
	Why  string
}

// FirstFailure returns the first of the steps H3, H4, H5, H7, H13, H16
// and H18 that the header fails, in the order of A-08 §6.2, or nil. H18
// (the randao reveal recovers to Coinbase) is checked only with a chain
// id; chainID nil leaves it out. The other steps need more than the
// header; a node may fail one of them first, which comes before or after
// the returned step as Order says. H13, H16 and H18 are not reached by a
// block number 0 mod 2^64 (H10 returns), so they are not checked for one.
func (h *Header) FirstFailure(chainID *big.Int) *Failure {
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
	x, err := rlp.Items(f[fExtra].Content)
	if err != nil || len(x) != extraElements {
		return &Failure{"H16", fmt.Sprintf("Extra does not decode as ten list elements (%d, %v)", len(x), err)}
	}
	reveal := x[xRandaoReveal]
	if reveal.List {
		return &Failure{"H16", "the randao reveal in Extra is a list, not bytes"}
	}
	if chainID == nil {
		return nil
	}
	data := RandaoData(chainID, h.Number)
	signer, err := secp256k1.Recover(keccak.Sum256(data[:]), reveal.Content)
	if err != nil {
		return &Failure{"H18", fmt.Sprintf("the randao reveal does not recover (%v)", err)}
	}
	if f[fCoinbase].List || !bytes.Equal(signer[:], f[fCoinbase].Content) {
		return &Failure{"H18", fmt.Sprintf("the randao reveal recovers to 0x%x, not Coinbase 0x%x", signer, f[fCoinbase].Content)}
	}
	return nil
}

// RandaoData is randao_data(chain_id, number) of A-02 §7.1:
// keccak256(be_min(chain_id) ‖ 0x01 ‖ be_min(number)), where be_min(0)
// is empty. The reveal is the signature of its keccak256 (ecdsa_sign
// hashes its input).
func RandaoData(chainID, number *big.Int) [32]byte {
	pre := append(append(chainID.Bytes(), randaoVersion), number.Bytes()...)
	return keccak.Sum256(pre)
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
