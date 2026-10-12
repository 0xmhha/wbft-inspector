package header

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

// Extra is the independently decoded A-03 consensus projection. Signatures
// remain bytes here: decoding is not aggregate-signature verification.
type Extra struct {
	Vanity, Randao                                   []byte
	PrevRound, Round                                 uint32
	PrevPrepared, PrevCommitted, Prepared, Committed []byte
	Epoch                                            *Epoch
	raw                                              []rlp.Item
}
type Candidate struct {
	Address   string
	Diligence uint64
}
type Epoch struct {
	Candidates []Candidate
	Validators []uint32
	Keys       [][]byte
}

func byteField(x rlp.Item, n int) ([]byte, error) {
	if x.List || (n >= 0 && len(x.Content) != n) {
		return nil, errors.New("wrong byte field type or size")
	}
	return x.Content, nil
}
func integer(x rlp.Item, bits int) (*big.Int, error) {
	n, err := x.Uint()
	if err != nil || (bits > 0 && n.BitLen() > bits) {
		return nil, errors.New("wrong integer type or size")
	}
	return n, nil
}
func nilStruct(x rlp.Item) bool { return len(x.Content) == 0 }
func seal(x rlp.Item) ([]byte, error) {
	if nilStruct(x) {
		return nil, nil
	}
	items, err := x.Items()
	if err != nil || len(items) != 2 {
		return nil, errors.New("seal must be a two-item list")
	}
	bitmap, err := byteField(items[0], -1)
	if err != nil {
		return nil, err
	}
	if _, err = byteField(items[1], -1); err != nil {
		return nil, err
	}
	return bitmap, nil
}
func DecodeExtra(data []byte) (*Extra, error) {
	x, err := rlp.Items(data)
	if err != nil || len(x) != 10 {
		return nil, errors.New("extra must be exactly ten RLP items")
	}
	e := &Extra{raw: x}
	if e.Vanity, err = byteField(x[0], -1); err != nil {
		return nil, err
	}
	if e.Randao, err = byteField(x[1], -1); err != nil {
		return nil, err
	}
	prev, err := integer(x[2], 32)
	if err != nil {
		return nil, err
	}
	round, err := integer(x[5], 32)
	if err != nil {
		return nil, err
	}
	e.PrevRound = uint32(prev.Uint64())
	e.Round = uint32(round.Uint64())
	if e.PrevPrepared, err = seal(x[3]); err != nil {
		return nil, err
	}
	if e.PrevCommitted, err = seal(x[4]); err != nil {
		return nil, err
	}
	if e.Prepared, err = seal(x[6]); err != nil {
		return nil, err
	}
	if e.Committed, err = seal(x[7]); err != nil {
		return nil, err
	}
	if _, err = integer(x[8], 0); err != nil {
		return nil, err
	}
	if !nilStruct(x[9]) {
		fields, err := x[9].Items()
		if err != nil || len(fields) != 3 {
			return nil, errors.New("epoch must be a three-item list")
		}
		e.Epoch = &Epoch{}
		candidates, err := fields[0].Items()
		if err != nil {
			return nil, err
		}
		for _, c := range candidates {
			pair, err := c.Items()
			if err != nil || len(pair) != 2 {
				return nil, errors.New("candidate must be an address/diligence pair")
			}
			addr, err := byteField(pair[0], 20)
			if err != nil {
				return nil, err
			}
			d, err := integer(pair[1], 64)
			if err != nil {
				return nil, err
			}
			e.Epoch.Candidates = append(e.Epoch.Candidates, Candidate{"0x" + hex.EncodeToString(addr), d.Uint64()})
		}
		validators, err := fields[1].Items()
		if err != nil {
			return nil, err
		}
		for _, v := range validators {
			idx, err := integer(v, 32)
			if err != nil {
				return nil, err
			}
			e.Epoch.Validators = append(e.Epoch.Validators, uint32(idx.Uint64()))
		}
		keys, err := fields[2].Items()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			raw, err := byteField(k, -1)
			if err != nil {
				return nil, err
			}
			e.Epoch.Keys = append(e.Epoch.Keys, raw)
		}
	}
	return e, nil
}
func (h *Header) Field(n int) (rlp.Item, bool) {
	if n < 0 || n >= len(h.fields) {
		return rlp.Item{}, false
	}
	return h.fields[n], true
}
func (h *Header) Extra() (*Extra, error) {
	x := h.fields[fExtra]
	if x.List {
		return nil, errors.New("extra must be bytes")
	}
	return DecodeExtra(x.Content)
}
func (h *Header) Coinbase() string   { return "0x" + hex.EncodeToString(h.fields[fCoinbase].Content) }
func (h *Header) ParentHash() string { return "0x" + hex.EncodeToString(h.fields[0].Content) }

// Hash implements A-03 ENC-082/084, including nil-structure normalization.
func (h *Header) Hash() string {
	fields := make([][]byte, len(h.fields))
	for i, f := range h.fields {
		fields[i] = f.Raw
	}
	d, err := h.fields[fDifficulty].Uint()
	if err == nil && d.Cmp(big.NewInt(1)) == 0 {
		if e, err := h.Extra(); err == nil {
			x := make([][]byte, 10)
			for i, f := range e.raw {
				x[i] = f.Raw
			}
			x[5] = rlp.EncodeUint(0)
			x[6] = rlp.EncodeList()
			x[7] = rlp.EncodeList()
			for _, i := range []int{3, 4, 9} {
				if nilStruct(e.raw[i]) {
					x[i] = rlp.EncodeList()
				}
			}
			fields[fExtra] = rlp.EncodeBytes(rlp.EncodeList(x...))
		}
	}
	hash := keccak.Sum256(rlp.EncodeList(fields...))
	return "0x" + hex.EncodeToString(hash[:])
}
func (e *Epoch) Addresses() ([]string, error) {
	if len(e.Keys) < len(e.Validators) {
		return nil, errors.New("epoch has fewer keys than validators")
	}
	out := make([]string, len(e.Validators))
	for i, v := range e.Validators {
		if int(v) >= len(e.Candidates) {
			return nil, fmt.Errorf("epoch validator index %d outside candidates", v)
		}
		out[i] = e.Candidates[v].Address
	}
	return out, nil
}
func Included(bitmap []byte, index int) bool {
	return index >= 0 && index/8 < len(bitmap) && bitmap[index/8]&(1<<uint(index%8)) != 0
}
