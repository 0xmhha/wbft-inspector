// Package rlp is the part of RLP decoding the inspector needs: splitting an
// encoding into its items with the canonical-size rules (a single byte below
// 0x80 is its own encoding, a long form only above 55 bytes and without
// leading zeros in its length), unsigned integers, and the encoding of a
// list from raw items.
package rlp

import (
	"errors"
	"math/big"
)

// Item is one decoded item.
type Item struct {
	List    bool
	Content []byte // the string's bytes, or the encoding of the list's items
	Raw     []byte // the whole encoding of the item
}

// ErrNonCanonical is returned for an encoding that is not the canonical one,
// ErrTruncated for one shorter than its header says.
var (
	ErrNonCanonical = errors.New("rlp: non-canonical encoding")
	ErrTruncated    = errors.New("rlp: truncated")
	ErrNotList      = errors.New("rlp: not a list")
	ErrTrailing     = errors.New("rlp: trailing bytes")
)

// Split decodes the first item of b and returns it with the bytes after it.
func Split(b []byte) (Item, []byte, error) {
	if len(b) == 0 {
		return Item{}, nil, ErrTruncated
	}
	h := b[0]
	var list bool
	var off, size int
	switch {
	case h < 0x80:
		return Item{Content: b[:1], Raw: b[:1]}, b[1:], nil
	case h < 0xb8:
		off, size = 1, int(h-0x80)
		if size == 1 && len(b) > 1 && b[1] < 0x80 {
			return Item{}, nil, ErrNonCanonical
		}
	case h < 0xc0:
		var err error
		if off, size, err = long(b, int(h-0xb7)); err != nil {
			return Item{}, nil, err
		}
	case h < 0xf8:
		list, off, size = true, 1, int(h-0xc0)
	default:
		var err error
		list = true
		if off, size, err = long(b, int(h-0xf7)); err != nil {
			return Item{}, nil, err
		}
	}
	if len(b) < off+size {
		return Item{}, nil, ErrTruncated
	}
	return Item{List: list, Content: b[off : off+size], Raw: b[:off+size]}, b[off+size:], nil
}

// long reads a long-form length of n bytes after the header byte.
func long(b []byte, n int) (off, size int, err error) {
	if len(b) < 1+n {
		return 0, 0, ErrTruncated
	}
	if b[1] == 0 || n > 4 {
		return 0, 0, ErrNonCanonical
	}
	for _, c := range b[1 : 1+n] {
		size = size<<8 | int(c)
	}
	if size <= 55 {
		return 0, 0, ErrNonCanonical
	}
	return 1 + n, size, nil
}

// Items decodes b, which must be exactly one list, into its items.
func Items(b []byte) ([]Item, error) {
	it, rest, err := Split(b)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, ErrTrailing
	}
	return it.Items()
}

// Items returns the items of a list item.
func (it Item) Items() ([]Item, error) {
	if !it.List {
		return nil, ErrNotList
	}
	var out []Item
	for c := it.Content; len(c) > 0; {
		x, rest, err := Split(c)
		if err != nil {
			return nil, err
		}
		out, c = append(out, x), rest
	}
	return out, nil
}

// Uint returns the unsigned integer of a string item: big-endian without
// leading zeros, the empty string for zero.
func (it Item) Uint() (*big.Int, error) {
	if it.List {
		return nil, errors.New("rlp: a list, not an integer")
	}
	if len(it.Content) > 0 && it.Content[0] == 0 {
		return nil, ErrNonCanonical
	}
	return new(big.Int).SetBytes(it.Content), nil
}

// EncodeList returns the encoding of a list of already encoded items.
func EncodeList(items ...[]byte) []byte {
	n := 0
	for _, it := range items {
		n += len(it)
	}
	out := header(0xc0, n)
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

// EncodeUint returns the encoding of v.
func EncodeBytes(b []byte) []byte {
	if len(b) == 1 && b[0] < 0x80 {
		return append([]byte{}, b...)
	}
	return append(header(0x80, len(b)), b...)
}

func EncodeUint(v uint64) []byte {
	switch {
	case v == 0:
		return []byte{0x80}
	case v < 0x80:
		return []byte{byte(v)}
	}
	b := new(big.Int).SetUint64(v).Bytes()
	return append(header(0x80, len(b)), b...)
}

func header(base byte, n int) []byte {
	if n <= 55 {
		return []byte{base + byte(n)}
	}
	l := new(big.Int).SetInt64(int64(n)).Bytes()
	return append([]byte{base + 55 + byte(len(l))}, l...)
}
