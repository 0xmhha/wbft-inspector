// Package keccak is Keccak-256 as Ethereum and wbft-spec use it (the
// original Keccak padding 0x01, not the SHA3-256 padding of crypto/sha3),
// and the message dedup key of wbft-spec A-03.
package keccak

import "math/bits"

const rate = 136 // bytes absorbed per permutation for a 256-bit output

var roundConstants = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// rotations[x+5y] is the rotation of lane (x, y) in the rho step.
var rotations = [25]int{
	0, 1, 62, 28, 27,
	36, 44, 6, 55, 20,
	3, 10, 43, 25, 39,
	41, 45, 15, 21, 8,
	18, 2, 61, 56, 14,
}

// permute is Keccak-f[1600] on the state a, lane (x, y) at a[x+5y].
func permute(a *[25]uint64) {
	var c [5]uint64
	var b [25]uint64
	for _, rc := range roundConstants {
		// theta
		for x := range 5 {
			c[x] = a[x] ^ a[x+5] ^ a[x+10] ^ a[x+15] ^ a[x+20]
		}
		for x := range 5 {
			d := c[(x+4)%5] ^ bits.RotateLeft64(c[(x+1)%5], 1)
			for y := 0; y < 25; y += 5 {
				a[x+y] ^= d
			}
		}
		// rho and pi: lane (x, y) moves to (y, 2x + 3y).
		for x := range 5 {
			for y := range 5 {
				b[y+5*((2*x+3*y)%5)] = bits.RotateLeft64(a[x+5*y], rotations[x+5*y])
			}
		}
		// chi
		for y := 0; y < 25; y += 5 {
			for x := range 5 {
				a[x+y] = b[x+y] ^ (^b[(x+1)%5+y] & b[(x+2)%5+y])
			}
		}
		// iota
		a[0] ^= rc
	}
}

// Sum256 returns the Keccak-256 hash of data.
func Sum256(data []byte) [32]byte {
	var a [25]uint64
	absorb := func(block []byte) {
		for i := range rate / 8 {
			var lane uint64
			for j := range 8 {
				lane |= uint64(block[8*i+j]) << (8 * j)
			}
			a[i] ^= lane
		}
		permute(&a)
	}
	for len(data) >= rate {
		absorb(data[:rate])
		data = data[rate:]
	}
	var last [rate]byte
	copy(last[:], data)
	last[len(data)] ^= 0x01
	last[rate-1] ^= 0x80
	absorb(last[:])
	var out [32]byte
	for i := range 4 {
		for j := range 8 {
			out[8*i+j] = byte(a[i] >> (8 * j))
		}
	}
	return out
}

// DedupKey is dedup_key(payload) of wbft-spec A-03: the Keccak-256 hash of
// the payload encoded as an RLP byte string.
func DedupKey(payload []byte) [32]byte {
	return Sum256(rlpString(payload))
}

// rlpString encodes b as an RLP byte string.
func rlpString(b []byte) []byte {
	switch {
	case len(b) == 1 && b[0] < 0x80:
		return []byte{b[0]}
	case len(b) < 56:
		return append([]byte{0x80 + byte(len(b))}, b...)
	}
	var n []byte
	for l := len(b); l > 0; l >>= 8 {
		n = append([]byte{byte(l)}, n...)
	}
	out := append([]byte{0xb7 + byte(len(n))}, n...)
	return append(out, b...)
}
