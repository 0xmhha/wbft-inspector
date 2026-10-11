// Package secp256k1 recovers the signer of an Ethereum-style ECDSA signature
// over secp256k1 with the acceptance rules of the cgo build of the
// reference (wbft-spec A-02 §8.2, WBFT-CRYPTO-013, WBFT-CRYPTO-014): the
// signature is R || S || V, 65 bytes, with V below 4; R and S lie in
// [1, n-1]; a high S is accepted. The inspector only reads public data, so
// the arithmetic is plain math/big and not constant-time.
package secp256k1

import (
	"errors"
	"math/big"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
)

var (
	p  = hexInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f")
	n  = hexInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")
	gx = hexInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
	gy = hexInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
	// sqrtExp is (p+1)/4: p = 3 mod 4, so a square root of a is a^sqrtExp.
	sqrtExp = new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(1)), 2)
)

func hexInt(s string) *big.Int {
	v, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("secp256k1: bad constant " + s)
	}
	return v
}

// ErrInvalidSignature is returned for a signature the reference rejects.
var ErrInvalidSignature = errors.New("secp256k1: invalid signature")

// point is a point in Jacobian coordinates (x/z², y/z³); z = 0 is the point
// at infinity.
type point struct{ x, y, z *big.Int }

func infinity() point { return point{new(big.Int), new(big.Int), new(big.Int)} }

func (a point) isInfinity() bool { return a.z.Sign() == 0 }

func mod(v *big.Int) *big.Int { return v.Mod(v, p) }

func mul(a, b *big.Int) *big.Int { return mod(new(big.Int).Mul(a, b)) }

func sub(a, b *big.Int) *big.Int { return mod(new(big.Int).Sub(a, b)) }

// double is dbl-2009-l for a = 0.
func double(a point) point {
	if a.isInfinity() || a.y.Sign() == 0 {
		return infinity()
	}
	A := mul(a.x, a.x)
	B := mul(a.y, a.y)
	C := mul(B, B)
	t := new(big.Int).Add(a.x, B)
	D := sub(mul(t, t), new(big.Int).Add(A, C))
	D = mod(D.Lsh(D, 1))
	E := mod(new(big.Int).Mul(A, big.NewInt(3)))
	F := mul(E, E)
	x3 := sub(F, new(big.Int).Lsh(D, 1))
	y3 := sub(mul(E, sub(D, x3)), new(big.Int).Lsh(C, 3))
	z3 := mod(new(big.Int).Lsh(mul(a.y, a.z), 1))
	return point{x3, y3, z3}
}

// add is add-2007-bl.
func add(a, b point) point {
	switch {
	case a.isInfinity():
		return b
	case b.isInfinity():
		return a
	}
	z1z1, z2z2 := mul(a.z, a.z), mul(b.z, b.z)
	u1, u2 := mul(a.x, z2z2), mul(b.x, z1z1)
	s1, s2 := mul(mul(a.y, b.z), z2z2), mul(mul(b.y, a.z), z1z1)
	h := sub(u2, u1)
	r := mod(new(big.Int).Lsh(sub(s2, s1), 1))
	if h.Sign() == 0 {
		if r.Sign() == 0 {
			return double(a)
		}
		return infinity()
	}
	i := mod(new(big.Int).Lsh(h, 1))
	i = mul(i, i)
	j := mul(h, i)
	v := mul(u1, i)
	x3 := sub(sub(mul(r, r), j), new(big.Int).Lsh(v, 1))
	y3 := sub(mul(r, sub(v, x3)), new(big.Int).Lsh(mul(s1, j), 1))
	zs := new(big.Int).Add(a.z, b.z)
	z3 := mul(sub(mul(zs, zs), new(big.Int).Add(z1z1, z2z2)), h)
	return point{x3, y3, z3}
}

// scalarMult returns k·a by double and add.
func scalarMult(a point, k *big.Int) point {
	r := infinity()
	for i := k.BitLen() - 1; i >= 0; i-- {
		r = double(r)
		if k.Bit(i) == 1 {
			r = add(r, a)
		}
	}
	return r
}

// affine returns the affine coordinates of a finite point.
func (a point) affine() (x, y *big.Int) {
	zi := new(big.Int).ModInverse(a.z, p)
	zi2 := mul(zi, zi)
	return mul(a.x, zi2), mul(a.y, mul(zi2, zi))
}

// Recover returns the address (the last 20 bytes of keccak256 of the
// uncompressed public key without its prefix) that signed hash with sig.
func Recover(hash [32]byte, sig []byte) ([20]byte, error) {
	var addr [20]byte
	if len(sig) != 65 || sig[64] >= 4 {
		return addr, ErrInvalidSignature
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	v := sig[64]
	if r.Sign() == 0 || r.Cmp(n) >= 0 || s.Sign() == 0 || s.Cmp(n) >= 0 {
		return addr, ErrInvalidSignature
	}
	// R: x = r (+ n for V >= 2), y of the parity of V.
	x := new(big.Int).Set(r)
	if v >= 2 {
		x.Add(x, n)
	}
	if x.Cmp(p) >= 0 {
		return addr, ErrInvalidSignature
	}
	alpha := mod(new(big.Int).Add(new(big.Int).Exp(x, big.NewInt(3), p), big.NewInt(7)))
	y := new(big.Int).Exp(alpha, sqrtExp, p)
	if mul(y, y).Cmp(alpha) != 0 {
		return addr, ErrInvalidSignature
	}
	if y.Bit(0) != uint(v&1) {
		y.Sub(p, y)
	}
	R := point{x, y, big.NewInt(1)}
	// Q = r⁻¹ (s·R − e·G).
	e := new(big.Int).SetBytes(hash[:])
	e.Mod(e, n)
	rInv := new(big.Int).ModInverse(r, n)
	u1 := new(big.Int).Mul(new(big.Int).Sub(n, e), rInv)
	u1.Mod(u1, n)
	u2 := new(big.Int).Mul(s, rInv)
	u2.Mod(u2, n)
	q := add(scalarMult(point{gx, gy, big.NewInt(1)}, u1), scalarMult(R, u2))
	if q.isInfinity() {
		return addr, ErrInvalidSignature
	}
	qx, qy := q.affine()
	var pub [64]byte
	qx.FillBytes(pub[:32])
	qy.FillBytes(pub[32:])
	h := keccak.Sum256(pub[:])
	copy(addr[:], h[12:])
	return addr, nil
}
