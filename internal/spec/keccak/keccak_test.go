package keccak

import (
	"encoding/hex"
	"testing"
)

func input(name string) []byte {
	seq := make([]byte, 300)
	for i := range seq {
		seq[i] = byte(i)
	}
	switch name {
	case "empty":
		return []byte{}
	case "abc":
		return []byte("abc")
	case "byte7f":
		return []byte{0x7f}
	case "byte80":
		return []byte{0x80}
	case "seq55":
		return seq[:55]
	case "seq56":
		return seq[:56]
	case "seq136":
		return seq[:136]
	}
	return seq
}

// TestVectors compares Sum256 and DedupKey with values computed by the wbft
// implementation (crypto/keccak and codec.DedupKey): inputs around the RLP
// string boundaries (single byte below 0x80, 55 and 56 bytes) and the
// Keccak rate (136 bytes, several blocks).
func TestVectors(t *testing.T) {
	for _, v := range []struct{ name, sum, dedup string }{
		{"empty", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"},
		{"abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45", "0a84eec7fd0dd3e34ad0a673ab6b58d9eb77082630eb3999125e23c329511bd0"},
		{"byte7f", "5c179d3bfde4c521afc3d3944357db5ee881a69c237d67c9aa79aa7a027c40ea", "5c179d3bfde4c521afc3d3944357db5ee881a69c237d67c9aa79aa7a027c40ea"},
		{"byte80", "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421", "03a5bd6b27a2d8e22280d5a3fd7f8efd489f8a9731ee5bfe999dcfd4a2c56b86"},
		{"seq55", "797f92d5e159d80a886c0a7802a255b475a1e8e473e8cf4345144824a2aee79c", "82b0e4654f7a0a22e51e917e14ae3412f03ec8c4329c361fe46e2516417f8022"},
		{"seq56", "0d0bf4902a749dee22eae5f1b6e2b867ba696ce9be7632eba14315ac09bd1856", "fcf3a676b26792aa84d23ef03be6873c93bbb887b97ce1c04e6ad09942e55ae4"},
		{"seq136", "7ce759f1ab7f9ce437719970c26b0a66ff11fe3e38e17df89cf5d29c7d7f807e", "54d7cb160323fd88c72c9cbdc15e817fabcadc5e6161212e7605f6b4fdb48651"},
		{"seq300", "a679e749a6af300c36e7ff2255d220864eab27b382f9cfdc5aa4d13563ba36ff", "c62f9c59c624f15fda4fb903a73c763a7a8c2c9485188487ef91e27366ebd873"},
	} {
		in := input(v.name)
		s, d := Sum256(in), DedupKey(in)
		if hex.EncodeToString(s[:]) != v.sum || hex.EncodeToString(d[:]) != v.dedup {
			t.Errorf("%s: sum %x dedup %x", v.name, s, d)
		}
	}
}
