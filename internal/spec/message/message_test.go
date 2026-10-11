package message

import (
	"bufio"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/yamlsubset"
)

// prepareKey1 is the payload of the wbft-spec case
// encoding/message_codec/prepare_key1: a PREPARE by key 1 for (2, 0).
const prepareKey1 = "0xf8caf8850280a06284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1eb860b9ed2c8ca8ef593fa5b1749082a5bc211460b913a9c5a3eec8770d5acff6bf6501dfa61735f6cdd045e5e75a9489801a0bca5554be5abae320e5d883dae61838ad5765c1427cb4a5672dabd5649969760505ff7aaee60aa2e2e5a623af1726a1b841210a2b4c90e9be64976a7b81aab05aad51146d6abc3bd0061f7a35af8290e6ae31038a77129d7441c68ade4ea87372a481e343a794b711f3cb8ff5b4d6b7bd5501"

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestDecode reads the view, digest and signer of prepare_key1, and refuses
// it under another code, truncated, and with its signature changed.
func TestDecode(t *testing.T) {
	p := unhex(t, prepareKey1)
	m, err := Decode(CodePrepare, p)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(m.Signer[:]) != "1111f6010b9b757b30e00a7d519cd98094b7a610" || m.Sequence.String() != "2" || m.Round.String() != "0" ||
		!m.HasDigest || hex.EncodeToString(m.Digest[:]) != "6284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e" {
		t.Fatalf("decoded %+v", m)
	}
	// The same payload as a COMMIT is signed over another code: another
	// signer, or none.
	if c, err := Decode(CodeCommit, p); err == nil && c.Signer == m.Signer {
		t.Fatal("the code is not part of the signed bytes")
	}
	if _, err := Decode(CodePreprepare, p); err == nil {
		t.Fatal("a PREPARE decoded as a PRE-PREPARE")
	}
	if _, err := Decode(CodePrepare, p[:len(p)-1]); err == nil {
		t.Fatal("a truncated payload decoded")
	}
	q := append([]byte(nil), p...)
	q[len(q)-2] ^= 1 // in S
	if c, err := Decode(CodePrepare, q); err == nil && c.Signer == m.Signer {
		t.Fatal("a changed signature recovers the same signer")
	}
}

// TestSpecVectors decodes every case of encoding/message_codec that wbft
// decodes (testdata/signers.txt) from the wbft-spec vector directory
// WBFT_SPEC_VECTORS names, and compares the signer, the view and the digest.
func TestSpecVectors(t *testing.T) {
	dir := os.Getenv("WBFT_SPEC_VECTORS")
	if dir == "" {
		t.Skip("WBFT_SPEC_VECTORS is not set")
	}
	f, err := os.Open(filepath.Join("testdata", "signers.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	for sc := bufio.NewScanner(f); sc.Scan(); {
		w := strings.Fields(sc.Text())
		if len(w) == 0 || strings.HasPrefix(w[0], "#") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, "encoding", "message_codec", w[0], "input.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		in, err := yamlsubset.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := strconv.ParseUint(in["code"].(string), 10, 64)
		m, err := Decode(code, unhex(t, in["payload"].(string)))
		if err != nil {
			t.Errorf("%s: %v", w[0], err)
			continue
		}
		digest := "-"
		if m.HasDigest {
			digest = "0x" + hex.EncodeToString(m.Digest[:])
		}
		got := []string{"0x" + hex.EncodeToString(m.Signer[:]), m.Sequence.String(), m.Round.String(), digest}
		if strings.Join(got, " ") != strings.Join(w[1:], " ") {
			t.Errorf("%s: %v, want %v", w[0], got, w[1:])
		}
		n++
	}
	t.Logf("%d cases", n)
}
