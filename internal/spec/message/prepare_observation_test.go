package message

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
	"github.com/0xmhha/wbft-inspector/internal/yamlsubset"
)

// These are unsigned container shapes, not signed conflicting messages.
func TestUnsignedPrepareJustificationShapes(t *testing.T) {
	empty := rlp.EncodeList()
	signed := rlp.EncodeList(empty, rlp.EncodeBytes(nil))
	vote := rlp.EncodeList(rlp.EncodeList(rlp.EncodeUint(2), rlp.EncodeUint(0),
		rlp.EncodeBytes(make([]byte, 32)), rlp.EncodeBytes(nil)), rlp.EncodeBytes(nil))
	for _, absent := range [][]byte{empty, rlp.EncodeBytes(nil), {0x01}, {0x7f}} {
		b := rlp.EncodeList(signed, empty, absent)
		got, err := preparePayloads(CodeRoundChange, b)
		if err != nil || len(got) != 0 {
			t.Fatalf("absent %x: %v %v", absent, got, err)
		}
	}
	for _, code := range []uint64{CodePreprepare, CodeRoundChange} {
		var b []byte
		if code == CodePreprepare {
			// The embedded RC placeholder is not another PREPARE.
			b = rlp.EncodeList(signed, rlp.EncodeList(rlp.EncodeList(signed), rlp.EncodeList(vote, vote)))
		} else {
			b = rlp.EncodeList(signed, empty, rlp.EncodeList(vote, vote))
		}
		got, err := preparePayloads(code, b)
		if err != nil || len(got) != 2 || !bytes.Equal(got[0].Raw, vote) || !bytes.Equal(got[1].Raw, vote) {
			t.Fatalf("code %x: %v %v", code, got, err)
		}
		if _, err := preparePayloads(code, append(b, 0x80)); err == nil {
			t.Fatal("trailing RLP accepted")
		}
	}
	for _, b := range [][]byte{
		rlp.EncodeList(signed, rlp.EncodeList(empty)),
		rlp.EncodeList(signed, rlp.EncodeList(empty, rlp.EncodeBytes([]byte{0x80}))),
	} {
		if _, err := preparePayloads(CodePreprepare, b); err == nil {
			t.Fatal("invalid PP justification accepted")
		}
	}
	if _, err := preparePayloads(CodeRoundChange, rlp.EncodeList(signed, empty, rlp.EncodeBytes([]byte{0x80}))); err == nil {
		t.Fatal("nonempty encoded string treated as absent")
	}
}

func TestSingleNormalPrepareObservationCopiesSignature(t *testing.T) {
	payload := unhex(t, prepareKey1)
	c, err := DecodePrepareContainer(CodePrepare, payload)
	if err != nil || len(c.Witnesses) != 1 {
		t.Fatalf("normal prepare: %+v %v", c, err)
	}
	w := c.Witnesses[0]
	if w.Nested || w.Index != -1 || w.Message.Sequence.String() != "2" || w.Message.Round.String() != "0" ||
		hex.EncodeToString(w.Message.Signer[:]) != "1111f6010b9b757b30e00a7d519cd98094b7a610" || len(w.Signature) != 65 {
		t.Fatalf("witness %+v", w)
	}
	saved := append([]byte(nil), w.Signature...)
	for i := range payload {
		payload[i] = 0
	}
	if !bytes.Equal(saved, w.Signature) {
		t.Fatal("signature aliases input payload")
	}
}

func TestUnsignedPrepareArrayHasNoPartialRecovery(t *testing.T) {
	// An unsigned array model with one existing normal signature; no signed
	// container or conflicting signature is constructed or delivered.
	first, _, err := rlp.Split(unhex(t, prepareKey1))
	if err != nil {
		t.Fatal(err)
	}
	bad, _, err := rlp.Split(rlp.EncodeList())
	if err != nil {
		t.Fatal(err)
	}
	got, err := recoverPrepareWitnesses(CodeRoundChange, []rlp.Item{first, bad})
	if err == nil || got != nil {
		t.Fatalf("partial result escaped: %+v %v", got, err)
	}
}

// The original specification job selects TestSpecVectors by prefix and
// supplies WBFT_SPEC_VECTORS. Only its normal, nonconflicting cases are read.
func TestSpecVectorsPrepareObservations(t *testing.T) {
	dir := os.Getenv("WBFT_SPEC_VECTORS")
	if dir == "" {
		t.Skip("WBFT_SPEC_VECTORS is not set")
	}
	for _, name := range []string{"round_change_prepared", "preprepare_round1_justified"} {
		b, err := os.ReadFile(filepath.Join(dir, "encoding", "message_codec", name, "input.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		in, err := yamlsubset.Parse(b)
		if err != nil {
			t.Fatal(err)
		}
		code, err := strconv.ParseUint(in["code"].(string), 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		c, err := DecodePrepareContainer(code, unhex(t, in["payload"].(string)))
		want := 1
		if name == "preprepare_round1_justified" {
			want = 3
		}
		if err != nil || len(c.Witnesses) != want {
			t.Fatalf("%s: %+v %v", name, c, err)
		}
		signers := map[string]bool{}
		for i, w := range c.Witnesses {
			if !w.Nested || w.Index != i || w.Message.Sequence.String() != "2" || w.Message.Round.String() != "0" || len(w.Signature) != 65 ||
				hex.EncodeToString(w.Message.Digest[:]) != "6284d1a2d0a027e77a8249b3ab24207ef68a2f5b98236cc4b044b6aaf5a10a1e" {
				t.Fatalf("%s: %+v", name, w)
			}
			signers[hex.EncodeToString(w.Message.Signer[:])] = true
		}
		if len(signers) != want || !signers["1111f6010b9b757b30e00a7d519cd98094b7a610"] {
			t.Fatalf("%s: wrong or replaced justification signers %v", name, signers)
		}
	}
}
