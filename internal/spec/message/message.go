// Package message reads what the inspector needs from the devp2p payload of
// a consensus message (wbft-spec A-03): its view, its digest and its signer.
// The signer is recovered from message_signing_payload, rlp([code,
// signed_fields]), with the reference's recovery rules. It does not check a
// message any further: the node judged it, and the frame dump says how.
package message

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/0xmhha/wbft-inspector/internal/spec/keccak"
	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
	"github.com/0xmhha/wbft-inspector/internal/spec/secp256k1"
)

// Codes of the consensus messages.
const (
	CodePreprepare  uint64 = 0x12
	CodePrepare     uint64 = 0x13
	CodeCommit      uint64 = 0x14
	CodeRoundChange uint64 = 0x15
)

// Message is what Decode reads from a payload.
type Message struct {
	Code     uint64
	Sequence *big.Int
	Round    *big.Int
	// Digest is the voted digest of a PREPARE or COMMIT, the hash of the
	// proposed block's header for a PRE-PREPARE, and the prepared digest of
	// a ROUND-CHANGE; HasDigest is false for a PRE-PREPARE without a
	// proposal and a ROUND-CHANGE without a prepared round.
	Digest    [32]byte
	HasDigest bool
	Signer    [20]byte
	// Header is the RLP encoding of a PRE-PREPARE's proposal header, nil
	// for other messages and a PRE-PREPARE without a proposal.
	Header []byte
}

// Decode reads the message of code from payload and recovers its signer.
func Decode(code uint64, payload []byte) (*Message, error) {
	m := &Message{Code: code}
	var signed rlp.Item // the signed fields, signed by sig
	var sig []byte
	switch code {
	case CodePrepare, CodeCommit:
		// [[sequence, round, digest, seal], signature]
		outer, err := rlp.Items(payload)
		if err != nil {
			return nil, err
		}
		if len(outer) != 2 {
			return nil, fmt.Errorf("message: %d items, want 2", len(outer))
		}
		f, err := outer[0].Items()
		if err != nil || len(f) != 4 {
			return nil, fmt.Errorf("message: vote payload of %d items: %v", len(f), err)
		}
		if err := m.view(f[0], f[1]); err != nil {
			return nil, err
		}
		if f[2].List || len(f[2].Content) != 32 {
			return nil, errors.New("message: digest is not 32 bytes")
		}
		copy(m.Digest[:], f[2].Content)
		m.HasDigest = true
		signed, sig = outer[0], outer[1].Content
	case CodePreprepare:
		// [[[sequence, round, proposal], signature], [round_changes, prepares]]
		outer, err := rlp.Items(payload)
		if err != nil {
			return nil, err
		}
		if len(outer) != 2 {
			return nil, fmt.Errorf("message: %d items, want 2", len(outer))
		}
		sp, err := outer[0].Items()
		if err != nil || len(sp) != 2 {
			return nil, fmt.Errorf("message: signed payload of %d items: %v", len(sp), err)
		}
		f, err := sp[0].Items()
		if err != nil || len(f) != 3 {
			return nil, fmt.Errorf("message: pre-prepare payload of %d items: %v", len(f), err)
		}
		if err := m.view(f[0], f[1]); err != nil {
			return nil, err
		}
		// The proposal is a block [header, ...]; an empty list has none.
		block, err := f[2].Items()
		if err != nil {
			return nil, err
		}
		if len(block) > 0 {
			if !block[0].List {
				return nil, errors.New("message: proposal header is not a list")
			}
			m.Digest, m.HasDigest = keccak.Sum256(block[0].Raw), true
			m.Header = block[0].Raw
		}
		signed, sig = sp[0], sp[1].Content
	case CodeRoundChange:
		// [[[sequence, round, prepared], signature], prepared_block, justification]
		outer, err := rlp.Items(payload)
		if err != nil {
			return nil, err
		}
		if len(outer) != 3 {
			return nil, fmt.Errorf("message: %d items, want 3", len(outer))
		}
		sp, err := outer[0].Items()
		if err != nil || len(sp) != 2 {
			return nil, fmt.Errorf("message: signed round change of %d items: %v", len(sp), err)
		}
		f, err := sp[0].Items()
		if err != nil || len(f) != 3 {
			return nil, fmt.Errorf("message: round change payload of %d items: %v", len(f), err)
		}
		if err := m.view(f[0], f[1]); err != nil {
			return nil, err
		}
		prepared, err := f[2].Items()
		if err != nil {
			return nil, err
		}
		if len(prepared) == 2 && !prepared[1].List && len(prepared[1].Content) == 32 {
			copy(m.Digest[:], prepared[1].Content)
			m.HasDigest = true
		}
		signed, sig = sp[0], sp[1].Content
	default:
		return nil, fmt.Errorf("message: code %#x is not a consensus message", code)
	}
	signing := rlp.EncodeList(rlp.EncodeUint(code), signed.Raw)
	a, err := secp256k1.Recover(keccak.Sum256(signing), sig)
	if err != nil {
		return nil, err
	}
	m.Signer = a
	return m, nil
}

func (m *Message) view(seq, round rlp.Item) error {
	var err error
	if m.Sequence, err = seq.Uint(); err != nil {
		return err
	}
	m.Round, err = round.Uint()
	return err
}
