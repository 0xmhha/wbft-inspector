package message

import (
	"errors"
	"fmt"

	"github.com/0xmhha/wbft-inspector/internal/spec/rlp"
)

// PrepareWitness is a recovered PREPARE, not a membership certificate.
type PrepareWitness struct {
	Message   *Message
	Signature []byte
	Nested    bool
	Index     int // original justification index; -1 for a direct PREPARE
}

// PrepareContainer keeps the outer signer separate from justification signers.
// Recovery is legacy-only and grants neither membership nor chain authority.
type PrepareContainer struct {
	Outer     *Message
	Witnesses []PrepareWitness
}

// DecodePrepareContainer recovers direct or flat justification PREPAREs. No
// witnesses escape when any member of the PREPARE array fails to decode.
// Declared signing profiles must be checked before calling this naked API.
func DecodePrepareContainer(code uint64, payload []byte) (*PrepareContainer, error) {
	items, err := preparePayloads(code, payload)
	if err != nil {
		return nil, err
	}
	outer, err := Decode(code, payload)
	if err != nil {
		return nil, err
	}
	witnesses, err := recoverPrepareWitnesses(code, items)
	if err != nil {
		return nil, err
	}
	return &PrepareContainer{Outer: outer, Witnesses: witnesses}, nil
}

func recoverPrepareWitnesses(code uint64, items []rlp.Item) ([]PrepareWitness, error) {
	var witnesses []PrepareWitness
	for i, item := range items {
		sig, err := prepareSignature(item)
		if err != nil {
			return nil, fmt.Errorf("message: prepare %d: %w", i, err)
		}
		m, err := Decode(CodePrepare, item.Raw)
		if err != nil {
			return nil, fmt.Errorf("message: prepare %d: %w", i, err)
		}
		index := i
		if code == CodePrepare {
			index = -1
		}
		witnesses = append(witnesses, PrepareWitness{Message: m,
			Signature: append([]byte(nil), sig...), Nested: code != CodePrepare, Index: index})
	}
	return witnesses, nil
}

// preparePayloads only splits unsigned RLP shapes. It verifies no signatures.
func preparePayloads(code uint64, payload []byte) ([]rlp.Item, error) {
	parts, err := rlp.Items(payload)
	if err != nil {
		return nil, err
	}
	switch code {
	case CodePrepare:
		item, rest, err := rlp.Split(payload)
		if err != nil || len(rest) != 0 {
			return nil, errors.New("message: invalid direct prepare")
		}
		return []rlp.Item{item}, nil
	case CodePreprepare:
		if len(parts) != 2 {
			return nil, errors.New("message: pre-prepare requires two items")
		}
		if err := observationOuterSignature(parts[0]); err != nil {
			return nil, err
		}
		justification, err := parts[1].Items()
		if err != nil || len(justification) != 2 || !justification[0].List || !justification[1].List {
			return nil, errors.New("message: invalid pre-prepare justification")
		}
		// Signed RC prepared tuples are not additional PREPARE votes.
		return justification[1].Items()
	case CodeRoundChange:
		if len(parts) != 3 {
			return nil, errors.New("message: round change requires three items")
		}
		if err := observationOuterSignature(parts[0]); err != nil {
			return nil, err
		}
		j := parts[2]
		// The core also reads a bare byte as absent, as well as empty
		// strings/lists. A nonempty encoded string is not a vote list.
		if len(j.Content) == 0 || !j.List && len(j.Raw) == 1 {
			return nil, nil
		}
		return j.Items()
	default:
		return nil, errors.New("message: not a prepare observation container")
	}
}

func observationOuterSignature(item rlp.Item) error {
	parts, err := item.Items()
	if err != nil || len(parts) != 2 || parts[1].List {
		return errors.New("message: invalid outer signed payload shape")
	}
	return nil
}

func prepareSignature(item rlp.Item) ([]byte, error) {
	parts, err := item.Items()
	if err != nil || len(parts) != 2 || parts[1].List {
		return nil, errors.New("invalid signed PREPARE shape")
	}
	fields, err := parts[0].Items()
	if err != nil || len(fields) != 4 || fields[2].List || len(fields[2].Content) != 32 || fields[3].List {
		return nil, errors.New("invalid PREPARE fields")
	}
	return parts[1].Content, nil
}
