// Package net holds the checkers of wbft-spec A-07 (network layer) that
// decide from frame dumps (R-01).
package net

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/0xmhha/wbft-inspector/internal/check"
	"github.com/0xmhha/wbft-inspector/internal/frames"
	"github.com/0xmhha/wbft-inspector/internal/verdict"
)

func init() {
	check.Register(frameCodes{check.Base{ID: "net.frame_codes",
		Reqs:  []string{"WBFT-NET-011", "WBFT-NET-013", "WBFT-NET-020", "WBFT-NET-021", "WBFT-NET-027", "WBFT-NET-028"},
		Kinds: []check.Kind{check.Frames}}})
}

// Codes and limits of A-07.
const (
	codeNewBlock      = 0x07
	codeLegacy        = 0x11
	codeFirst         = 0x12 // PRE-PREPARE
	codeLast          = 0x15 // ROUND-CHANGE
	maxIstanbulMsgLen = 10 << 20
)

// emptySHA256 is the payload hash of a frame with an empty payload.
var emptySHA256 = func() string { s := sha256.Sum256(nil); return hex.EncodeToString(s[:]) }()

// frameCodes decides the rules of A-07 that follow from a frame's code,
// size and receive outcome alone:
//
//   - WBFT-NET-011: a node sends only codes 0x12..0x15.
//   - WBFT-NET-013: a received frame longer than MAX_ISTANBUL_MSG_SIZE
//     disconnects the peer.
//   - WBFT-NET-020: received codes 0x00..0x10 other than 0x07 are
//     discarded (DROP_SILENT) whatever the engine state. For codes
//     0x11..0x15 the row follows the frame's engine state: discarded while
//     the node synchronises (syncing), the peer disconnected when the engine
//     is stopped otherwise. With the engine running the message goes to the
//     duplicate check (A-07 §5.3), decided elsewhere. A frame without an
//     engine state has no instance.
//   - WBFT-NET-027: the same two stopped-engine rows.
//   - WBFT-NET-021: an empty payload under 0x12..0x15 disconnects the peer.
//   - WBFT-NET-028: a received 0x07 does not disconnect the peer unless it
//     is too large.
//
// The size is known from a frame whose payload the dump holds, and from a
// frame recorded without its payload (too large to keep) that carries a
// non-zero size. A dump that wrote such a frame with size 0 (earlier wbft
// exports) leaves it without an instance of WBFT-NET-013.
type frameCodes struct{ check.Base }

func (c frameCodes) Run(_ context.Context, in *check.Inputs, out check.Emitter) error {
	for _, d := range in.Frames {
		// The outcomes the core recorded later for a received frame.
		later := map[[3]string]string{}
		for _, r := range d.Records {
			if r.Type == "outcome" && r.Of != nil {
				k := [3]string{r.File, r.Run, strconv.FormatUint(*r.Of, 10)}
				if _, ok := later[k]; !ok {
					later[k] = r.Outcome
				}
			}
		}
		for _, r := range d.Records {
			if r.Type != "frame" {
				continue
			}
			code, err := strconv.ParseUint(r.Code, 0, 64)
			if err != nil {
				continue // frames verify reports it
			}
			switch r.Dir {
			case "out":
				sendCode(r, code, out)
			case "in":
				receive(r, code, out)
				stoppedEngine(r, code, later[[3]string{r.File, r.Run, strconv.FormatUint(r.Seq, 10)}], out)
			}
		}
	}
	return nil
}

func emit(out check.Emitter, req string, r *frames.Record, ok bool, msg string) {
	v := verdict.Pass
	if !ok {
		v = verdict.Fail
	}
	out.Emit(check.FrameInstance(req, r, v, "", msg))
}

func sendCode(r *frames.Record, code uint64, out check.Emitter) {
	ok := code >= codeFirst && code <= codeLast
	emit(out, "WBFT-NET-011", r, ok, fmt.Sprintf("sent code %#x", code))
}

func receive(r *frames.Record, code uint64, out check.Emitter) {
	known := r.Size != nil && (r.Payload != "" || *r.Size > 0)
	large := known && *r.Size > maxIstanbulMsgLen
	disconnect := r.Outcome == "DISCONNECT"
	if large {
		emit(out, "WBFT-NET-013", r, disconnect, fmt.Sprintf("received %d bytes, outcome %s", *r.Size, r.Outcome))
	}
	switch {
	case code == codeNewBlock:
		if !large {
			emit(out, "WBFT-NET-028", r, !disconnect, "received 0x07, outcome "+r.Outcome)
		}
	case code < codeLegacy:
		emit(out, "WBFT-NET-020", r, r.Outcome == "DROP_SILENT", fmt.Sprintf("received %#x, outcome %s (want DROP_SILENT)", code, r.Outcome))
	case code >= codeFirst && code <= codeLast && r.Payload == emptySHA256:
		emit(out, "WBFT-NET-021", r, disconnect, fmt.Sprintf("received %#x with an empty payload, outcome %s", code, r.Outcome))
	}
}

// stoppedEngine decides the rows of WBFT-NET-020 and WBFT-NET-027 for a
// consensus code received while the engine was not running. The outcome is
// the frame's, or, when the frame waited for the core (PENDING), the first
// outcome recorded for it.
func stoppedEngine(r *frames.Record, code uint64, later string, out check.Emitter) {
	if code < codeLegacy || code > codeLast {
		return
	}
	var want string
	switch r.Engine {
	case "syncing":
		want = "DROP_SILENT"
	case "stopped":
		want = "DISCONNECT"
	default:
		return
	}
	got := r.Outcome
	if got == "PENDING" {
		got = later
	}
	for _, req := range []string{"WBFT-NET-020", "WBFT-NET-027"} {
		if got == "" {
			out.Emit(check.FrameInstance(req, r, verdict.CannotDecide, verdict.MissingData,
				fmt.Sprintf("received %#x with the engine %s; no outcome was recorded for it", code, r.Engine)))
			continue
		}
		emit(out, req, r, got == want, fmt.Sprintf("received %#x with the engine %s, outcome %s (want %s)", code, r.Engine, got, want))
	}
}
