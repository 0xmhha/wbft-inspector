# WBFT transport capture overlay

This tool adds opt-in wire-frame observation to a clean, isolated checkout of
source commit `740526d0375a8aca817b580e7a4bfc4c1028ae29`. It verifies source
file hashes and renders a Go overlay outside the checkout. It never edits the
source, changes protocol bytes, or publishes captured input files.

Activate Go 1.26.8 with gvm, then run:

```sh
python3 -B tools/tapbuild/overlay.py --source /private/source-checkout \
  --out /private/overlay --build /private/node-with-capture
```

To capture, set `WBFT_TAP_DIR` to a private absolute directory and
`WBFT_TAP_NODE` to the recording validator's public address. Confirm that this
address matches the node before importing the input. With no capture directory,
the original protocol reader/writer is returned unchanged. The CLI flushes
queued observations on normal shutdown. Abrupt termination leaves an unknown
tail. The bounded queue emits dropped-record evidence instead of claiming a
complete stream after overflow.

The directory holds R-01 `frames-<run>.jsonl` and private content-addressed
payloads. Received bytes are observed through the existing reads; the tap never
drains or eagerly consumes a message. Write results preserve the original
return error and distinguish explicit `ok` from `error`. The optional
`write_result` field on outgoing frames is `ok`, `error`, or `not_attached`;
absence in older captures does not prove a successful write.

Optional `io` endpoints bracket the existing write call or the read call plus
its actual payload consumption. They use the same monotonic origin as the
frame record. A read may include waiting; partial or interrupted reads have no
completed interval. Endpoints are sampled before hashing, serialization, and
queued file writes. The existing frame timestamp remains unchanged. Clock
regressions are retained; intervals do not justify correcting latency or
claiming delivery coverage.

The overlay manifest pins original and replacement hashes. A clean source
revision in Go build info does **not** mean an overlay binary is unmodified;
retain the overlay manifest and binary hash with every capture.

This stage records wire bytes and stream lifecycle. Engine outcomes remain
`PENDING`, and send cause, delivery coverage and cross-node stream order remain
unavailable. It does not establish packet loss, resolve repeated transmissions,
or complete the tapped-versus-original block-hash/round-distribution acceptance.
Those require subsequent evidence and physical-node validation.


## Runtime sidecar

The same opt-in directory also contains `observations-<run>.jsonl`, with its own
sequence and queue-loss count. These rows are not R-01 frames or native engine
events. A successful backend start snapshots scalar effective configuration at
the explicitly recorded next height: request timeout (milliseconds), block
period and future-block allowance (seconds), epoch, maximum timeout, proposer
policy ID and counts of transitions/upgrades. Later effective configuration,
policy sorting, native options, WAL/sign floor and per-node clock calibration
are not established by this snapshot.

Real call boundaries identify `backend_start`, `worker_commit_work`,
`insert_chain` and `write_block_and_set_head` with operation IDs. They preserve
original returns and errors, recording only fixed outcome names. A worker return
is not proof of proposal submission. A batch import return is not a per-block
canonical commit or a consensus commit timestamp. Missing start/end records,
queue overflow and abrupt termination retain incomplete capture status.

The pinned backend's `Close` method is a no-op. Its `runtime_close` observation
explicitly records `engine_stopped: false`, independently of an actual `Stop`
return. A normal CLI flush does not prove that the engine called Stop.

On normal flush, `capture_end` records dropped observation count. Opening errors
and identity mismatch surface at CLI flush without substituting engine errors.
The original frame sequence remains independent. Validate a file with:

```sh
python3 -B tools/tapbuild/verify_observations.py /private/capture/observations-run.jsonl
```

Exit 0 validates complete sidecar call boundaries, 65 indicates missing evidence and
64 indicates malformed structure. None of these establishes a complete runtime
model, application request completion, receiver coverage, or physical equivalence.

Task sealing stages retain the original worker operation token through the
copied environment, actual task, and an optional observed backend Seal method.
Disabled calls use the original Seal method and create no observation file.
The task records offer, transfer, receipt, duplicate/skip, abandonment and Seal
entry/return. Request post entry/return runs around the actual event-mux call in
its asynchronous goroutine; result-channel handover and cancellation are separate
stages. Identical block hashes never merge independent call tokens.

`wbft-inspector observations verify FILE` preserves exact root and stage lines,
and reports incomplete or ambiguous candidates without selecting nearby times.
Stage-aware output uses `wbft-tap-observations/2`; older sidecars keep version 1.
An observed result is a result-channel handover, not canonical import or consensus
acceptance. A function return is not asynchronous completion. Cross-goroutine
stage write order is not a total execution order. This capture still does not
establish the entire runtime/application model, receiver coverage, or physical
untapped equivalence.
