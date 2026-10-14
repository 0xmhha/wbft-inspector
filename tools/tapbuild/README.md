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

The overlay manifest pins original and replacement hashes. A clean source
revision in Go build info does **not** mean an overlay binary is unmodified;
retain the overlay manifest and binary hash with every capture.

This stage records wire bytes and stream lifecycle. Engine outcomes remain
`PENDING`, and send cause, delivery coverage and cross-node stream order remain
unavailable. It does not establish packet loss, resolve repeated transmissions,
or complete the tapped-versus-original block-hash/round-distribution acceptance.
Those require subsequent evidence and physical-node validation.
