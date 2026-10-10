# wbft-inspector

`wbft-inspector` checks implementations of WBFT, the consensus protocol of
StableNet, against the public specification
[wbft-spec](https://github.com/0xmhha/wbft-spec). It is an observer in the
sense of wbft-spec A-11 (conformance class `OB`): it does not behave as a
node, it decides from what nodes and implementations produce whether they
followed the requirements tagged `Observable:`.

It runs as a batch command and writes one JSON report per run. It has two
commands that decide requirements:

- `check` reads consensus event streams (JSON Lines) written by a node or a
  simulator and runs the checkers of the checker catalog on them.
- `vectors` runs the conformance vectors of wbft-spec against an
  implementation through the adapter protocol `wbft-vector/1` (A-11 §3.4)
  and reports every case and every requirement the cases cover.

This is the first public version. The checkers cover part of chapters A-05
(consensus state machine) and A-06 (timers); see [Coverage](#coverage).

## Build

Go 1.26.8 or later. The inspector module depends on the Go standard library
only.

```sh
go build -o bin/wbft-inspector ./cmd/wbft-inspector
go build -o bin/self-adapter ./adapters/self    # optional, see "vectors"
```

## check: event streams

```sh
wbft-inspector check --events events/ --chain-config genesis.json --out report.json
```

- `--events PATH` (repeatable) is an event stream file or a directory of
  `*.jsonl` files. Each line is one event with the common fields `v` (format
  version 1), `node`, `run`, `seq`, `t_wall`, `t_mono_ns`, `kind` and
  optionally `view`, `step`, `imp`, `src`, followed by the fields of the
  kind (`ROUND_ENTER`, `TIMER_ARM`, `SEND`, `MSG_OUTCOME`, ...). The
  [wbft](https://github.com/0xmhha/wbft) node and its simulator
  (`conformance/sim`) write this format.
- `--logs NODE=PATH` (repeatable, with `--log-profile FILE`) reads the JSON
  log of a node that has no event stream, through the implementation
  profile its build publishes (`wbft-log-profile/1`; wbft's
  `cmd/wbft-logprofile` writes it and `wbft_nodeInfo.logProfile` names it).
  A log has no monotonic time, so only the checkers that use none judge a
  log run, and only when the log shows both consensus modules at trace
  from its start. Other log runs are `CANNOT_DECIDE`, with the reason
  `NEEDS_NODE_FEATURE` (the checker needs the event stream) or `LOG_LEVEL`
  (records may be missing).
- `--chain-config FILE` is a genesis file (or its `config` object). The
  timer checkers need it to compute `round_timeout(config_at(h), r)` and
  `RT(h)`; without it those requirements are `CANNOT_DECIDE` with the reason
  `MISSING_DATA`.
- `--checks` selects requirement IDs, priorities (`P0`, `P1`, `P2`, `V`) or
  checker-name globs (`timer.*`); the default is the whole catalog.
- `--require-decided FILE` lists requirement IDs (one per line, `#` starts a
  comment) that must end `PASS` or `FAIL`; otherwise the exit code is 2. Use
  it to state which requirements a scenario must exercise.
- `--min-coverage`, `--fail-on` (default `critical,high,medium`),
  `--clock-model`, `--sched-ms`, `--margin-ms`: see `wbft-inspector check -h`.

Every requirement gets one verdict. A checker decides each instance of a
requirement (a timer, a message, a view change); any failed instance makes the
requirement `FAIL`, otherwise one passed instance makes it `PASS` (the
undecided instances are counted in `coverage`), otherwise it is
`CANNOT_DECIDE` with a reason code such as `NOT_EXERCISED` (the situation did
not occur), `MISSING_DATA`, `OBSERVER_SCOPE` or `CLOCK_UNCERTAINTY`.
A requirement whose checker is not implemented yet is `NOT_RUN`.

Time comparisons use the monotonic clock of one node: a measured duration
`d` against an expected `t` passes within `[t, t + sched]`, fails beyond a
further `margin`, and is `CLOCK_UNCERTAINTY` in between.

## vectors: conformance vectors

```sh
wbft-inspector vectors --impl "path/to/adapter" --vectors wbft-spec/spec/vectors --out report.json
```

The runner reads `<runner>/<handler>/<case>/{meta,input,expected}.yaml`,
rejects files outside the YAML subset of WBFT-VEC-013, and fails the run
(exit 3) when a file of the selection was not read (WBFT-VEC-012). Each case
goes to the adapters that list its handler, in the order of `--impl`; an
adapter that answers `unsupported` passes the case to the next one. A case
with `expected.yaml` passes when the result is `ok` and the output equals it
key by key; a case without it passes when the operation fails. An adapter
that exits, exceeds the time limit (`--case-timeout`, `--steps-timeout`) or
breaks the protocol is restarted. The report lists every case under
`vectors.cases` and one result per requirement ID the cases name.

`adapters/self` is an adapter around the inspector's own model of the
specification (`chain/config_at`, `timers/round_timeout`); CI runs it against
the pinned vectors so that the model the timer checkers use is the model the
reference computes.

## catalog

```sh
wbft-inspector catalog list [--chapter A-06] [--json]
wbft-inspector catalog coverage --spec wbft-spec/spec --chapters A-05,A-06
wbft-inspector catalog extract --spec wbft-spec/spec --commit <c> --reference <r> --out internal/catalog/data/requirements.json
```

`internal/catalog/data/requirements.json` is the requirement list of the
wbft-spec commit in `spec.lock`, extracted with `catalog extract`.
`internal/catalog/data/checkers.yaml` assigns a checker and a priority to
requirements; it is written in the same YAML subset as the vectors.

## frames: frame dumps

```sh
wbft-inspector frames verify --frames dump/ [--frames dump2/]
```

A frame dump is the R-01 record of the istanbul frames a node sent and
received: `frames-<run>.jsonl` (records `frame`, `outcome`,
`send_suppressed`, `conn`, `dropped`) and the payloads under
`payloads/<ab>/<sha256>`. The wbft node writes it with
`wbft-journal export --format r01`. `frames verify` checks the format: the
common fields, the value sets, one node and run per file, unique `seq` per
run, `of` and `relay_of` naming a received frame, and for every frame its
payload file, sha256, size and `dedup_key` (Keccak-256 of the payload as an
RLP string, wbft-spec A-03). It prints one JSON object per dump and exits
with 1 when a dump has a problem. `check --frames DIR` decides the frame
checkers (see [Coverage](#coverage)) and reports the format problems of the
dump as errors.

## Report

The report follows [`schema/report-v1.json`](schema/report-v1.json)
(`"schema": "wbft-inspector-report/1"`): `run` (tool, build, catalog hash,
specification commit, inputs with their SHA-256, nodes, clock model,
options), `summary` (counts by verdict, priority, tag and node, failures by
severity, exit code), `results` (one per requirement, with coverage, up to 100
violations and 20 undecided samples, each with evidence pointers into the
inputs), `observations`, `vectors` and `errors` (tool errors, not verdicts).
The same inputs and options give the same report except `run.started_at` and
`run.finished_at`.

Exit codes: 0 no failure, 1 a failure of a `--fail-on` severity (vectors: a
failed case), 2 the coverage policy is not met, 3 vector files not read, 64
usage error, 69 input unavailable, 70 internal error.

## Builds

`run.inspector.build` names the build that wrote a report. The build of this
repository is `public`: it knows the requirements of the public specification
only. A requirement ID it does not know (for example in `--checks`,
`--require-decided` or a vector's `meta.yaml`) is reported as `CANNOT_DECIDE`
with the reason `NOT_IN_BUILD` instead of being decided. When a node declares
optional behaviours (a non-empty `improvements` list in `NODE_START`, or an
`imp` field on an event), a failure on that node is also `NOT_IN_BUILD`,
because this build cannot tell which requirements those behaviours change.

Checkers and catalog rows are registered at init time (`check.Register`,
`catalog.Register`). Another build can compile in further packages that
register checkers, for example with `go build -overlay`, without changes to
this repository; `run.inspector.catalog_sha256` then differs as well.

## Coverage

Chapters A-05 and A-06 have 70 requirements tagged `Observable:` in the
pinned specification. 33 of them have a checker in this version; the other 37
are in the catalog with the checker planned for them and are reported
`NOT_RUN`.

| Chapter | Implemented (decided from event streams) |
|---|---|
| A-05 | WBFT-SM-011, -012, -013 (relay after OK, no relay after ERR), -014 (self-delivery), -020 (disposition after `check_message`), -030 (round timer on entering a view), -039 (PRE-PREPARE acceptance order), -043 (Prepared on PREPARE quorum), -046 (decide on COMMIT quorum), -050 (timer not stopped after the decision), -057 (F+1 rule), -077 (retry timeout), -089 (cause of an own ROUND-CHANGE) |
| A-06 | WBFT-TIMER-002, -005, -006, -007 (round timeout per `config_at`), -003, -020 (retry timer `RT(h)`), -010, -012 (arming on view entry and acceptance), -013, -033 (cancellation on arming), -014 (stale expiry), -015, -017 (expiry actions), -016 (not cancelled on COMMIT quorum), -018 (engine stop), -021, -022 (retry expiry), -023 (retry not cancelled on quorum), -041 (no build wait for round >= 1) |

From frame dumps (`check --frames`), chapter A-07: WBFT-NET-011 (only codes
0x12..0x15 are sent), -013 (an oversized frame disconnects), -020 (codes
0x00..0x10 other than 0x07 are discarded; codes 0x11..0x15 received with the
engine stopped are discarded while the node synchronises and disconnect the
peer otherwise, decided from the frame's `engine` and its recorded outcome),
-021 (an empty consensus payload disconnects), -023 (a key received from a
peer enters that peer's recent cache before the known-cache check: the node
leaves it out of sends to that peer and finds it on the peer's next copy,
judged after receipts that carry `dedup` while the cache cannot have
evicted the key), -024 (a consensus frame whose
key the node already knew is discarded and does not reach the core, from the
frame's `dedup` hits; a first receipt is delivered and its key is known
to the next copy, unless the cache may have evicted it or records were
lost), -027 (the same
stopped-engine rows), -028 (0x07 does not disconnect), -032 (the same key
is not sent to the same peer twice in a run, a failed write included, unless
the cache may have evicted it), and -043 (a received message that ended in
`DROP_SILENT` or `IGNORE` is not relayed; relays are matched by key, so a
key that another copy got accepted for, or that is the node's own message,
passes). The size
is known from frames whose payload the dump holds and from frames recorded
without their payload that carry their size. Chapter A-06: WBFT-TIMER-024
(a retransmitted ROUND-CHANGE goes on the wire only to peers whose recent
cache does not hold it), from the `cause` and `send_suppressed` records;
a retransmission on the wire with no earlier copy for that peer in the
dump, or after enough other keys or peers to evict it, is undecided.

Not implemented yet: the requirements that need message payloads or frame
captures (WBFT-SM-003, -035, -037, -040, -044, -053, -054, -059, -062, -064,
-083 .. -088, -090; WBFT-TIMER-030, -031), headers or node RPC
(WBFT-SM-026, -047, -048, -067, -086; WBFT-TIMER-040, -042, -043), the `MAY`
rules that give observations rather than verdicts (WBFT-SM-078, -080, -081,
-082, -091), and WBFT-SM-049, WBFT-TIMER-001, -004, -008, -011, -032.
`wbft-inspector catalog list` prints the current state.

Some checkers cannot see everything from an event stream: a relay is recorded
only when a target is left after target filtering, and the stream carries no
validator set, so a missing own message is a failure only on a node that was
seen to send in that sequence. Such instances are `CANNOT_DECIDE`
(`OBSERVER_SCOPE`), not `PASS`.

## Development

```sh
make test                                # vet and unit tests (race detector)
make lint                                # golangci-lint, dependency check
make catalog-check vectors WBFT_SPEC_DIR=../wbft-spec
make e2e WBFT_SPEC_DIR=../wbft-spec      # needs cgo
```

The unit tests use two event streams written by the wbft simulator
(`testdata/events`) and change single records to show that each checker
fails on the change it is meant to catch. `test/e2e` is a separate module
that pins a wbft version: it runs every scenario of the simulator's bundle,
checks the event streams of all nodes (no requirement may fail, every report
must follow the schema), and runs every public vector against the wbft
adapter. `WBFT_E2E_SEEDS` sets the number of seeds per scenario.

## License

`wbft-inspector` is licensed under the GNU Lesser General Public License,
version 3 or (at your option) any later version (SPDX: `LGPL-3.0-or-later`,
[LICENSE](LICENSE)). The LGPL supplements the GNU General Public License
v3.0 ([COPYING](COPYING)).
