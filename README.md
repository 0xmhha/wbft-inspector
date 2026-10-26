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

`reconstruction` independently validates one reconstructed comparison packet
and preserves its original source pointers. It does not decide requirements;
see [reconstructed step review](#reconstructed-step-review).

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

- `--rpc URL --from N --to M --chain-config FILE` reads bounded canonical
  header ranges. Use `--blocks DIR` for zero-padded block RLP files, or
  `--header-cache DIR --offline` to repeat a captured snapshot. A cache
  is bound to chain ID, genesis hash, node label and sanitized RPC origin;
  checksums detect corrupt files. `--header-node LABEL` identifies whose
  current seals are observed. RPC batches have at most 100 requests, at
  most five per second, transport retries and optional-method probes.
  Network and range metadata connect the report to analyzer header views.
- The independent header model checks eight public content requirements:
  difficulty, uncle hash, gas-limit bound, forbidden optional fields,
  gas-used bound, extra decoding, and signature recovery to Coinbase.
  Recovery does not bind Coinbase to the actual proposer's node key:
  that part remains `PARTLY_DECIDED` with `OBSERVER_SCOPE`. Genesis is
  excluded from proposal/import checks. These are content checks; node
  rejection order, aggregate signatures, execution state and the other
  P0 checks are not inferred from valid headers.
- Header observations compare scheduled/actual proposers and own/child
  previous seals. They do not turn schedule differences or late seals
  into failures. All occurrences are counted; evidence retains at most
  20 pointers per group, including the validator address and both the
  own header and child proof. Header payload/state values are not copied.
- `--events PATH` (repeatable) is an event stream file or a directory of
  `*.jsonl` files. Each line is one event with the common fields `v` (format
  version 1), `node`, `run`, `seq`, `t_wall`, `t_mono_ns`, `kind` and
  optionally `view`, `step`, `imp`, `src`, followed by the fields of the
  kind (`ROUND_ENTER`, `TIMER_ARM`, `SEND`, `MSG_OUTCOME`, ...). The
  [wbft](https://github.com/0xmhha/wbft) node and its simulator
  (`conformance/sim`) write this format; its schema is wbft's
  `observe/event/schema/events-v1.json`. A copy pinned to a wbft commit is
  in `internal/events/testdata` (`events-v1.ref` names the commit), and the
  tests check that the kinds, the field names and the compared values the
  checkers use are in it.
  A node whose event writer fell behind writes
  `{"type":"dropped","node":…,"run":…,"count":N,"from_seq":S}` in place of
  the N records from seq S. Such spans, and seq gaps without such a
  record (reported as input errors), are lost: a `FAIL` anchored at an
  event of that run becomes `CANNOT_DECIDE` with the reason `MISSING_DATA`,
  since the lost records may hold what the checker found missing.
- `--logs NODE=PATH` (repeatable, with `--log-profile FILE`) reads the JSON
  log of a node that has no event stream, through the implementation
  profile its build publishes (`wbft-log-profile/1`; wbft's
  `cmd/wbft-logprofile` writes it and `wbft_nodeInfo.logProfile` names it).
  A log has no monotonic time, so only the checkers that use none judge a
  log run, and only when the log shows both consensus modules at trace
  from its start. Other log runs are `CANNOT_DECIDE`, with the reason
  `NEEDS_NODE_FEATURE` (the checker needs the event stream) or `LOG_LEVEL`
  (records may be missing).
- `--rejections NODE=PATH` (repeatable) reads the blocks and proposals a
  node rejected (`wbft_rejections`): the RPC response, a file of its
  records as JSON Lines, or the node's `rejections` store directory. It is
  read with the node's frame dump.
- `--chain-config FILE` is a genesis file (or its `config` object). The
  timer checkers need it to compute `round_timeout(config_at(h), r)` and
  `RT(h)`; without it those requirements are `CANNOT_DECIDE` with the reason
  `MISSING_DATA`.
  Its `chainId`, when present, lets WBFT-HDR-060 check the randao reveal
  of proposals (step H18).
- `--checks` selects requirement IDs, priorities (`P0`, `P1`, `P2`, `V`) or
  checker-name globs (`timer.*`); the default is the whole catalog.
- `--require-decided FILE` lists requirement IDs (one per line, `#` starts a
  comment) that must end `PASS` or `FAIL`; otherwise the exit code is 2. Use
  it to state which requirements a scenario must exercise.
- `--min-coverage R` sets the lowest share of passed instances a partly
  decided requirement may have (below it the exit code is 2).
- `--fail-on` (default `critical,high,medium`), `--clock-model`,
  `--sched-ms`, `--margin-ms`: see `wbft-inspector check -h`.

Every requirement gets one verdict. A checker decides each instance of a
requirement (a timer, a message, a view change), and the instances give the
verdict:

| Instances | Verdict |
|---|---|
| any failed | `FAIL` |
| all passed | `PASS` |
| some passed, the others undecided, none failed | `CANNOT_DECIDE`, reason `PARTLY_DECIDED` |
| all undecided | `CANNOT_DECIDE`, with the most frequent reason, such as `MISSING_DATA`, `OBSERVER_SCOPE` or `CLOCK_UNCERTAINTY` |
| none | `CANNOT_DECIDE`, reason `NOT_EXERCISED` (the situation did not occur) |

A requirement whose checker is not implemented yet is `NOT_RUN`. A
requirement is `PASS` only when every instance was decided and passed: an
undecided instance may hide a failure. Each result's `coverage` counts the
passed, failed and undecided instances apart, with the reasons of the
undecided ones. A `PARTLY_DECIDED` result also says in its `detail` how
many instances passed and how many could not be decided. The summary counts
`partly_decided` as part of `cannot_decide`. `check` ends by writing the
counts on standard error in one line, for example:

```
check: 87 requirements: 16 passed, 0 failed, 35 could not be decided (2 of them partly passed), 36 not run
```

Time comparisons use the monotonic clock of one node: a measured duration
`d` against an expected `t` passes within `[t, t + sched]`, fails beyond a
further `margin`, and is `CLOCK_UNCERTAINTY` in between.

For a timer restored after WAL replay, its arm event is written after the
timer is scheduled. When the event supplies `deadline_mono_ns`, the round
timeout and first ROUND-CHANGE checks use its logical origin only after
matching a continuous canonical replay lifecycle, timer identity and live
expiry. Contradictory or incomplete explicit evidence remains undecided.

An older restored arm can also use the measured scheduler origin when a
complete R01 transcript passes format validation and full operation replay.
This path requires one closed single-engine run, a unique matching restored
arm, queued expiry and dequeue, exact timer identity and callback entry
clocks, and a bound stop and lifecycle clear. Checker evidence refers to the original
event and R01 positions. A later asynchronous writing timestamp does not
establish whole-run clock continuity. Without this complete proof, the older
arm keeps its original timing interpretation. Clock tolerances and original
event timestamps are unchanged.

## Node header variants

A header variant is one node's observed header for a height and WBFT block
hash. For a decodable, difficulty-one WBFT header, the hash is computed with
the current `PreparedSeal` and `CommittedSeal` removed and `Round` set to zero.
Two node copies can therefore have the same block hash while their current round, signer bitmaps and
aggregate signatures differ. The child's `PrevRound` and previous seals
remain part of the child's hashed content; they are a separate observation.

Scope own-header observations to their input snapshot and `--header-node`
label. The source fingerprint includes the full observed header, including
fields excluded from the block hash. A shared block hash alone does not
identify one exact header variant or establish globally identical own seals.
Apply content checks to the observed variant. A differing signer bitmap,
round or additional seal by itself is not an inspector failure.

Network participation uses a parent-linked child's previous seals and the
validator set governing the preceding height. Without that child, it remains
unknown. Keep a node-copy round distinct from a child-backed decision round;
these observations alone do not validate aggregate signatures, execution
state or message timing.

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

Recorded application sync sources use `sync_trace` version 1 and
`sync_control` notifications and handling records. A snapshot declaration
can share the scheduler or cache declaration row. The reader checks closed
metadata, snapshot counts, logical request and handling identities, and the
exact journal sequence, segment and offset of a retained original request.
The request may occur physically after its handling record. Source order and
recorded clocks are retained.

Event cursor bounds use the next-sequence interval `[before, after)` and are
separate from journal coordinates. Failed control calls can have an empty
measured interval. Submitted notifications do not measure engine or guard
state. Explicitly incomplete snapshots remain incomplete and do not gain
inferred request coordinates. Source validation authenticates neither an
external downloader nor consensus-policy correctness; this reader support
does not add a sync-policy requirement checker.

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
The exception is the restart-safety rules every wbft node declares,
`one_round0_proposal` and `bad_block_release_mark` (`check.PublicBehaviours`).
This build knows what they change: `one_round0_proposal` changes WBFT-SM-032
and WBFT-SM-082, and `bad_block_release_mark` changes no requirement. A node
that declares only these keeps its failures of every other requirement.

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
the cache may have evicted it), -043 (a received message that ended in
`DROP_SILENT` or `IGNORE` is not relayed; relays are matched by key, so a
key that another copy got accepted for, or that is the node's own message,
passes), and -044 (the node does not close a peer's stream for a message
that ended in `IGNORE`, from the `by`, `cause` and `of` of closed `conn`
records; a close by the node for another reason before the peer's next
frame is undecided, and a dump without `by` passes). The size
is known from frames whose payload the dump holds and from frames recorded
without their payload that carry their size. Chapter A-06: WBFT-TIMER-024
(a retransmitted ROUND-CHANGE goes on the wire only to peers whose recent
cache does not hold it), from the exact cache decision and enqueue identity.
A closed cache snapshot is replayed independently at the real 40-peer and
1,024-message capacities. Legacy physical frame order cannot establish the
cache decision of an asynchronous write, so outgoing legacy retries are
undecided. Explicit suppression remains an observation of a send left out.
Chapter A-05: WBFT-SM-083 (a node does not send two PREPAREs, or two
COMMITs, with different digests for one view within one run), from the
payloads of the node's own sent frames: the signer is recovered from each
payload (relays of other validators' messages are left out), and runs are
judged apart because the property does not hold across a restart.
With the event stream of the same run, chapter A-10: WBFT-SEC-041 (a
node that receives two valid signatures of one validator on different
digests for one view reports it), the cross-check of the node's EVIDENCE
records with its received PRE-PREPARE, PREPARE and COMMIT frames: a pair
without EVIDENCE fails while the node was at that sequence or next to it,
and an EVIDENCE whose two messages the dump does not hold is undecided
(INCONSISTENT_INPUT).
Also with the event stream, chapter A-10: WBFT-SEC-081 (after a node
records a block at height h as bad, it sends no PREPARE or COMMIT for it
at h). The bad blocks are the node's `IMPORT_FAIL` records with
`recorded_bad`. A vote for one sent after its record fails, in any later
run too. A bad block is undecided when the dump has no record after it,
or lost records, and when the vote came after ten higher bad blocks were
recorded (the reference keeps ten, so the record may have been dropped).
With the node's rejections (`--rejections`), chapter A-09: WBFT-APP-051
(a node sends no PREPARE for a proposal the application found invalid):
each received PRE-PREPARE of a rejected block whose outcome is row 13 of
the outcome table fails when the node then sent its own PREPARE for that
view and block before accepting a later copy, and passes otherwise. The
node's own rejected proposal has no received frame (it is delivered to the
node without one), so its sent PRE-PREPARE is judged instead: it fails when
the run holds the node's PREPARE for that view and block. A
rejection stamped within a run whose dump holds no such PRE-PREPARE is
undecided (INCONSISTENT_INPUT). That the round then ends by timeout is
not decided.
With the same input, chapter A-08: WBFT-HDR-060 (a node verifies a
proposal with the steps P1-P7 in order and takes the first failing step
as the result), for the proposals the inspector finds invalid itself: it
applies the header steps that need nothing but the proposal header (H3,
H4, H5, H7, H13, H16) and, with the chain id of `--chain-config`, H18
(the randao reveal recovers to the proposal's Coinbase). For a proposal failing step S, the node fails the
requirement when it accepted the proposal or recorded a rejection at a
step after S, and passes when it recorded one at S or before; without a
rejection record the proposal is undecided (it may have failed the
message checks first).
With the event stream as well, WBFT-HDR-061 (a node rejects a proposal
whose hash it recorded as a bad block, at P2, before any check but the
type check). The bad blocks are the node's `IMPORT_FAIL` records with
`recorded_bad`. Each PRE-PREPARE of such a block that the node received
after the record, or proposed itself, fails when the node accepted it
or rejected it at a step after P2. It passes when the node rejected it at
P1 or P2. A proposal after ten higher bad blocks were recorded is left
out, since the record may have been dropped.
From the event stream alone, chapter A-09: WBFT-APP-100 (after a finalized
block fails import, consensus does not decide it again at the same height
and goes on through a ROUND-CHANGE started by its round timer). The
failure is an `IMPORT_FAIL` with path `sealed_locally` or a
`COMMIT_RESULT` with `ok` false. It fails when the block is decided again
(`FINALIZE_HANDOVER`) or becomes the head. It also fails when the next
round of the height is entered with cause `finalize_fail`. It passes when
that round comes by `timeout` or `f_plus_one`, or when the height ends with
another block. The wbft simulator records neither failure record, so its
streams do not exercise it.

Not implemented yet: the requirements that need message payloads or frame
captures (WBFT-SM-003, -035, -037, -040, -044, -053, -054, -059, -062, -064,
-084 .. -088, -090; WBFT-TIMER-030, -031), headers or node RPC
(WBFT-SM-026, -047, -048, -067, -086; WBFT-TIMER-040, -042, -043), the `MAY`
rules that give observations rather than verdicts (WBFT-SM-078, -080, -081,
-082, -091), and WBFT-SM-049, WBFT-TIMER-001, -004, -008, -011, -032.
`wbft-inspector catalog list` prints the current state.

Some checkers cannot see everything from an event stream: a relay is recorded
only when a target is left after target filtering, and the stream carries no
validator set, so a missing own message is a failure only on a node that was
seen to send in that sequence in the same node's writer run. A reused run ID
on another node does not provide membership evidence. Unproven membership
leaves the instance `CANNOT_DECIDE` (`OBSERVER_SCOPE`). Self-delivery pairing
ends at `ENGINE_STOP`; a later engine's receive outcome cannot prove delivery
of a discarded scheduled message. The stopped send remains `CANNOT_DECIDE`
(`NOT_EXERCISED`).

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

Header validation on 2026-10-13 used the public testnet range
22044761..22144760 and real G7 nodes. The implemented seven content checks
passed, signature recovery was partly decided, and six other selected P0
checks were not run. This is a header input milestone, not completion of
the full P0 specification or its state/aggregate-signature checks.

## Legacy G7 log observations

`check --log-profile profiles/gstable@740526d03.json --logs NODE=FILE ...`
reads the generated public A-13 profile without importing the consensus
engine. Use `--log-from` and `--log-to` for an inclusive RFC3339 window;
original complete-file SHA256 and line numbers are retained. The reader
streams bounded lines and retains at most 200,000 selected events.
Declared log network identity uses `--log-chain-id` and
`--log-genesis-hash` together; it is metadata, not an authenticated chain
claim. Nodes may be stable labels; observed addresses remain separate.

Full heights/rounds, engine boundaries, codes, positive timer/F+1 causes
and prior engine-start context are preserved. No step, monotonic clock,
complete coverage or wire success is invented. Payload/data/arbitrary
errors are not retained by this adapter. Unknown phrases/malformed lines
produce counts without echoing their bytes. Positive round-change and
engine-restart observations have capped input/line pointers and full counts.

A real original seven-file G7 report retained 38,302 scenario records,
12 observation groups (32 round changes, four engine restarts), 68 source
pointers and no parse errors. Existing requirements remained 33 undecided
and 32 not run because legacy logs do not prove complete event coverage.
The report passes the report schema. Full I2 checker coverage is pending.

### Source-pinned transport capture

`tools/tapbuild/overlay.py` adds opt-in wire-frame capture to an isolated,
source-pinned node checkout through a Go build overlay. It records original
protocol bytes, explicit write results, and stream lifecycle in the R-01
format without editing the source checkout. The inspector accepts optional
`write_result` on outgoing frames and refuses contradictory success/error
evidence. Old captures with no explicit result retain their original meaning.

See [the capture tool instructions](tools/tapbuild/README.md). Wire capture
does not establish engine outcomes, delivery coverage, paired stream order,
or tapped-versus-original block-hash/round-distribution equivalence.

Runtime sidecars are separate from R-01 wire files. Use
`wbft-inspector observations verify observations-RUN.jsonl` to read their
closed scalar configuration and exact operation ID boundaries. The reader
refuses duplicate keys, unknown or null fields, changed identities, duplicate
operations, reversed call intervals, and inconsistent dropped counts. Missing
boundaries remain unavailable; exit 2 means capture evidence is incomplete.
Output preserves original one-based lines, integer strings for call identities
and durations, and recorded return paths. A complete capture does not establish
a complete runtime model, remote delivery, or application request completion.

### Measured timer cancellation sources

Current R01 exports can include `scheduler_trace`, `timer_operation` and
`scheduler_step`. The declaration counts the complete available operation
and step snapshot; `own_input` also serves as its original step witness.
Every source retains its raw journal sequence, segment and byte offset.
The declaration's zero/epoch clock is explicitly unavailable, not measured.
Operation counters and nanosecond bounds use canonical decimal strings.

The cancellation checkers bind event node/run, engine/step, timer kind,
generation, full view and duration to the measured arm, queue insertion,
cancellation request and new round arm. Mutex sequence is global within the
writer run across engine lifecycles; file order is not operation order.
Lifecycle records can name the last completed step. A WAL replay step without
entry measurements cannot provide a guessed operation clock.

A complete source that shows the same expiry queued before cancellation can
prove a missing cancel event is expected. A timer still active at the round
arm fails. Deadline passage and a later FIRE alone prove neither condition;
without measured source or an explicit cancellation, the result is
`CANNOT_DECIDE` (`OBSERVER_SCOPE`). Damaged, conflicting, truncated or
unbound sources cannot prove a pass. Raw coordinate authentication remains
a separate audit against retained journal bytes.


### Measured cache decisions and queued writes

R01 exports can include `cache_trace`, `cache_instance` and `cache_operation`.
A node that also records scheduler sources places `cache_trace` metadata on
its existing `scheduler_trace` declaration row: both originate from one raw
segment record and retain that single original sequence. The snapshot closes
the available instance and operation counts and marks incomplete context.
Only empty-instance declarations initialize a cache. Engine changes or peer
reconnection do not fabricate a reset.

Each operation preserves its mutex-local instance and sequence, code, key,
payload hash, pre-operation hits, actual candidate set, targets and suppressed
peers. The inspector replays both LRU levels independently; file order, frame
time and a recent peer/key match are not substitutes for decision order.
Outgoing `send_attempt` metadata binds a queued frame to its own original
`cache_decision` source sequence, segment and offset. An observer replacement,
legacy adapter, missing source or reused/conflicting identity cannot provide
that proof. Metadata integers remain canonical decimal strings, including
values beyond JavaScript's exact numeric range.

A retry selected while the key was absent passes even when its physical write
is recorded after a later suppression. A successful write of an exact decision
whose recent cache held the key fails. An unsuccessful write that does not
establish a complete frame stays undecided; `not_attached` records no write.
Gap or inconsistent cache context cannot prove a pass. Every decided instance
retains separate frame and cache-operation evidence pointers. Raw coordinate
authentication remains a separate audit against retained journal bytes; the
metadata alone does not prove peer delivery or authenticate unavailable bytes.

### Independently recorded downloader notifications

`check --sync-observations FILE` reads a `wbft-sync-notifications/1` JSON Lines
file, separately from canonical events and R01 control records. Repeat the
option for multiple sources. The report retains each file's SHA-256 and line
count as a structured log input, without assigning it a legacy log profile.
The `sync_notification_source` observation points to its original header and,
when retained, footer. It describes source coverage and emits no policy verdict.

The reader preserves process node/run identity, notification order, available
posting times and exact decimal completion-header numbers. It rejects duplicate
or unknown fields, missing booleans, malformed hashes, impossible counts and
contradictory completeness claims. A missing footer or final line terminator
remains incomplete. Wall-clock regression does not reorder notifications, and
an unavailable clock is never reconstructed from consensus event positions.

A complete file is still not external producer authentication. Matching its
notifications to a core request requires separate exact process identity,
request/processing coverage and original canonical event evidence. It cannot
turn a requirement without a checker into a pass, repair lost journal records,
or establish an absent downloader branch.

### Downloader core lifecycle policy

`sync.downloader_core` checks SNET-SYNC-030 from three sources of the same
validator process: canonical events (`--events`), recorded control requests and
handling (`--frames`), and typed notifications (`--sync-observations`). Each
notification must have one uniquely matched request and processing operation.
Completion numbers and hashes must also occur in that process's canonical
`NEW_HEAD` records. Posting time never supplies an event boundary.

Actual control calls use next-sequence ranges `[before, after)` and measured
running states. The checker independently follows canonical engine starts and
stops. A later sync's observed stop after the first successful sync is a failure;
unattributed lifecycle changes, failed control calls and insufficient source
coverage stay undecided. A no-call handling has no inferred event range.

Missing, coalesced, repeated or reordered handling cannot prove a pass, even
when notification and operation counts are equal. Failed initial syncs, the
first successful sync and a subsequent cycle must all be exercised for complete
branch coverage; absent branches remain `NOT_EXERCISED`. A process with no
validator downloader cycle also stays undecided. Structured source coverage
and original input hashes do not authenticate an external producer.

## Reconstructed step review

```sh
wbft-inspector reconstruction --packet review.json --sha256 EXPECTED_SHA256
```

The input is a bounded `wbft-reconstruction-review/1` packet containing one
WBFT observable state/action comparison, its source fingerprints and its
original processing coordinates. The reader rejects duplicate or unknown
fields, paths, raw payloads, inconsistent source domains and truncated or
oversized documents. Full decimal heights, rounds and clocks remain strings.
Reconstructed ordinals, physical source sequences and storage positions stay
separate; timer generations remain explicitly derived.

Exit 0 means the packet structure was validated and, when `--sha256` is given,
its bytes match that independently supplied checksum. Output uses
`wbft-reconstruction-review-validation/1`. It retains partial or unapplied
steps and labels the specification verdict `not_evaluated`. A parent result
hash alone does not verify the selected record, and packet validation does not
authenticate source truth. Use the original logs, frames and headers with
`check` for requirements whose evidence is available.

The standard-library-only reader is independent of the comparison producer.
The versioned contract is [schema/reconstruction-review-v1.md](schema/reconstruction-review-v1.md).


Local prepared-candidate checks use the rejection path `local_reproposal`.
The reader retains this origin separately from `preprepare`; a local record
is not evidence that a peer PRE-PREPARE or physical frame was received.
Checks that require received-proposal rejections keep their existing scope.
The `round_proposal` timer and its snapshot-unavailable health condition
are local observations, without implying execution or network validity.


For an explicit positive `consensusRules.blsRandao` activation, the canonical
header reader selects the reveal format from a matching parent's full successor
height. It checks the active wire length and retains the independent structural
predicates. BLS signature validity is `CANNOT_DECIDE` until an independent BLS
verifier and registered proposer key are supplied. It never treats a 96-byte
reveal as an ECDSA recovery failure or reports its signature as verified. A
frame-only observation with a declared activation lacks this parent context;
its first-failure checker retains other checks without applying legacy recovery.
Missing or null activation keeps the existing ECDSA checks. Standard-library-only
dependencies and the separate node-key observer-scope limitation are preserved.
