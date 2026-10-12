#!/usr/bin/env python3
"""Generate the legacy log profile from public A-13, without editing phrases."""
import argparse
import hashlib
import json
import re
from pathlib import Path


def semantic(message):
    """Map catalog phrases to the shared event vocabulary; retain unknown semantics as HEALTH."""
    kind, fields = "HEALTH", {}
    phase = next((p for p in ("PRE-PREPARE", "PREPARE", "COMMIT", "ROUND-CHANGE") if p in message), None)
    if phase:
        fields["phase"] = phase
    if message.startswith("WBFT: broadcast ") and message.endswith(" message"):
        kind, fields["cause"] = "SEND", "broadcast"
    elif message.startswith("WBFT: handle ") and message.endswith(" message"):
        fields["action"] = "handle"
    elif message.startswith("WBFT: accepted ") and "message" in message:
        kind, fields["outcome"] = "MSG_OUTCOME", "ACCEPT"
    if message == "WBFT: accepted PRE-PREPARE message":
        kind = "PREPREPARE_ACCEPT"
    elif message.startswith("WBFT: received quorum of "):
        kind, fields["what"] = "QUORUM", phase.replace("-", "_")
    elif message == "WBFT: received F+1 ROUND-CHANGE messages":
        kind, fields["what"] = "QUORUM", "F_PLUS_ONE"
    elif message == "WBFT: start new round":
        kind = "ROUND_ENTER"
    elif message == "WBFT: changed state":
        kind = "STATE"
    elif message == "WBFT: start new ROUND-CHANGE timer":
        kind, fields["timer"] = "TIMER_ARM", "round"
    elif message == "WBFT: set ROUND-CHANGE retry timer":
        kind, fields["timer"] = "TIMER_ARM", "retry"
    elif message == "WBFT: TIMER CHANGING ROUND":
        kind, fields["timer"] = "TIMER_FIRE", "round"
    elif message == "WBFT: block proposal committed":
        kind, fields["path"] = "NEW_HEAD", "sealed_locally"
    elif message == "WBFT: handle final committed":
        kind = "FINALIZE_HANDOVER"
    elif message in ("WBFT: start", "WBFT: activate WBFT"):
        kind = "ENGINE_START"
    elif message in ("WBFT: stopped", "WBFT: deactivate"):
        kind = "ENGINE_STOP"
    elif "backlog" in message and not message.startswith("WBFT: failed"):
        kind = "BACKLOG"
    elif message.startswith("WBFT: new extra "):
        kind = "EXTRA_SEAL"
    elif message == "WBFT: handle block proposal request":
        kind = "BUILD_REQUEST"
    elif "will be treated again later" in message:
        kind = "PROPOSAL_DEFERRED"
    return kind, fields


def generate(spec):
    raw = spec.read_bytes()
    entries = {}
    rows = 0
    for line in raw.decode().splitlines():
        m = re.fullmatch(r"\| L\d{3} \| `([^`]+)` \| (\w+) \| (.*?) \| .*", line)
        if not m:
            continue
        location, level, message = m.groups()
        template = message.startswith("fmt: ")
        if template:
            message = message[5:]
        kind, fields = semantic(message)
        key = (message, level.lower())
        if key not in entries:
            entries[key] = dict(kind=kind, module="", level=level.lower(), msg=message,
                                locations=[], fields=fields)
            if template:
                entries[key]["template"] = True
        entries[key]["locations"].append(location)
        rows += 1
    if rows != 184:
        raise ValueError(f"expected all 184 A-13 rows, found {rows}")
    return dict(format="wbft-log-profile/1", id="gstable@740526d03", keys=[],
                source=dict(spec="A-13-appendix.md", spec_sha256=hashlib.sha256(raw).hexdigest(),
                            reference="740526d03", rows=rows), entries=list(entries.values()))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec", type=Path)
    ap.add_argument("--out", type=Path, default=Path("profiles/gstable@740526d03.json"))
    ap.add_argument("--check", action="store_true")
    args = ap.parse_args()
    data = (json.dumps(generate(args.spec), indent=2, ensure_ascii=False) + "\n").encode()
    if args.check:
        if args.out.read_bytes() != data:
            raise SystemExit("legacy profile is stale; regenerate from the pinned public A-13")
    else:
        args.out.write_bytes(data)


if __name__ == "__main__":
    main()
