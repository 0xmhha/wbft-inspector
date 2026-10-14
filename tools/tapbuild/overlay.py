#!/usr/bin/env python3
"""Render a source-pinned WBFT transport observation overlay without edits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REVISION = "740526d0375a8aca817b580e7a4bfc4c1028ae29"
INPUTS = {
    "eth/handler_istanbul.go": "0f774908993269557aa9cb327bc57c2c02dbe2820dbd8506448e3dadad5b4507",
    "cmd/gstable/main.go": "df5ec38d660ea7743987ccc932bc645f7e2c679c4e296de921f1dd1746409297",
}


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError("source hook is absent or ambiguous")
    return text.replace(old, new, 1)


def render(source, output):
    source, output = Path(source).resolve(), Path(output).resolve()
    if source == output or source in output.parents:
        raise ValueError("overlay output must be outside the source checkout")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    replacements, hashes = {}, {}
    for name, expected in INPUTS.items():
        raw = (source / name).read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != expected:
            raise ValueError("source file does not match the pinned revision")
        hashes[name] = digest
    handler = (source / "eth/handler_istanbul.go").read_text()
    handler = replace_once(handler, "\t\t\t\t\tethPeer.AddConsensusProtoRW(rw)",
        "\t\t\t\t\ttapRW, tapClose, tapErr := p2p.WBFTTapStream(rw, p)\n"
        "\t\t\t\t\tif tapErr != nil { return tapErr }\n"
        "\t\t\t\t\trw = tapRW\n\t\t\t\t\tdefer tapClose()\n"
        "\t\t\t\t\tethPeer.AddConsensusProtoRW(rw)")
    main = (source / "cmd/gstable/main.go").read_text()
    main = replace_once(main, '"github.com/ethereum/go-ethereum/node"',
        '"github.com/ethereum/go-ethereum/node"\n\t"github.com/ethereum/go-ethereum/p2p"')
    main = replace_once(main, "\tapp.After = func(ctx *cli.Context) error {\n\t\tdebug.Exit()",
        "\tapp.After = func(ctx *cli.Context) error {\n\t\ttapErr := p2p.WBFTTapClose()\n\t\tdebug.Exit()")
    main = replace_once(main, "\t\tprompt.Stdin.Close() // Resets terminal mode.\n\t\treturn nil",
        "\t\tprompt.Stdin.Close() // Resets terminal mode.\n\t\treturn tapErr")
    files = {"eth/handler_istanbul.go": handler, "cmd/gstable/main.go": main,
             "p2p/wbft_tap_overlay.go": Path(__file__).with_name("runtime.go.tmpl").read_text()}
    test_template = Path(__file__).with_name("runtime_test.go.tmpl")
    if test_template.exists():
        files["p2p/wbft_tap_overlay_test.go"] = test_template.read_text()
    for index, (name, text) in enumerate(files.items()):
        replacement = output / f"{index}.go"
        replacement.write_text(text)
        replacement.chmod(0o600)
        subprocess.run(["gofmt", "-w", str(replacement)], check=True)
        replacements[str(source / name)] = str(replacement)
    overlay = output / "overlay.json"
    overlay.write_text(json.dumps({"Replace": replacements}, indent=2) + "\n")
    overlay.chmod(0o600)
    manifest = {"format": "wbft-tapbuild/1", "source_commit": REVISION,
                "source_sha256": hashes,
                "overlay_sha256": {str(Path(k).relative_to(source)): hashlib.sha256(Path(v).read_bytes()).hexdigest()
                                   for k, v in replacements.items()},
                "captures": ["wire_frames", "write_result", "stream_lifecycle", "io_intervals"],
                "unavailable": ["engine_outcomes", "send_cause", "delivery_coverage", "paired_stream_order"]}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (output / "manifest.json").chmod(0o600)
    return overlay


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--build", type=Path)
    args = parser.parse_args()
    source = args.source.resolve()
    revision = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
    if revision != REVISION or subprocess.check_output(["git", "-C", str(source), "status", "--porcelain"], text=True):
        parser.error("use an isolated, clean checkout of the pinned source commit")
    if "go1.26.8 " not in subprocess.check_output(["go", "version"], text=True):
        parser.error("activate Go 1.26.8 with gvm before running this tool")
    overlay = render(source, args.out)
    if args.build:
        binary = args.build.resolve()
        subprocess.run(["go", "build", "-overlay", str(overlay), "-o", str(binary), "./cmd/gstable"], cwd=source, check=True)
        binary.chmod(0o700)
    print(overlay)


if __name__ == "__main__":
    main()
