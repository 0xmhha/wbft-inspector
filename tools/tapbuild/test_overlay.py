import hashlib
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

import overlay


class OverlayTest(unittest.TestCase):
    def source(self, root):
        source = root / "source"
        (source / "eth").mkdir(parents=True)
        (source / "cmd/gstable").mkdir(parents=True)
        files = {
            "eth/handler_istanbul.go": "package eth\nfunc stub() {\n\t\t\t\t\tethPeer.AddConsensusProtoRW(rw)\n}\n",
            "cmd/gstable/main.go": '''package main
import (
"github.com/ethereum/go-ethereum/node"
)
func init() {
\tapp.After = func(ctx *cli.Context) error {
\t\tdebug.Exit()
\t\tprompt.Stdin.Close() // Resets terminal mode.
\t\treturn nil
\t}
}
''',
        }
        files.update({
            "consensus/wbft/backend/backend.go": 'package backend\nimport (\n"github.com/ethereum/go-ethereum/log"\n)\nfunc (sb *Backend) Close() error {return nil}\n',
            "consensus/wbft/config.go": "package wbft\n",
            "consensus/wbft/backend/engine.go": '''package backend
import (
"github.com/ethereum/go-ethereum/log"
)
func (sb *Backend) Start(notifyNewRound func(waitTime time.Duration, round *big.Int)) error {
 sb.coreStarted = true

 return nil
}
func (sb *Backend) Stop() error { return nil }
'''.replace(" sb.coreStarted", "\tsb.coreStarted").replace(" return nil", "\treturn nil"),
            "miner/worker.go": '''package miner
import (
"github.com/ethereum/go-ethereum/log"
)
func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {
\tif w.syncing.Load() {
\t\treturn
\t}
\tif true {
\t\tif true {
\t\t\tlog.Error("Refusing to mine without etherbase")
\t\t}
\t\tlog.Error("Fail to prepare work", "err", err)
\t}
\t// Fill pending transactions from the txpool into the block.
\tif true {
\t\twork.discard()
\t\treturn
\t}
\tif true {
\t\tlog.Error("Fail to commit work", "err", err)
\t}
}
''',
            "core/blockchain.go": '''package core
import (
"github.com/ethereum/go-ethereum/log"
)
func (bc *BlockChain) InsertChain(chain types.Blocks) (int, error) { return 0,nil }
func (bc *BlockChain) WriteBlockAndSetHead(emitHeadEvent bool) (status WriteStatus, err error) {
\tif !bc.chainmu.TryLock() {return 0,nil}
 return 0,nil
}
''',
        })
        for name, text in files.items():
            (source / name).parent.mkdir(parents=True, exist_ok=True)
            (source / name).write_text(text)
        hashes = {name: hashlib.sha256(text.encode()).hexdigest() for name, text in files.items()}
        return source, files, hashes

    def test_exact_overlay_preserves_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, files, hashes = self.source(root)
            with patch.dict(overlay.INPUTS, hashes, clear=True):
                path = overlay.render(source, root / "output")
            self.assertTrue(path.is_file())
            for name, original in files.items():
                self.assertEqual((source / name).read_text(), original)
            self.assertFalse((source / "p2p/wbft_tap_overlay.go").exists())

    def test_changed_source_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, _, hashes = self.source(root)
            (source / "eth/handler_istanbul.go").write_text("changed")
            with patch.dict(overlay.INPUTS, hashes, clear=True):
                with self.assertRaisesRegex(ValueError, "pinned revision"):
                    overlay.render(source, root / "output")

    def test_ambiguous_hook_and_in_source_output_are_refused(self):
        with self.assertRaises(ValueError):
            overlay.replace_once("hook hook", "hook", "replacement")
        with tempfile.TemporaryDirectory() as directory:
            source, _, _ = self.source(Path(directory))
            with self.assertRaises(ValueError):
                overlay.render(source, source / "output")


if __name__ == "__main__":
    unittest.main()
