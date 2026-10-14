#!/usr/bin/env python3
"""Render a source-pinned WBFT transport observation overlay without edits."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

REVISION = "740526d0375a8aca817b580e7a4bfc4c1028ae29"
INPUTS = {
    "consensus/wbft/core/core.go": "ffeb201f03f0f67c81011cd2d1cdc1f5e0a980d31d31210d6bebfdd78119c107",
    "consensus/wbft/core/handler.go": "2f6cfaaf5b5d6677fa3323cdf16608344653ff9786c310fb2625ab59ce3f5ec1",
    "eth/handler_istanbul.go": "0f774908993269557aa9cb327bc57c2c02dbe2820dbd8506448e3dadad5b4507",
    "consensus/wbft/backend/engine.go": "6d95bfc7fa8d36f546ce3879ba28c0c9efede2a4165276646221aa7c4b0cd1eb",
    "consensus/wbft/backend/backend.go": "1bb189b8d2ecd592b3f0f0c5942c4ce507fdf7b0d0cd7c568a42b00a1d50a213",
    "consensus/wbft/config.go": "98ff7cf5fbf54b3eeb40e5b37d08904f4e5353fdc2b5830c54ffd929de68def5",
    "miner/worker.go": "f11d1f008b8a4bafd00c8248face4564cea09dfd4b7bc813bff7b48e45d34ab4",
    "core/blockchain.go": "fedf77f7db36ab3bad460b0894b07065b519cdf7923d282c31a406817bd92976",
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
    for name in ["consensus/wbft/backend/engine.go", "consensus/wbft/backend/backend.go", "miner/worker.go", "core/blockchain.go", "consensus/wbft/core/core.go", "consensus/wbft/core/handler.go"]:
        text = (source / name).read_text()
        text = replace_once(text, '"github.com/ethereum/go-ethereum/log"',
            '\"github.com/ethereum/go-ethereum/log\"\n\t\"github.com/ethereum/go-ethereum/p2p\"')
        if name == "consensus/wbft/core/core.go":
            text = replace_once(text, "type Core struct {", "type Core struct {\n\twbftTapEngine *p2p.WBFTTapEngine")
        elif name == "consensus/wbft/core/handler.go":
            text = replace_once(text, "func (c *Core) Start() error {", 'func (c *Core) Start() error {\n\tc.wbftTapEngine.Stage(nil, "start_enter")')
            text = replace_once(text, "\tc.subscribeEvents()", '\tc.subscribeEvents()\n\tc.wbftTapEngine.Stage(nil, "subscribed")')
            text = replace_once(text, "\tgo c.handleEvents()", '\tgo func() {\n\t\tc.wbftTapEngine.Stage(nil, "handler_enter")\n\t\tc.handleEvents()\n\t}()')
            text = replace_once(text, "\tc.startNewRound(common.Big0)", '\tc.startNewRound(common.Big0)\n\tc.wbftTapEngine.Stage(nil, "initial_round_return")\n\tc.wbftTapEngine.Stage(nil, "start_return")')
            text = replace_once(text, "func (c *Core) Stop() error {", 'func (c *Core) Stop() error { return c.StopObserved(nil) }\n\nfunc (c *Core) StopObserved(parent *p2p.WBFTTapOperation) error {\n\tc.wbftTapEngine.Stage(parent, "stop_enter")')
            text = replace_once(text, "\tc.stopTimer()", '\tc.stopTimer()\n\tc.wbftTapEngine.Stage(parent, "timers_stopped")')
            text = replace_once(text, "\tc.unsubscribeEvents()", '\tc.unsubscribeEvents()\n\tc.wbftTapEngine.Stage(parent, "unsubscribed")')
            text = replace_once(text, "\tc.handlerWg.Wait()", '\tc.handlerWg.Wait()\n\tc.wbftTapEngine.Stage(parent, "handler_joined")\n\tc.wbftTapEngine.Stage(parent, "stop_return")')
            text = replace_once(text, "\t\tc.handlerWg.Done()", '\t\tc.wbftTapEngine.Stage(nil, "handler_exit")\n\t\tc.handlerWg.Done()')
            text += '\n// Bind before starting the handler; the instance token remains immutable.\nfunc (c *Core) SetWBFTTapEngine(e *p2p.WBFTTapEngine) { c.wbftTapEngine=e }\n'
        elif name.endswith("engine.go"):
            text = replace_once(text, "notifyNewRound func(waitTime time.Duration, round *big.Int)) error {",
                "notifyNewRound func(waitTime time.Duration, round *big.Int)) (tapErr error) {\n"
                '\ttap := p2p.WBFTTapBegin("backend_start", "", "", 0)\n'
                '\tdefer func() { tap.EndError(tapErr, "", "", 0) }()')
            text = replace_once(text, "\tsb.coreStarted = true\n\n\treturn nil", """\tsb.coreStarted = true
\tif p2p.WBFTTapEnabled() {\n\ttapHeight := new(big.Int).Add(chain.CurrentHeader().Number, big.NewInt(1))
\ttapConfig := sb.config.GetConfig(tapHeight)
\ttapPolicy := ""
\tif tapConfig.ProposerPolicy != nil { tapPolicy = new(big.Int).SetUint64(uint64(tapConfig.ProposerPolicy.Id)).String() }
\tp2p.WBFTTapRuntimeStart(p2p.WBFTTapRuntimeConfig{
 Address:sb.Address().Hex(), Height:tapHeight.String(),
 RequestTimeoutMS:new(big.Int).SetUint64(tapConfig.RequestTimeout).String(),
 BlockPeriodSeconds:new(big.Int).SetUint64(tapConfig.BlockPeriod).String(),
 Epoch:new(big.Int).SetUint64(tapConfig.Epoch).String(),
 AllowedFutureBlockSeconds:new(big.Int).SetUint64(tapConfig.AllowedFutureBlockTime).String(),
 MaxRequestTimeoutSeconds:new(big.Int).SetUint64(tapConfig.MaxRequestTimeoutSeconds).String(),
 ProposerPolicy:tapPolicy, Transitions:len(sb.config.Transitions), SystemContractUpgrades:len(sb.config.SystemContractUpgrades),
 })\n }
\treturn nil""")
            text = replace_once(text, "func (sb *Backend) Stop() error {", """func (sb *Backend) Stop() (tapErr error) {
\tdefer func() { p2p.WBFTTapRuntimeStop(tapErr) }()\n""")
            text = replace_once(text, "sb.startWBFT()", "sb.startWBFT(tap)")
            text = replace_once(text, "func (sb *Backend) Stop() (tapErr error) {", 'func (sb *Backend) Stop() (tapErr error) {\n\ttap := p2p.WBFTTapBegin("backend_stop", "", "", 0)\n\tdefer func() { tap.EndError(tapErr, "", "", 0) }()')
            text = replace_once(text, "sb.stop()", "sb.stop(tap)")
            signature = "func (sb *Backend) Seal(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}) error {"
            text = replace_once(text, signature, signature + "\n\treturn sb.sealObserved(chain, block, results, stop, nil)\n}\n\n" +
                "func (sb *Backend) SealObserved(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}, tap *p2p.WBFTTapOperation) error {\n\treturn sb.sealObserved(chain, block, results, stop, tap)\n}\n\n" +
                "func (sb *Backend) sealObserved(chain consensus.ChainHeaderReader, block *types.Block, results chan<- *types.Block, stop <-chan struct{}, tap *p2p.WBFTTapOperation) error {\n" +
                '\ttapHeight, tapHash := "", ""\n\tif tap != nil { tapHeight, tapHash = block.Number().String(), block.Hash().Hex() }\n' +
                '\ttap.Stage("seal_enter", tapHeight, tapHash)\n\tdefer tap.Stage("seal_return", tapHeight, tapHash)')
            text = replace_once(text, "\t\tgo sb.EventMux().Post(wbft.RequestEvent{\n\t\t\tProposal: block,\n\t\t})", '\t\ttapMux := sb.EventMux()\n\t\ttapRequest := wbft.RequestEvent{Proposal: block}\n\t\tgo func() {\n\t\t\ttap.Stage("request_post_enter", tapHeight, tapHash)\n\t\t\ttapMux.Post(tapRequest)\n\t\t\ttap.Stage("request_post_return", tapHeight, tapHash)\n\t\t}()')
            text = replace_once(text, "\t\t\t\t\t\tresults <- sealed\n\t\t\t\t\t\treturn", '\t\t\t\t\t\tresults <- sealed\n\t\t\t\t\t\ttap.Stage("seal_result", tapHeight, tapHash)\n\t\t\t\t\t\treturn')
            text = replace_once(text, "\t\t\t\tresults <- nil\n\t\t\t\treturn", '\t\t\t\tresults <- nil\n\t\t\t\ttap.Stage("seal_cancel", tapHeight, tapHash)\n\t\t\t\treturn')
        elif name.endswith("backend.go"):
            text = replace_once(text, "func (sb *Backend) startWBFT() error {", "func (sb *Backend) startWBFT(parent *p2p.WBFTTapOperation) error {")
            text = replace_once(text, "\tsb.core = wbftcore.New(sb, sb.config)", "\tsb.core = wbftcore.New(sb, sb.config)\n\tsb.core.SetWBFTTapEngine(p2p.WBFTTapNewEngine(parent))")
            text = replace_once(text, "func (sb *Backend) stop() error {", "func (sb *Backend) stop(parent *p2p.WBFTTapOperation) error {")
            text = replace_once(text, "core.Stop()", "core.StopObserved(parent)")
            text = replace_once(text, "func (sb *Backend) Close() error {", "func (sb *Backend) Close() error {\n\tp2p.WBFTTapRuntimeClose()\n")
        elif name.endswith("worker.go"):
            text = replace_once(text, "func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {", """func (w *worker) commitWork(interrupt *atomic.Int32, timestamp int64) {
\ttap := p2p.WBFTTapBegin("worker_commit_work", "", "", 1)
\ttapResult, tapHeight := "returned", ""
\tdefer func() { tap.End(tapResult, tapHeight, "", 0) }()""")
            text = replace_once(text, "\tif w.syncing.Load() {\n\t\treturn", '\tif w.syncing.Load() {\n\t\ttapResult = "syncing"\n\t\treturn')
            text = replace_once(text, '\t\t\tlog.Error("Refusing to mine without etherbase")', '\t\t\ttapResult = "missing_etherbase"\n\t\t\tlog.Error("Refusing to mine without etherbase")')
            text = replace_once(text, '\t\tlog.Error("Fail to prepare work", "err", err)', '\t\ttapResult = "prepare_error"\n\t\tlog.Error("Fail to prepare work", "err", err)')
            text = replace_once(text, "\t// Fill pending transactions from the txpool into the block.", "\tif p2p.WBFTTapEnabled() { tapHeight = work.header.Number.String() }\n\t// Fill pending transactions from the txpool into the block.")
            text = replace_once(text, "\t\twork.discard()\n\t\treturn", '\t\ttapResult = "new_head_discard"\n\t\twork.discard()\n\t\treturn')
            text = replace_once(text, '\t\tlog.Error("Fail to commit work", "err", err)', '\t\ttapResult = "commit_error"\n\t\tlog.Error("Fail to commit work", "err", err)')
            text = replace_once(text, "type environment struct {", "type environment struct {\n\ttap *p2p.WBFTTapOperation")
            text = replace_once(text, "\tcpy := &environment{", "\tcpy := &environment{\n\t\ttap: env.tap,")
            text = replace_once(text, "type task struct {", "type task struct {\n\ttap *p2p.WBFTTapOperation")
            text = replace_once(text, "\t// Fill pending transactions from the txpool into the block.", "\twork.tap = tap\n\t// Fill pending transactions from the txpool into the block.")
            text = replace_once(text, "\t\t\tselect {\n\t\t\tcase w.taskCh <- &task{", '\t\t\ttapHeight, tapHash := "", ""\n\t\t\tif env.tap != nil { tapHeight, tapHash = block.Number().String(), block.Hash().Hex() }\n\t\t\tenv.tap.Stage("task_offer", tapHeight, tapHash)\n\t\t\tselect {\n\t\t\tcase w.taskCh <- &task{tap: env.tap,')
            text = replace_once(text, "\t\t\t\tfees := totalFees", '\t\t\t\tenv.tap.Stage("task_sent", tapHeight, tapHash)\n\t\t\t\tfees := totalFees')
            text = replace_once(text, 'log.Info("Worker has exited")', 'env.tap.Stage("task_abandoned", tapHeight, tapHash)\n\t\t\t\tlog.Info("Worker has exited")')
            text = replace_once(text, "\t\tcase task := <-w.taskCh:", '\t\tcase task := <-w.taskCh:\n\t\t\ttapHeight, tapHash := "", ""\n\t\t\tif task.tap != nil { tapHeight, tapHash = task.block.Number().String(), task.block.Hash().Hex() }\n\t\t\ttask.tap.Stage("task_received", tapHeight, tapHash)')
            text = replace_once(text, "\t\t\tif sealHash == prev {\n\t\t\t\tcontinue", '\t\t\tif sealHash == prev {\n\t\t\t\ttask.tap.Stage("task_duplicate", tapHeight, tapHash)\n\t\t\t\tcontinue')
            text = replace_once(text, "\t\t\tif w.skipSealHook != nil && w.skipSealHook(task) {\n\t\t\t\tcontinue", '\t\t\tif w.skipSealHook != nil && w.skipSealHook(task) {\n\t\t\t\ttask.tap.Stage("task_skipped", tapHeight, tapHash)\n\t\t\t\tcontinue')
            text = replace_once(text, "w.engine.Seal(w.chain, task.block, w.resultCh, stopCh)", "func() error {\n\t\t\t\tif task.tap != nil {\n\t\t\t\t\tif observed, ok := w.engine.(interface{ SealObserved(consensus.ChainHeaderReader, *types.Block, chan<- *types.Block, <-chan struct{}, *p2p.WBFTTapOperation) error }); ok { return observed.SealObserved(w.chain, task.block, w.resultCh, stopCh, task.tap) }\n\t\t\t\t\ttask.tap.Stage(\"seal_unsupported\", tapHeight, tapHash)\n\t\t\t\t}\n\t\t\t\treturn w.engine.Seal(w.chain, task.block, w.resultCh, stopCh)\n\t\t\t}()")
        else:
            text = replace_once(text, "func (bc *BlockChain) InsertChain(chain types.Blocks) (int, error) {", """func (bc *BlockChain) InsertChain(chain types.Blocks) (tapIndex int, tapErr error) {
\ttapHeight, tapHash := "", ""
\tif p2p.WBFTTapEnabled() && len(chain)>0 && chain[0]!=nil { tapHeight, tapHash = chain[0].Number().String(), chain[0].Hash().Hex() }
\ttap := p2p.WBFTTapBegin("insert_chain", tapHeight, tapHash, len(chain))
\tdefer func() { tap.EndError(tapErr, tapHeight, tapHash, tapIndex) }()\n""")
            text = replace_once(text, "emitHeadEvent bool) (status WriteStatus, err error) {\n\tif !bc.chainmu.TryLock()", """emitHeadEvent bool) (status WriteStatus, err error) {
\ttapHeight, tapHash := "", ""
\tif p2p.WBFTTapEnabled() && block!=nil { tapHeight, tapHash = block.Number().String(), block.Hash().Hex() }
\ttap := p2p.WBFTTapBegin("write_block_and_set_head", tapHeight, tapHash, 1)
\tdefer func() { tap.EndError(err, tapHeight, tapHash, int(status)) }()
\tif !bc.chainmu.TryLock()""")
        files[name] = text
    test_template = Path(__file__).with_name("runtime_test.go.tmpl")
    if test_template.exists():
        files["p2p/wbft_tap_overlay_test.go"] = test_template.read_text()
    for package, template in [("miner", "worker_observation_test.go.tmpl"), ("consensus/wbft/backend", "seal_observation_test.go.tmpl")]:
        test = Path(__file__).with_name(template)
        if test.exists():
            files[package + "/wbft_tap_observation_test.go"] = test.read_text()
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
                "captures": ["wire_frames", "write_result", "stream_lifecycle", "io_intervals", "runtime_start_config", "runtime_stop", "application_call_boundaries", "exact_task_sealing_stages", "exact_engine_lifecycle"],
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
