# Frame dumps

`wbft-kvstore/` is an R-01 frame dump of node 0 of a four-node `wbft-kvstore`
development network (wbft `examples/kvstore`), heights 1 to 3, written by
`wbft-journal export --format r01 --to 3` from wbft `50736b7`. The payloads
are consensus messages of that test network; it holds no secrets.

`wbft-kvstore-stalled/` is node 0 of a four-node `wbft-kvstore` network in
which two nodes were stopped after a few blocks, so that the round stalled
and the retry timer retransmitted ROUND-CHANGE. It holds heights 7 and up of
that run, written by `wbft-journal export --format r01 --from 7` from wbft
`72d2147`, which records send causes and suppressed sends. Every
retransmission is a `send_suppressed` record with cause `retry`.
