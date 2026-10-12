# Sanitized G7 regression input

Unchanged metadata-only excerpts from wbft-analyzer main `781baf8`,
`internal/source/logs/testdata/g7`. They contain 310 selected records at
heights 5542 and 5565 from a real local G7 go-stablenet `740526d03` run.
Source payloads, data, arbitrary errors and unrelated records were removed;
line numbers and file hashes here differ from the full originals. This is
an incomplete excerpt, not a complete event stream or a wire archive.

Node4 stopped before height 5542 (round 1: five timeout/one F+1 entries).
Node5 and node6 stopped before height 5565 (rounds 1 and 2: five timeout
entries each). The full source reports are verified separately against
all original files and their original SHA256/line pointers.
