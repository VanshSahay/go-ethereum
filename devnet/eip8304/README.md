# EIP-8304 devnet checks

Two ways to run the same end-to-end check (`check.sh`): proven queries against
`eth_getLogs`, independent proof verification, tamper and adversarial-prover
rejection, absence proofs, retained levels, reverse cursor walks and a restart.

| | `dev/run.sh` (single `geth --dev` node) | Kurtosis devnet (`args.json`) |
|---|---|---|
| Needs | Go, `cast`, `jq` | Docker, Kurtosis, `my-geth:8304` image |
| Blocks | sealed on demand, ~50 per second | real slots (2 s or 4 s) |
| 1,200 blocks (past the level-0 ring of 1,025) | about 25 s, whole check about 75 s | 40 min at 2 s, 80 min at 4 s |
| 4,300 blocks (past the level-1 ring of 4,101) | about 90 s, whole check about 4 min | 2.4 h at 2 s |
| Covers | index, RPC, verifier, retention, rewind across a due height, restart | two real clients, Engine API, consensus parity with a `--logindex.disable` node, p2p |

Table sizes stay the spec's (1, 4, 16, 64, 256) in both: they are
consensus-relevant and the ring size is part of the index contract, so there is
no shortcut by shrinking them. The dev harness makes blocks cheap instead.

## Fast run

```sh
devnet/eip8304/dev/run.sh 1200     # chain past the level-0 retention window
devnet/eip8304/dev/run.sh 4300     # past level 1
REWIND=0 TAMPER_ALL= devnet/eip8304/dev/run.sh 400    # quick smoke test
```

`run.sh` builds geth and `cmd/mkchain`, starts `geth --dev --dev.period 0
--override.eip8304=0`, mines the chain (one log-emitting transaction per block,
ERC-20 `Transfer` topic), rewinds `REWIND` blocks with `debug_setHead` and
rebuilds them so the index follows a reorg across a due 256-block table, then
runs `check.sh` with a small page limit (cursor paging on a short chain), the
exhaustive tamper scan, and a restart of the same node.

## Kurtosis run

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o build/bin/geth ./cmd/geth
docker build -t my-geth:8304 -f devnet/eip8304/Dockerfile .
kurtosis run github.com/ethpandaops/ethereum-package --args-file devnet/eip8304/args.json --enclave eip8304
devnet/eip8304/check.sh "$(kurtosis port print eip8304 el-1-geth-lighthouse rpc)" \
                         "$(kurtosis port print eip8304 el-2-geth-lighthouse rpc)"
```

`args.json` uses 4 s slots; 2 s also works (`seconds_per_slot`), which halves
the wait.

## check.sh knobs

| Variable | Effect |
|---|---|
| `TARGET` | head to wait for (default: first indexed block + 360, just past the first 256-block table's publication at block 319) |
| `PAGE_LIMIT` | limit of each forward page, so short chains still page with cursors |
| `TAMPER_ALL` | flip every hex and base64 string of one proof, one at a time; each must be rejected |
| `RESTART_CMD` | how to restart the node under test (default: `docker restart` of the `el-1-geth` container) |
| `PROXY_PORT` | listen port of the adversarial proxy (default 28545) |

The tamper index of `cmd/verify ... tamper <i>` is stable across runs (object
keys are visited in sorted order), and the header's derived `hash` member is
skipped because the verifier recomputes it.
