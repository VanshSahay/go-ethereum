#!/usr/bin/env bash
# EIP-8304 devnet verification: index contract ring inspection, query parity
# against eth_getLogs, independent proof verification, tamper and absence
# demos, and indexer restart resilience.
#
# Usage: check.sh <rpc-url> [<second-participant-rpc-url>]
#
# With a second participant (the devnet runs one with --logindex.disable) the
# script also checks that both nodes follow the same chain: the table roots are
# derived from the chain history, so a node without an index must not diverge.
# Prerequisites: the devnet runs geth with --override.eip8304=0 (see
# args.json), so the node deployed the index contract at the first block (an
# optional devnet/eip8304/deployed_block overrides the first indexed block, and
# deploy.sh is only a debugging fallback), the spammer is producing ERC-20
# transfers, and the script is invoked from a checkout of this repository (the
# verifier runs through go run).
set -euo pipefail
RPC="$1"
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../.." && pwd)"
OUT="$(mktemp -d)"
CONTRACT=0x0000000000000000000000000000000000008304
TRANSFER=0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
# the index contract is deployed by the fork-activation system call at the
# first EIP-8304 block (--override.eip8304=0), so every block from 1 on is indexed
DEPLOY=1
if [ -f "$DIR/deployed_block" ]; then
  DEPLOY=$(cat "$DIR/deployed_block")
fi

head_number() {
  cast block-number --rpc-url "$RPC"
}

# verify_proof <proof.json> <topic0> [tamper <index>] runs the standalone
# verifier. The trusted reference hash comes from the node's own block (a light
# client would take it from its header chain) and the query file is the request
# the proof must answer.
verify_proof() {
  local proof=$1 topic=$2
  shift 2
  local ref_number ref_hash
  ref_number=$(jq -r '.refHeader.number' "$proof")
  ref_hash=$(cast block "$((ref_number))" --rpc-url "$RPC" --json | jq -r .hash)
  printf '{"pattern":{"field":"topics[0]","value":"%s"},"firstBlock":%d,"lastBlock":%d,"limit":10000,"limitLatest":false}' "$topic" "${VFROM:-$FROM}" "${VTO:-$TO}" > "$OUT/query.json"
  ( cd "$REPO" && go run ./devnet/eip8304/cmd/verify -network devnet -ref-hash "$ref_hash" -query "$OUT/query.json" "$proof" "$@" )
}

if [ -n "${2:-}" ]; then
  echo "== consensus parity with the index-less participant =="
  HEAD=$(cast block-number --rpc-url "$RPC")
  CHECK=$((HEAD > 8 ? HEAD - 8 : 1))
  A=$(cast block "$CHECK" --rpc-url "$RPC" --field hash)
  B=$(cast block "$CHECK" --rpc-url "$2" --field hash)
  if [ "$A" != "$B" ]; then
    echo "participants disagree at block $CHECK: $A vs $B" >&2
    exit 1
  fi
  echo "block $CHECK: $A on both participants"
fi

echo "== waiting for the index to accumulate blocks =="
TARGET=$((DEPLOY + 360))
while true; do
  HEAD=$(head_number)
  if [ "$HEAD" -ge "$TARGET" ]; then break; fi
  echo "  head $HEAD / $TARGET"
  sleep 10
done
echo "head: $HEAD, contract deployed at: $DEPLOY"

echo
echo "== index contract ring inspection =="
ring_get() { # first_block, table_size -> root or REVERT
  local fb=$1 ts=$2
  local data
  data="0x$(printf '%048x%016x%048x%016x' 0 "$fb" 0 "$ts")"
  cast call "$CONTRACT" --rpc-url "$RPC" --data "$data" 2>/dev/null || echo "REVERT (outside freshness window)"
}
echo "get() results at head $HEAD (readable iff fb + ts + ts/4 <= head):"
for TS in 1 4 16 64 256; do
  FB=$(( (HEAD - TS - TS/4) / TS * TS ))
  if [ "$FB" -lt "$DEPLOY" ]; then
    echo "  ts=$TS: no table published before the deployment yet"
    continue
  fi
  ROOT=$(ring_get "$FB" "$TS")
  echo "  ts=$TS first_block=$FB root=${ROOT:0:34}…"
  UNPUB=$((FB + TS))
  UNPUB_ROOT=$(ring_get "$UNPUB" "$TS")
  echo "  ts=$TS first_block=$UNPUB (unpublished) -> ${UNPUB_ROOT:0:24}…"
done

echo
echo "== query parity: pureth_getLogsWithProofV1 vs eth_getLogs =="
# one proven query returns at most 10000 logs (the RPC default); longer ranges are paged
FROM=$((DEPLOY + 2))
TO=$((HEAD - 2))
GETLOGS_PARAMS=$(printf '{"fromBlock":"0x%x","toBlock":"0x%x","topics":[["%s"]]}' "$FROM" "$TO" "$TRANSFER")
cast rpc --rpc-url "$RPC" eth_getLogs "$GETLOGS_PARAMS" > "$OUT/getlogs.json"
N_GETLOGS=$(jq 'length' "$OUT/getlogs.json")
# page through the range: a page that reaches the limit is cut inside its last
# block (lastBlock), so the next page starts at that block again and the logs
# already received are dropped by (block, log index)
START=$FROM
PAGE=0
echo "[]" > "$OUT/pages.json"
while [ "$START" -le "$TO" ]; do
  PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"}' "$TRANSFER" "$START" "$TO")
  cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PARAMS" > "$OUT/page$PAGE.json"
  PAGE_LAST=$(( $(jq -r '.lastBlock' "$OUT/page$PAGE.json") ))
  echo "  page $PAGE: blocks $START..$PAGE_LAST, $(jq '.logs | length' "$OUT/page$PAGE.json") logs"
  jq -s '.[0] + .[1].logs' "$OUT/pages.json" "$OUT/page$PAGE.json" > "$OUT/pages.tmp" && mv "$OUT/pages.tmp" "$OUT/pages.json"
  jq '.proof' "$OUT/page$PAGE.json" > "$OUT/proof$PAGE.json"
  VFROM=$START verify_proof "$OUT/proof$PAGE.json" "$TRANSFER" > "$OUT/verify$PAGE.log" 2>&1 || { cat "$OUT/verify$PAGE.log" >&2; echo "page $PAGE failed verification" >&2; exit 1; }
  N_PAGE=$(jq '.logs | length' "$OUT/page$PAGE.json")
  if [ "$N_PAGE" -ge 10000 ] && [ "$PAGE_LAST" -ge "$START" ]; then
    START=$PAGE_LAST
  else
    START=$((PAGE_LAST + 1))
  fi
  PAGE=$((PAGE + 1))
done
jq 'unique_by([.blockNumber, .logIndex])' "$OUT/pages.json" > "$OUT/pages.tmp" && mv "$OUT/pages.tmp" "$OUT/pages.json"
cp "$OUT/page0.json" "$OUT/result.json"
SMALL_TO=$((FROM + 40))
PURETH_PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"}' "$TRANSFER" "$FROM" "$SMALL_TO")
N_PURETH=$(jq 'length' "$OUT/pages.json")
echo "pureth logs: $N_PURETH over $PAGE verified pages, eth_getLogs logs: $N_GETLOGS over blocks $FROM..$TO"
if [ "$N_PURETH" -ne "$N_GETLOGS" ] || [ "$N_PURETH" -eq 0 ]; then
  echo "PARITY FAIL" >&2
  exit 1
fi
if ! diff <(jq -S 'sort_by(.blockNumber, .logIndex)' "$OUT/pages.json") <(jq -S 'sort_by(.blockNumber, .logIndex)' "$OUT/getlogs.json") > "$OUT/parity.diff"; then
  echo "log mismatch (first differences):" >&2
  head -20 "$OUT/parity.diff" >&2
  exit 1
fi
echo "parity: all $N_PURETH logs identical"

echo
echo "== independent proof verification =="
jq '.proof' "$OUT/result.json" > "$OUT/proof.json"
verify_proof "$OUT/proof.json" "$TRANSFER"

echo
echo "== tamper demos (each modified proof must be rejected) =="
for IDX in 0 40 90; do
  echo "--- tamper index $IDX"
  if verify_proof "$OUT/proof.json" "$TRANSFER" tamper "$IDX"; then
    echo "TAMPER DEMO FAILED: tampered proof verified" >&2
    exit 1
  fi
done

echo
echo "== adversarial prover (every rewritten proof must be rejected) =="
PROXY="$OUT/evilproxy"
( cd "$REPO" && go build -o "$PROXY" ./devnet/eip8304/cmd/evilproxy )
PROXY_PORT=${PROXY_PORT:-28545}
PROXY_PID=""
trap '[ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true' EXIT
for MODE in none drop-block forge-contract bad-ref truncate-range flip-hash; do
  "$PROXY" -upstream "$RPC" -listen "127.0.0.1:$PROXY_PORT" -mode "$MODE" > "$OUT/proxy-$MODE.log" 2>&1 &
  PROXY_PID=$!
  for _ in $(seq 1 60); do
    (echo > "/dev/tcp/127.0.0.1/$PROXY_PORT") 2>/dev/null && break
    sleep 0.5
  done
  cast rpc --rpc-url "http://127.0.0.1:$PROXY_PORT" pureth_getLogsWithProofV1 "$PURETH_PARAMS" | jq '.proof' > "$OUT/proof-$MODE.json"
  kill "$PROXY_PID" 2>/dev/null || true
  wait "$PROXY_PID" 2>/dev/null || true
  if [ "$MODE" = "none" ]; then
    echo "--- $MODE (the honest proof through the proxy must verify)"
    VTO=$SMALL_TO verify_proof "$OUT/proof-$MODE.json" "$TRANSFER"
  else
    echo "--- $MODE"
    if VTO=$SMALL_TO verify_proof "$OUT/proof-$MODE.json" "$TRANSFER"; then
      echo "ADVERSARY DEMO FAILED: $MODE proof verified" >&2
      exit 1
    fi
  fi
done

echo
echo "== absence proof (querying a log that never happened) =="
DEAD=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
ABSENT_PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"}' "$DEAD" "$FROM" "$TO")
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$ABSENT_PARAMS" > "$OUT/absent.json"
N_ABSENT=$(jq '.logs | length' "$OUT/absent.json")
echo "absent-topic logs: $N_ABSENT"
jq '.proof' "$OUT/absent.json" > "$OUT/absent_proof.json"
verify_proof "$OUT/absent_proof.json" "$DEAD"

echo
echo "== restart resilience (file-backed indexer reload) =="
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PURETH_PARAMS" > "$OUT/result1.json"
N_BEFORE=$(jq '.logs | length' "$OUT/result1.json")
EL_CONTAINER=$(docker ps --format '{{.Names}}' | grep 'el-1-geth' | head -1)
docker restart "$EL_CONTAINER" > /dev/null
# docker maps the published port again on restart: follow the container
NEW_RPC=$(docker port "$EL_CONTAINER" 8545/tcp | head -1 | sed 's/^0\.0\.0\.0/127.0.0.1/')
RPC=${NEW_RPC:-$RPC}
while ! cast block-number --rpc-url "$RPC" > /dev/null 2>&1; do
  sleep 3
done
echo "node restarted, head back online at $(head_number)"
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PURETH_PARAMS" > "$OUT/result2.json"
N_PURETH2=$(jq '.logs | length' "$OUT/result2.json")
echo "logs after restart: $N_PURETH2 (before: $N_BEFORE)"
[ "$N_PURETH2" -eq "$N_BEFORE" ] || { echo "RESTART FAIL" >&2; exit 1; }
jq -S '.logs' "$OUT/result2.json" > "$OUT/logs2.sorted"
jq -S '.logs' "$OUT/result1.json" > "$OUT/logs1.sorted"
diff "$OUT/logs1.sorted" "$OUT/logs2.sorted" > /dev/null || { echo "logs differ after restart" >&2; exit 1; }
echo "identical results after restart"

echo
echo "ALL CHECKS PASSED (artifacts in $OUT)"
