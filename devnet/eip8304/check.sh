#!/usr/bin/env bash
# EIP-8304 devnet verification: index contract ring inspection, query parity
# against eth_getLogs, independent proof verification, tamper and absence
# demos, and indexer restart resilience.
#
# Usage: check.sh <rpc-url>
# Prerequisites: deploy.sh has run (devnet/eip8304/deployed_block exists),
# the spammer is producing ERC-20 transfers, and the script is invoked from a
# checkout of this repository (the verifier runs through go run).
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
  printf '{"pattern":{"field":"topics[0]","value":"%s"},"firstBlock":%d,"lastBlock":%d,"limit":18446744073709551615,"limitLatest":false}' "$topic" "$FROM" "$TO" > "$OUT/query.json"
  ( cd "$REPO" && go run ./devnet/eip8304/cmd/verify -network devnet -ref-hash "$ref_hash" -query "$OUT/query.json" "$proof" "$@" )
}

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
FROM=$((DEPLOY + 2))
TO=$((HEAD - 2))
PURETH_PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"}' "$TRANSFER" "$FROM" "$TO")
GETLOGS_PARAMS=$(printf '{"fromBlock":"0x%x","toBlock":"0x%x","topics":[["%s"]]}' "$FROM" "$TO" "$TRANSFER")
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PURETH_PARAMS" > "$OUT/result.json"
cast rpc --rpc-url "$RPC" eth_getLogs "$GETLOGS_PARAMS" > "$OUT/getlogs.json"
N_PURETH=$(jq '.logs | length' "$OUT/result.json")
N_GETLOGS=$(jq 'length' "$OUT/getlogs.json")
echo "pureth logs: $N_PURETH, eth_getLogs logs: $N_GETLOGS over blocks $FROM..$TO"
if [ "$N_PURETH" -ne "$N_GETLOGS" ] || [ "$N_PURETH" -eq 0 ]; then
  echo "PARITY FAIL" >&2
  exit 1
fi
if ! diff <(jq -S '.logs | sort_by(.blockNumber, .logIndex)' "$OUT/result.json") <(jq -S 'sort_by(.blockNumber, .logIndex)' "$OUT/getlogs.json") > "$OUT/parity.diff"; then
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
EL_CONTAINER=$(docker ps --format '{{.Names}}' | grep 'el-1-geth' | head -1)
docker restart "$EL_CONTAINER" > /dev/null
while ! cast block-number --rpc-url "$RPC" > /dev/null 2>&1; do
  sleep 3
done
echo "node restarted, head back online at $(head_number)"
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PURETH_PARAMS" > "$OUT/result2.json"
N_PURETH2=$(jq '.logs | length' "$OUT/result2.json")
echo "logs after restart: $N_PURETH2 (before: $N_PURETH)"
[ "$N_PURETH2" -eq "$N_PURETH" ] || { echo "RESTART FAIL" >&2; exit 1; }
jq -S '.logs' "$OUT/result2.json" > "$OUT/logs2.sorted"
jq -S '.logs' "$OUT/result.json" > "$OUT/logs1.sorted"
diff "$OUT/logs1.sorted" "$OUT/logs2.sorted" > /dev/null || { echo "logs differ after restart" >&2; exit 1; }
echo "identical results after restart"

echo
echo "ALL CHECKS PASSED (artifacts in $OUT)"
