#!/usr/bin/env bash
# EIP-8304 devnet verification: index contract ring inspection, query parity
# against eth_getLogs, independent proof verification, tamper and absence
# demos, and indexer restart resilience.
#
# Usage: check.sh <rpc-url> [<second-participant-rpc-url>]
#
# Environment knobs (all optional):
#   TARGET       head to wait for before checking (default: first indexed block
#                + 360). 1100 or more makes the retained-levels step run past
#                the level-0 window, 4200 or more past level 1.
#   PAGE_LIMIT   limit of every forward page, so short chains still exercise
#                cursor paging.
#   RESTART_CMD  command that restarts the node under test (default: docker
#                restart of the el-1-geth container). With a geth --dev node,
#                see dev/run.sh.
#   TAMPER_ALL   non-empty: also flip every hex/base64 string of one proof, one at a
#                time, and require each modified proof to be rejected.
#   PROXY_PORT   listen port of the adversarial proxy (default 28545).
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

# build the verifier once instead of re-linking it through go run per proof
VERIFY_BIN="$OUT/verify"
( cd "$REPO" && go build -o "$VERIFY_BIN" ./devnet/eip8304/cmd/verify )

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
  if [ "$ref_number" != "${REF_CACHE_N:-}" ]; then
    REF_CACHE_HASH=$(cast block "$((ref_number))" --rpc-url "$RPC" --json | jq -r .hash)
    REF_CACHE_N=$ref_number
  fi
  ref_hash=$REF_CACHE_HASH
  printf '{"pattern":{"field":"topics[0]","value":"%s"},"firstBlock":%d,"lastBlock":%d,"limit":%s,"limitLatest":%s%s}' "$topic" "${VFROM:-$FROM}" "${VTO:-$TO}" "${VLIMIT:-10000}" "${VLATEST:-false}" "${VCURSOR:-}" > "$OUT/query.json"
  "$VERIFY_BIN" -network devnet -ref-hash "$ref_hash" -query "$OUT/query.json" "$proof" "$@"
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
TARGET=${TARGET:-$((DEPLOY + 360))}
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
# blocks below the first 16 have no table above level 1 (none covers the
# genesis block) and age out of the lowest levels, so start at the first full
# 16-block table
FROM=$((DEPLOY + 15))
TO=$((HEAD - 2))
GETLOGS_PARAMS=$(printf '{"fromBlock":"0x%x","toBlock":"0x%x","topics":[["%s"]]}' "$FROM" "$TO" "$TRANSFER")
cast rpc --rpc-url "$RPC" eth_getLogs "$GETLOGS_PARAMS" > "$OUT/getlogs.json"
N_GETLOGS=$(jq 'length' "$OUT/getlogs.json")
# page through the range: a page that reaches the limit carries a nextCursor
# (its last log), and the next page starts at that block after the cursor
PAGE_LIMIT_PARAM=""
[ -n "${PAGE_LIMIT:-}" ] && PAGE_LIMIT_PARAM=$(printf ',"limit":"0x%x"' "$PAGE_LIMIT")
START=$FROM
CURSOR=""
VCURSOR_NEXT=""
PAGE=0
echo "[]" > "$OUT/pages.json"
while [ "$START" -le "$TO" ]; do
  PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"%s%s}' "$TRANSFER" "$START" "$TO" "$PAGE_LIMIT_PARAM" "$CURSOR")
  cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PARAMS" > "$OUT/page$PAGE.json"
  PAGE_LAST=$(( $(jq -r '.lastBlock' "$OUT/page$PAGE.json") ))
  echo "  page $PAGE: blocks $START..$PAGE_LAST, $(jq '.logs | length' "$OUT/page$PAGE.json") logs"
  jq -s '.[0] + .[1].logs' "$OUT/pages.json" "$OUT/page$PAGE.json" > "$OUT/pages.tmp" && mv "$OUT/pages.tmp" "$OUT/pages.json"
  jq '.proof' "$OUT/page$PAGE.json" > "$OUT/proof$PAGE.json"
  VFROM=$START VLIMIT=${PAGE_LIMIT:-10000} VCURSOR=$VCURSOR_NEXT verify_proof "$OUT/proof$PAGE.json" "$TRANSFER" > "$OUT/verify$PAGE.log" 2>&1 || { cat "$OUT/verify$PAGE.log" >&2; echo "page $PAGE failed verification" >&2; exit 1; }
  if [ "$(jq -r '.nextCursor // empty' "$OUT/page$PAGE.json")" != "" ]; then
    CUR_BLOCK=$(( $(jq -r '.nextCursor.block' "$OUT/page$PAGE.json") ))
    CUR_INDEX=$(( $(jq -r '.nextCursor.logIndex' "$OUT/page$PAGE.json") ))
    CURSOR=$(printf ',"cursor":{"block":"0x%x","logIndex":"0x%x"}' "$CUR_BLOCK" "$CUR_INDEX")
    VCURSOR_NEXT=$(printf ',"cursor":{"block":%d,"logIndex":%d}' "$CUR_BLOCK" "$CUR_INDEX")
    START=$CUR_BLOCK
  else
    START=$((PAGE_LAST + 1))
    CURSOR=""
    VCURSOR_NEXT=""
  fi
  PAGE=$((PAGE + 1))
done
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
# result.json is the first page: it answers the paged request, limit included
VLIMIT=${PAGE_LIMIT:-10000} verify_proof "$OUT/proof.json" "$TRANSFER"

echo
echo "== tamper demos (each modified proof must be rejected) =="
for IDX in 0 40 90; do
  echo "--- tamper index $IDX"
  if VLIMIT=${PAGE_LIMIT:-10000} verify_proof "$OUT/proof.json" "$TRANSFER" tamper "$IDX"; then
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

if [ -n "${TAMPER_ALL:-}" ]; then
  echo
  echo "== exhaustive tamper scan (every hex and base64 string of one proof, one byte flipped each) =="
  SCANNED=0
  while true; do
    if OUTPUT=$(VTO=$SMALL_TO verify_proof "$OUT/proof-none.json" "$TRANSFER" tamper "$SCANNED" 2>&1); then
      echo "$OUTPUT" | grep tampering >&2
      echo "TAMPER SCAN FAILED: the proof verified with string $SCANNED modified" >&2
      exit 1
    fi
    if echo "$OUTPUT" | grep -q "out of range"; then break; fi
    SCANNED=$((SCANNED + 1))
  done
  echo "all $SCANNED single-byte modifications rejected"
fi

echo
echo "== retained levels: an old range and a reverse (limitLatest) cursor walk =="
# once the head is past the level-0 window the lowest levels no longer hold the
# old blocks: the old range is served and proven by the higher levels
OLD_FROM=$((DEPLOY + 19))
OLD_TO=$((OLD_FROM + 60))
OLD_PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x"}' "$TRANSFER" "$OLD_FROM" "$OLD_TO")
cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$OLD_PARAMS" > "$OUT/old.json"
jq '.proof' "$OUT/old.json" > "$OUT/old_proof.json"
VFROM=$OLD_FROM VTO=$OLD_TO verify_proof "$OUT/old_proof.json" "$TRANSFER"
echo "old range $OLD_FROM..$OLD_TO: $(jq '.logs | length' "$OUT/old.json") logs verified at head $(head_number)"

# newest-first walk over a short range with a small limit
REV_TO=$((DEPLOY + 40))
REV_LIMIT=500
CURSOR=""
REV_VCURSOR=""
LAST_BLOCK=$REV_TO
REV_TOTAL=0
for REV_PAGE in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19; do
  PARAMS=$(printf '{"topics":[["%s"]],"firstBlock":"0x%x","lastBlock":"0x%x","limit":"0x%x","limitLatest":true%s}' "$TRANSFER" "$FROM" "$LAST_BLOCK" "$REV_LIMIT" "$CURSOR")
  cast rpc --rpc-url "$RPC" pureth_getLogsWithProofV1 "$PARAMS" > "$OUT/rev$REV_PAGE.json"
  jq '.proof' "$OUT/rev$REV_PAGE.json" > "$OUT/revproof$REV_PAGE.json"
  VFROM=$FROM VTO=$LAST_BLOCK VLIMIT=$REV_LIMIT VLATEST=true VCURSOR=$REV_VCURSOR verify_proof "$OUT/revproof$REV_PAGE.json" "$TRANSFER" > "$OUT/revverify$REV_PAGE.log" 2>&1 || { cat "$OUT/revverify$REV_PAGE.log" >&2; echo "reverse page $REV_PAGE failed verification" >&2; exit 1; }
  REV_TOTAL=$((REV_TOTAL + $(jq '.logs | length' "$OUT/rev$REV_PAGE.json")))
  NEXT=$(jq -r '.nextCursor // empty' "$OUT/rev$REV_PAGE.json")
  [ -z "$NEXT" ] && break
  NB=$(( $(jq -r '.nextCursor.block' "$OUT/rev$REV_PAGE.json") ))
  NI=$(( $(jq -r '.nextCursor.logIndex' "$OUT/rev$REV_PAGE.json") ))
  CURSOR=$(printf ',"cursor":{"block":"0x%x","logIndex":"0x%x"}' "$NB" "$NI")
  REV_VCURSOR=$(printf ',"cursor":{"block":%d,"logIndex":%d}' "$NB" "$NI")
  LAST_BLOCK=$NB
done
WANT=$(cast rpc --rpc-url "$RPC" eth_getLogs "$(printf '{"fromBlock":"0x%x","toBlock":"0x%x","topics":[["%s"]]}' "$FROM" "$REV_TO" "$TRANSFER")" | jq 'length')
echo "reverse walk: $((REV_PAGE + 1)) pages, $REV_TOTAL logs (eth_getLogs: $WANT)"
[ "$REV_TOTAL" -eq "$WANT" ] || { echo "REVERSE WALK FAIL" >&2; exit 1; }

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
if [ -n "${RESTART_CMD:-}" ]; then
  bash -c "$RESTART_CMD"
else
  EL_CONTAINER=$(docker ps --format '{{.Names}}' | grep 'el-1-geth' | head -1)
  # the harness stops containers after one second, too short for a clean state
  # journal: give the node time to shut down
  docker restart -t 60 "$EL_CONTAINER" > /dev/null
  # docker maps the published port again on restart: follow the container
  NEW_RPC=$(docker port "$EL_CONTAINER" 8545/tcp | head -1 | sed 's/^0\.0\.0\.0/127.0.0.1/')
  RPC=${NEW_RPC:-$RPC}
fi
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
