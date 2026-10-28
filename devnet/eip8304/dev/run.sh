#!/usr/bin/env bash
# Fast EIP-8304 check on a single geth --dev node: no consensus client, blocks
# are sealed on demand, so a chain past the level-0 retention window (about
# 1,025 blocks) takes about half a minute instead of over an hour of 4s slots.
# What this cannot cover (two real clients, p2p sync, Engine API) stays on the
# Kurtosis devnet, see ../check.sh.
#
# Usage: dev/run.sh [blocks]      (default 1200)
# Environment: HTTP_PORT (default 28545), PROXY_PORT (default 29545), KEEP=1 to
# leave the node and its datadir running for inspection.
set -euo pipefail
BLOCKS=${1:-1200}
DIR="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$DIR/../../.." && pwd)"
HTTP_PORT=${HTTP_PORT:-28545}
PROXY_PORT=${PROXY_PORT:-29545}
WORK="$(mktemp -d)"
GETH="$WORK/geth"
RPC="http://127.0.0.1:$HTTP_PORT"

( cd "$REPO" && go build -o "$GETH" ./cmd/geth && go build -o "$WORK/mkchain" ./devnet/eip8304/cmd/mkchain )

start_node() {
  "$GETH" --dev --dev.period 0 --override.eip8304=0 --datadir "$WORK/data" \
    --http --http.api eth,debug,pureth,dev,txpool,web3 --http.port "$HTTP_PORT" \
    --authrpc.port $((HTTP_PORT + 6)) --port 0 --nodiscover --verbosity 3 >> "$WORK/geth.log" 2>&1 &
  echo $! > "$WORK/geth.pid"
  for _ in $(seq 1 60); do
    cast block-number --rpc-url "$RPC" > /dev/null 2>&1 && return
    sleep 0.5
  done
  echo "node did not come up, see $WORK/geth.log" >&2
  exit 1
}
stop_node() {
  [ -f "$WORK/geth.pid" ] && kill "$(cat "$WORK/geth.pid")" 2>/dev/null && wait "$(cat "$WORK/geth.pid")" 2>/dev/null || true
}
if [ -z "${KEEP:-}" ]; then
  trap 'stop_node; rm -rf "$WORK"' EXIT
fi

start_node
"$WORK/mkchain" -rpc "$RPC" -blocks "$BLOCKS" | tail -2

# the dev node has no spammer: a small page limit exercises cursor paging on
# the one-log-per-block chain
export TARGET=$BLOCKS PAGE_LIMIT=${PAGE_LIMIT:-300} PROXY_PORT
cat > "$WORK/restart.sh" <<RESTART
#!/usr/bin/env bash
set -e
PID=\$(cat "$WORK/geth.pid")
kill "\$PID"
while kill -0 "\$PID" 2>/dev/null; do sleep 0.5; done
"$GETH" --dev --dev.period 0 --override.eip8304=0 --datadir "$WORK/data" \\
  --http --http.api eth,debug,pureth,dev,txpool,web3 --http.port "$HTTP_PORT" \\
  --authrpc.port $((HTTP_PORT + 6)) --port 0 --nodiscover --verbosity 3 >> "$WORK/geth.log" 2>&1 &
echo \$! > "$WORK/geth.pid"
RESTART
chmod +x "$WORK/restart.sh"
export RESTART_CMD="$WORK/restart.sh"
"$REPO/devnet/eip8304/check.sh" "$RPC"
