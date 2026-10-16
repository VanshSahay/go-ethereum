#!/usr/bin/env bash
# Deploys the EIP-8304 index contract to the devnet with a regular creation
# transaction. The node deploys the system contract itself at fork activation,
# so this is only a fallback for debugging; the code lands at the CREATE
# address of the sender, not the fixed system address.
#
# Usage: deploy.sh <rpc-url>
set -euo pipefail
RPC="$1"
DIR="$(dirname "$0")"
MNEMONIC="giant issue aisle success illegal bike spike question tent bar rely arctic volcano long crawl hungry vocal artwork sniff fantasy very lucky have athlete"
PRIVKEY=$(cast wallet private-key --mnemonic "$MNEMONIC" --mnemonic-index 0)
echo "deploying the index contract at $RPC"
CODE=$(cat "$DIR/index_contract.hex")
TXHASH=$(cast send --rpc-url "$RPC" --private-key "$PRIVKEY" --create "0x$CODE" --json | jq -r .transactionHash)
echo "tx: $TXHASH"
for i in $(seq 1 60); do
  STATUS=$(cast receipt "$TXHASH" --rpc-url "$RPC" --json | jq -r .status 2>/dev/null || echo pending)
  if [ "$STATUS" = "0x1" ]; then break; fi
  sleep 1
done
if [ "$STATUS" != "0x1" ]; then
  echo "deployment failed (status $STATUS)" >&2
  exit 1
fi
BLOCK=$(cast receipt "$TXHASH" --rpc-url "$RPC" --json | jq -r .blockNumber)
echo "deployed in block $BLOCK"
echo "$BLOCK" > "$DIR/deployed_block"
