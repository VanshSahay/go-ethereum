// Command mkchain mines a long chain of log-emitting blocks on a `geth --dev
// --dev.period 0` node, so the EIP-8304 checks can run past the table
// publication and retention windows without waiting for real slots.
//
// Every transaction makes the dev node seal one block, and calls a tiny
// contract that emits one LOG2 whose topics are the first two calldata words.
// The first topic is the ERC-20 Transfer signature, so check.sh finds the logs
// exactly as it finds the spammer's; the second one cycles through -topics
// values.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

// emitter runtime: PUSH1 32 CALLDATALOAD PUSH0 CALLDATALOAD PUSH1 0 PUSH1 0 LOG2 STOP
var runtimeCode = common.FromHex("0x6020355f3560006000a200")

var transferTopic = common.HexToHash("0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef")

func main() {
	var (
		url    = flag.String("rpc", "http://127.0.0.1:8545", "dev node RPC endpoint")
		blocks = flag.Uint64("blocks", 1200, "mine until the head reaches this height")
		topics = flag.Int("topics", 64, "number of distinct topics to cycle through")
	)
	flag.Parse()

	ctx := context.Background()
	c, err := rpc.DialContext(ctx, *url)
	if err != nil {
		log.Fatal(err)
	}
	var accounts []common.Address
	if err := c.CallContext(ctx, &accounts, "eth_accounts"); err != nil || len(accounts) == 0 {
		log.Fatalf("no dev account (%v): is this a --dev node?", err)
	}
	from := accounts[0]

	head := func() uint64 {
		var n hexutil.Uint64
		if err := c.CallContext(ctx, &n, "eth_blockNumber"); err != nil {
			log.Fatal(err)
		}
		return uint64(n)
	}
	send := func(to *common.Address, data []byte) common.Hash {
		args := map[string]any{"from": from, "data": hexutil.Bytes(data), "gas": hexutil.Uint64(200000)}
		if to != nil {
			args["to"] = *to
		}
		var h common.Hash
		if err := c.CallContext(ctx, &h, "eth_sendTransaction", args); err != nil {
			log.Fatalf("send: %v", err)
		}
		return h
	}

	// init code: PUSH<n> <runtime> PUSH0 MSTORE PUSH1 n PUSH1 32-n RETURN
	n := byte(len(runtimeCode))
	initCode := append([]byte{0x5f + n}, runtimeCode...)
	initCode = append(initCode, 0x5f, 0x52, 0x60, n, 0x60, 32-n, 0xf3)
	deployTx := send(nil, initCode)
	var receipt struct {
		ContractAddress *common.Address `json:"contractAddress"`
	}
	for i := 0; i < 100 && receipt.ContractAddress == nil; i++ {
		time.Sleep(50 * time.Millisecond)
		_ = c.CallContext(ctx, &receipt, "eth_getTransactionReceipt", deployTx)
	}
	if receipt.ContractAddress == nil {
		log.Fatal("emitter deployment was not mined")
	}
	emitter := *receipt.ContractAddress
	fmt.Printf("emitter %s, head %d\n", emitter, head())

	start, startHead := time.Now(), head()
	for i := 0; ; i++ {
		prev := head()
		if prev >= *blocks {
			break
		}
		data := append(transferTopic.Bytes(), common.BigToHash(big.NewInt(int64(i%*topics))).Bytes()...)
		send(&emitter, data)
		// one block per transaction: wait for it so nonces never collide
		for head() == prev {
			time.Sleep(2 * time.Millisecond)
		}
		if i%200 == 0 {
			fmt.Printf("head %d (%.1f blocks/s)\n", head(), float64(head()-startHead)/time.Since(start).Seconds())
		}
	}
	fmt.Printf("head %d after %v\n", head(), time.Since(start).Round(time.Millisecond))
}
