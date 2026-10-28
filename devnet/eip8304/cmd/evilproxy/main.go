// evilproxy is a JSON-RPC reverse proxy that plays a malicious prover: it
// forwards every request to an honest node and rewrites the result of
// pureth_getLogsWithProofV1 according to the selected mode. The devnet check
// runs the standalone verifier on the rewritten proofs and requires every
// attack to be rejected (and the unmodified "none" mode to be accepted).
//
// Usage:
//
//	evilproxy -upstream http://127.0.0.1:8545 -listen 127.0.0.1:18545 -mode drop-block
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/core/logindex/logquery/adversary"
)

func main() {
	var (
		upstream = flag.String("upstream", "http://127.0.0.1:8545", "honest JSON-RPC endpoint")
		listen   = flag.String("listen", "127.0.0.1:18545", "address to listen on")
		mode     = flag.String("mode", "none", "rewrite mode: "+strings.Join(adversary.Modes, ", "))
	)
	flag.Parse()
	if !contains(adversary.Modes, *mode) {
		fmt.Fprintf(os.Stderr, "unknown mode %q\n", *mode)
		os.Exit(2)
	}
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp, err := http.Post(*upstream, "application/json", bytes.NewReader(body))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, err := io.ReadAll(resp.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		var req struct {
			Method string `json:"method"`
		}
		if json.Unmarshal(body, &req) == nil && req.Method == "pureth_getLogsWithProofV1" {
			out = rewrite(out, *mode)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(out)
	})
	log.Printf("evilproxy: %s -> %s, mode %s", *listen, *upstream, *mode)
	log.Fatal(http.ListenAndServe(*listen, nil))
}

// rewrite applies the attack to the result of a response; a response it cannot
// parse or attack is forwarded unchanged and the failure logged.
func rewrite(resp []byte, mode string) []byte {
	doc, err := adversary.Decode(resp)
	if err != nil {
		log.Printf("cannot decode response: %v", err)
		return resp
	}
	result, ok := doc["result"].(map[string]any)
	if !ok {
		return resp
	}
	if err := adversary.Apply(mode, result); err != nil {
		log.Printf("cannot apply %s: %v", mode, err)
		return resp
	}
	out, err := json.Marshal(doc)
	if err != nil {
		log.Printf("cannot encode response: %v", err)
		return resp
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
