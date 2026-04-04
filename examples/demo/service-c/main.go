// Service C is the terminal service in the demo.
// It verifies the incoming TxToken and logs the full transaction context.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/aramase/kontxt/sdk/middleware"
	"github.com/aramase/kontxt/sdk/verify"
)

func main() {
	addr := flag.String("addr", ":8083", "listen address")
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "demo.example.com", "trust domain")
	flag.Parse()

	verifier := verify.New(*jwksURL, *trustDomain)

	mux := http.NewServeMux()
	mux.Handle("GET /api/store", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())

		tctxJSON, _ := json.Marshal(claims.TransactionContext)
		log.Printf("[service-c] txn=%s sub=%s scope=%s tctx=%s",
			claims.TransactionID, claims.Subject, claims.Scope, string(tctxJSON))

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "stored"})
	})))

	fmt.Printf("Service C listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
