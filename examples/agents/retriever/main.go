// retriever is the document retrieval agent in the AI Research Assistant demo.
// It verifies the incoming TxToken (defense-in-depth alongside gateway ext_authz)
// and returns mock documents.
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
	addr := flag.String("addr", ":8082", "listen address")
	jwksURL := flag.String("jwks", "http://kontxt-tts.kontxt-system.svc.cluster.local:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "demo.example.com", "trust domain")
	flag.Parse()

	verifier := verify.New(*jwksURL, *trustDomain)

	mux := http.NewServeMux()
	mux.Handle("GET /api/retrieve", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())

		tctxJSON, _ := json.Marshal(claims.TransactionContext)
		log.Printf("[retriever] txn=%s sub=%s scope=%s tctx=%s",
			claims.TransactionID, claims.Subject, claims.Scope, string(tctxJSON))

		company := r.URL.Query().Get("company")
		if company == "" {
			company = "ACME"
		}

		// Return mock documents
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"documents": []string{
				fmt.Sprintf("%s Annual Report 2024 - Revenue grew 15%% YoY to $4.2B", company),
				fmt.Sprintf("%s Q3 Earnings Call Transcript - CEO highlighted strong cloud growth", company),
				fmt.Sprintf("%s SEC Filing 10-K - Operating margins expanded to 22%%", company),
			},
		})
	})))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("retriever listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
