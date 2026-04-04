// Service B is the middle service in the demo.
// It verifies the incoming TxToken, logs the transaction, and forwards to Service C.
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
	jwksURL := flag.String("jwks", "http://localhost:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "demo.example.com", "trust domain")
	serviceCURL := flag.String("service-c", "http://localhost:8083", "Service C URL")
	flag.Parse()

	verifier := verify.New(*jwksURL, *trustDomain)

	mux := http.NewServeMux()
	mux.Handle("GET /api/process", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		log.Printf("[service-b] txn=%s sub=%s scope=%s", claims.TransactionID, claims.Subject, claims.Scope)

		// Forward to Service C
		client := &http.Client{Transport: middleware.NewPropagateTransport(http.DefaultTransport)}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, *serviceCURL+"/api/store", nil)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "failed to call service-c", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
	})))

	fmt.Printf("Service B listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
