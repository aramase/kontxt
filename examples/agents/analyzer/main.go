// analyzer is the analysis engine agent in the AI Research Assistant demo.
// It verifies the incoming TxToken (defense-in-depth alongside gateway ext_authz)
// and returns mock analysis results.
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
	jwksURL := flag.String("jwks", "http://kontxt-tts.kontxt-system.svc.cluster.local:8080/.well-known/jwks.json", "TTS JWKS URL")
	trustDomain := flag.String("trust-domain", "demo.example.com", "trust domain")
	flag.Parse()

	verifier := verify.New(*jwksURL, *trustDomain)

	mux := http.NewServeMux()
	mux.Handle("POST /api/analyze", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())

		tctxJSON, _ := json.Marshal(claims.TransactionContext)
		log.Printf("[analyzer] txn=%s sub=%s scope=%s tctx=%s",
			claims.TransactionID, claims.Subject, claims.Scope, string(tctxJSON))

		var req struct {
			Company   string   `json:"company"`
			Period    string   `json:"period"`
			Question  string   `json:"question"`
			Documents []string `json:"documents"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		// Return mock analysis
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"analysis": fmt.Sprintf(
				"Based on %d documents for %s (%s): Revenue grew 15%% YoY driven by cloud expansion. "+
					"Operating margins improved to 22%%. Management guidance suggests continued momentum "+
					"into next quarter with expected 12-15%% growth.",
				len(req.Documents), req.Company, req.Period),
		})
	})))

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("analyzer listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
