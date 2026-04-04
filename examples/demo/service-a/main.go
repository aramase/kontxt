// Service A is the entry-point service in the demo.
// It receives requests with an OAuth access token, exchanges it for a TxToken
// via the TTS, and calls Service B with the TxToken propagated.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"

	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/sdk/middleware"
	sdktts "github.com/aramase/kontxt/sdk/tts"
)

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	ttsEndpoint := flag.String("tts", "http://localhost:8080", "TTS endpoint")
	serviceBURL := flag.String("service-b", "http://localhost:8082", "Service B URL")
	flag.Parse()

	ttsClient := sdktts.NewClient(*ttsEndpoint)

	http.HandleFunc("POST /api/analyze", func(w http.ResponseWriter, r *http.Request) {
		// Extract OAuth AT
		auth := r.Header.Get("Authorization")
		if len(auth) < 8 {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := auth[7:]

		// Exchange AT for TxToken
		txToken, err := ttsClient.Exchange(r.Context(), &sdktts.ExchangeRequest{
			SubjectToken:     accessToken,
			SubjectTokenType: token.SubjectTokenTypeAccessToken,
			Scope:            "read:data",
			RequestDetails:   map[string]any{"action": "analyze", "datasetId": "ds-1234"},
			RequestContext:   map[string]any{"req_ip": r.RemoteAddr, "authn": "oidc"},
		})
		if err != nil {
			log.Printf("[service-a] token exchange failed: %v", err)
			http.Error(w, "token exchange failed", http.StatusInternalServerError)
			return
		}

		log.Printf("[service-a] TxToken obtained, calling service-b")

		// Call Service B with TxToken
		ctx := middleware.WithToken(r.Context(), txToken)
		client := &http.Client{Transport: middleware.NewPropagateTransport(http.DefaultTransport)}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, *serviceBURL+"/api/process", nil)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "failed to call service-b", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "analyzed"})
	})

	fmt.Printf("Service A listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
