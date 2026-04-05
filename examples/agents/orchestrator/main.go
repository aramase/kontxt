// orchestrator is the entry-point agent service in the AI Research Assistant demo.
// It receives requests with an OAuth access token (which AgentGateway's ext_authz
// adapter exchanges for a TxToken). It then calls the retriever and analyzer
// services, propagating the TxToken via the SDK middleware.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/aramase/kontxt/sdk/middleware"
)

type researchRequest struct {
	Company  string `json:"company"`
	Period   string `json:"period"`
	Question string `json:"question"`
}

type researchResponse struct {
	Company   string   `json:"company"`
	Period    string   `json:"period"`
	Question  string   `json:"question"`
	Documents []string `json:"documents"`
	Analysis  string   `json:"analysis"`
}

func main() {
	addr := flag.String("addr", ":8081", "listen address")
	retrieverURL := flag.String("retriever", "http://retriever.demo.svc.cluster.local:8082", "retriever service URL")
	analyzerURL := flag.String("analyzer", "http://analyzer.demo.svc.cluster.local:8083", "analyzer service URL")
	flag.Parse()

	client := &http.Client{Transport: middleware.NewPropagateTransport(http.DefaultTransport)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/research", func(w http.ResponseWriter, r *http.Request) {
		// The TxToken was injected by the ext_authz generate adapter.
		// The SDK propagate transport will forward it automatically.
		txToken := r.Header.Get("Txn-Token")
		if txToken != "" {
			// Store in context so PropagateTransport can forward it
			r = r.WithContext(middleware.WithToken(r.Context(), txToken))
		}

		var req researchRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}

		log.Printf("[orchestrator] research request: company=%s period=%s", req.Company, req.Period)

		// Call retriever
		retrieverReq, _ := http.NewRequestWithContext(r.Context(), http.MethodGet,
			*retrieverURL+"/api/retrieve?company="+req.Company, nil)
		retrieverResp, err := client.Do(retrieverReq)
		if err != nil {
			log.Printf("[orchestrator] retriever call failed: %v", err)
			http.Error(w, "retriever call failed", http.StatusBadGateway)
			return
		}
		defer retrieverResp.Body.Close()
		if retrieverResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(retrieverResp.Body)
			log.Printf("[orchestrator] retriever returned %d: %s", retrieverResp.StatusCode, string(body))
			http.Error(w, "retriever error: "+string(body), retrieverResp.StatusCode)
			return
		}
		var docs struct {
			Documents []string `json:"documents"`
		}
		json.NewDecoder(retrieverResp.Body).Decode(&docs)

		// Call analyzer
		analyzerBody, _ := json.Marshal(map[string]any{
			"company":   req.Company,
			"period":    req.Period,
			"question":  req.Question,
			"documents": docs.Documents,
		})
		analyzerReq, _ := http.NewRequestWithContext(r.Context(), http.MethodPost,
			*analyzerURL+"/api/analyze", strings.NewReader(string(analyzerBody)))
		analyzerReq.Header.Set("Content-Type", "application/json")
		analyzerResp, err := client.Do(analyzerReq)
		if err != nil {
			log.Printf("[orchestrator] analyzer call failed: %v", err)
			http.Error(w, "analyzer call failed", http.StatusBadGateway)
			return
		}
		defer analyzerResp.Body.Close()
		if analyzerResp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(analyzerResp.Body)
			log.Printf("[orchestrator] analyzer returned %d: %s", analyzerResp.StatusCode, string(body))
			http.Error(w, "analyzer error: "+string(body), analyzerResp.StatusCode)
			return
		}
		var analysis struct {
			Analysis string `json:"analysis"`
		}
		json.NewDecoder(analyzerResp.Body).Decode(&analysis)

		// Return combined result
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(researchResponse{
			Company:   req.Company,
			Period:    req.Period,
			Question:  req.Question,
			Documents: docs.Documents,
			Analysis:  analysis.Analysis,
		})
	})

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("orchestrator listening on %s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
