// mock-idp is a lightweight OIDC-compatible identity provider for demo use.
// It issues signed JWT access tokens and serves OIDC discovery + JWKS endpoints.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/aramase/kontxt/pkg/keys"
)

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	issuer := flag.String("issuer", "http://mock-idp.demo.svc.cluster.local:8080", "issuer URL (must match external URL)")
	flag.Parse()

	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	if err != nil {
		log.Fatalf("failed to create key manager: %v", err)
	}

	mux := http.NewServeMux()

	// OIDC Discovery
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"issuer":   *issuer,
			"jwks_uri": *issuer + "/.well-known/jwks.json",
		})
	})

	// JWKS endpoint
	mux.Handle("GET /.well-known/jwks.json", keyMgr.JWKSHandler())

	// Token endpoint - issues access tokens
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Email string `json:"email"`
			Scope string `json:"scope"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.Email == "" {
			http.Error(w, "email is required", http.StatusBadRequest)
			return
		}
		if req.Scope == "" {
			req.Scope = "read:docs analyze:data"
		}

		now := time.Now()
		claims := jwt.MapClaims{
			"iss":   *issuer,
			"sub":   req.Email,
			"email": req.Email,
			"aud":   "demo-app",
			"scope": req.Scope,
			"iat":   now.Unix(),
			"exp":   now.Add(1 * time.Hour).Unix(),
		}

		key, kid := keyMgr.SigningKey()
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		signed, err := tok.SignedString(key)
		if err != nil {
			http.Error(w, "failed to sign token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"access_token": signed,
			"token_type":   "Bearer",
		})
	})

	// Health check
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	fmt.Printf("mock-idp listening on %s (issuer=%s)\n", *addr, *issuer)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
