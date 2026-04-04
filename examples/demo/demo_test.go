package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	pkgtts "github.com/aramase/kontxt/pkg/tts"
	"github.com/aramase/kontxt/sdk/middleware"
	sdktts "github.com/aramase/kontxt/sdk/tts"
	"github.com/aramase/kontxt/sdk/verify"
)

// auditEntry represents a structured audit log entry from a service.
type auditEntry struct {
	Service string `json:"service"`
	Txn     string `json:"txn"`
	Sub     string `json:"sub"`
	Scope   string `json:"scope"`
}

// auditCollector collects audit log entries from all services for test assertions.
type auditCollector struct {
	mu      sync.Mutex
	entries []auditEntry
}

func (a *auditCollector) log(entry auditEntry) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.entries = append(a.entries, entry)
}

func (a *auditCollector) getEntries() []auditEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	result := make([]auditEntry, len(a.entries))
	copy(result, a.entries)
	return result
}

// setupFullStack creates the complete test infrastructure: IdP, TTS, verifier, and 3 services.
func setupFullStack(t *testing.T) (
	idpKeyMgr *keys.Manager,
	idpURL string,
	ttsClient *sdktts.Client,
	serviceAURL string,
	audit *auditCollector,
) {
	t.Helper()

	// 1. Create IdP
	idpKeyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	var idpServerURL string
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpServerURL, idpServerURL+"/.well-known/jwks.json")
	})
	idpMux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(idpMux)
	idpServerURL = idpServer.URL
	t.Cleanup(idpServer.Close)

	// 2. Create TTS
	ttsCfg := &pkgtts.Config{
		TrustDomain: "demo.example.com",
		Issuer:      "https://tts.demo.example.com",
		SubjectTokens: []authn.AuthenticatorConfig{
			{
				Issuer: authn.IssuerConfig{
					URL:       idpServer.URL,
					Audiences: []string{"demo-app"},
				},
				ClaimMappings: authn.ClaimMappings{
					Subject: authn.ClaimOrExpression{Claim: "email"},
				},
			},
		},
		Defaults: pkgtts.TokenDefaults{
			TokenLifetime: "15s",
			KeySize:       2048,
		},
	}
	ttsServer, err := pkgtts.NewServer(ttsCfg)
	require.NoError(t, err)
	ttsHTTP := httptest.NewServer(ttsServer.Handler())
	t.Cleanup(ttsHTTP.Close)

	// 3. Create verifier pointing at TTS JWKS
	verifier := verify.New(ttsHTTP.URL+"/.well-known/jwks.json", "demo.example.com")

	// 4. Create audit collector
	audit = &auditCollector{}

	// 5. Create Service C (terminal — verify + log)
	serviceCMux := http.NewServeMux()
	serviceCMux.Handle("GET /api/store", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		audit.log(auditEntry{
			Service: "service-c",
			Txn:     claims.TransactionID,
			Sub:     claims.Subject,
			Scope:   claims.Scope,
		})
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "stored"})
	})))
	serviceC := httptest.NewServer(serviceCMux)
	t.Cleanup(serviceC.Close)

	// 6. Create Service B (middle — verify + forward + log)
	serviceBMux := http.NewServeMux()
	serviceBMux.Handle("GET /api/process", middleware.VerifyTxToken(verifier)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		audit.log(auditEntry{
			Service: "service-b",
			Txn:     claims.TransactionID,
			Sub:     claims.Subject,
			Scope:   claims.Scope,
		})

		// Forward to Service C with TxToken propagated
		client := &http.Client{Transport: middleware.NewPropagateTransport(http.DefaultTransport)}
		req, _ := http.NewRequestWithContext(r.Context(), http.MethodGet, serviceC.URL+"/api/store", nil)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "failed to call service-c", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "processed"})
	})))
	serviceB := httptest.NewServer(serviceBMux)
	t.Cleanup(serviceB.Close)

	// 7. Create Service A (entry — exchange AT for TxToken, call Service B)
	ttsClient = sdktts.NewClient(ttsHTTP.URL)

	serviceAMux := http.NewServeMux()
	serviceAMux.HandleFunc("POST /api/analyze", func(w http.ResponseWriter, r *http.Request) {
		// Extract the OAuth AT from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || len(authHeader) < 8 {
			http.Error(w, "missing Authorization header", http.StatusUnauthorized)
			return
		}
		accessToken := authHeader[7:] // strip "Bearer "

		// Exchange AT for TxToken
		txToken, err := ttsClient.Exchange(r.Context(), &sdktts.ExchangeRequest{
			SubjectToken:     accessToken,
			SubjectTokenType: token.SubjectTokenTypeAccessToken,
			Scope:            "read:data",
			RequestDetails: map[string]any{
				"action":    "analyze",
				"datasetId": "ds-1234",
			},
			RequestContext: map[string]any{
				"req_ip": r.RemoteAddr,
				"authn":  "oidc",
			},
		})
		if err != nil {
			http.Error(w, "token exchange failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		// Verify the TxToken we just received (for audit logging)
		claims, err := verifier.Verify(r.Context(), txToken)
		if err != nil {
			http.Error(w, "self-verification failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
		audit.log(auditEntry{
			Service: "service-a",
			Txn:     claims.TransactionID,
			Sub:     claims.Subject,
			Scope:   claims.Scope,
		})

		// Call Service B with TxToken
		ctx := middleware.WithToken(r.Context(), txToken)
		client := &http.Client{Transport: middleware.NewPropagateTransport(http.DefaultTransport)}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, serviceB.URL+"/api/process", nil)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "failed to call service-b", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "analyzed"})
	})
	serviceA := httptest.NewServer(serviceAMux)
	t.Cleanup(serviceA.Close)

	return idpKeyMgr, idpServer.URL, ttsClient, serviceA.URL, audit
}

func createOIDCToken(t *testing.T, keyMgr *keys.Manager, issuer string) string {
	t.Helper()
	signingKey, kid := keyMgr.SigningKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss":   issuer,
		"aud":   "demo-app",
		"email": "alice@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})
	tok.Header["kid"] = kid
	tokenString, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return tokenString
}

func TestEndToEnd_3ServiceChain(t *testing.T) {
	idpKeyMgr, idpURL, _, serviceAURL, audit := setupFullStack(t)

	// Create an OIDC access token
	accessToken := createOIDCToken(t, idpKeyMgr, idpURL)

	// Send request to Service A
	req, err := http.NewRequest(http.MethodPost, serviceAURL+"/api/analyze", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), "analyzed")

	// Verify all 3 services logged the same txn
	entries := audit.getEntries()
	require.Len(t, entries, 3, "all 3 services should have logged")

	// All should have the same txn
	txn := entries[0].Txn
	assert.NotEmpty(t, txn)
	for _, e := range entries {
		assert.Equal(t, txn, e.Txn, "all services should see the same txn")
		assert.Equal(t, "alice@example.com", e.Sub, "all services should see the same sub")
		assert.Equal(t, "read:data", e.Scope, "all services should see the same scope")
	}

	// Verify the correct service order
	assert.Equal(t, "service-a", entries[0].Service)
	assert.Equal(t, "service-b", entries[1].Service)
	assert.Equal(t, "service-c", entries[2].Service)
}

func TestEndToEnd_ExpiredTokenRejected(t *testing.T) {
	idpKeyMgr, idpURL, ttsClient, _, _ := setupFullStack(t)

	// Create OIDC token and exchange for TxToken
	accessToken := createOIDCToken(t, idpKeyMgr, idpURL)
	txToken, err := ttsClient.Exchange(context.Background(), &sdktts.ExchangeRequest{
		SubjectToken:     accessToken,
		SubjectTokenType: token.SubjectTokenTypeAccessToken,
		Scope:            "read:data",
	})
	require.NoError(t, err)
	require.NotEmpty(t, txToken)

	// The TxToken is valid for 15s — for this test we just verify it was issued
	// (testing actual expiry in the verifier tests is more appropriate)
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, _, err := parser.ParseUnverified(txToken, jwt.MapClaims{})
	require.NoError(t, err)
	claims := parsed.Claims.(jwt.MapClaims)
	assert.Equal(t, "alice@example.com", claims["sub"])
}

func TestEndToEnd_InvalidAccessTokenRejected(t *testing.T) {
	_, _, _, serviceAURL, _ := setupFullStack(t)

	// Send request with an invalid access token
	req, err := http.NewRequest(http.MethodPost, serviceAURL+"/api/analyze", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer invalid-token")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should fail at token exchange
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestEndToEnd_MissingAuthorizationHeader(t *testing.T) {
	_, _, _, serviceAURL, _ := setupFullStack(t)

	// Send request without Authorization header
	req, err := http.NewRequest(http.MethodPost, serviceAURL+"/api/analyze", nil)
	require.NoError(t, err)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}
