package tts

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
)

// Handler processes RFC 8693 token exchange requests and issues TxTokens.
type Handler struct {
	router      *authn.Router
	keyManager  *keys.Manager
	issuer      string
	trustDomain string
	lifetime    time.Duration
}

// NewHandler creates a new token exchange handler.
func NewHandler(router *authn.Router, keyManager *keys.Manager, issuer, trustDomain string, lifetime time.Duration) *Handler {
	return &Handler{
		router:      router,
		keyManager:  keyManager,
		issuer:      issuer,
		trustDomain: trustDomain,
		lifetime:    lifetime,
	}
}

// TokenExchangeRequest represents the parsed RFC 8693 token exchange parameters.
type TokenExchangeRequest struct {
	GrantType          string
	SubjectToken       string
	SubjectTokenType   string
	RequestedTokenType string
	Audience           string
	Scope              string
	RequestDetails     map[string]any // becomes tctx
	RequestContext     map[string]any // becomes rctx
}

// TokenExchangeResponse is the RFC 8693 token exchange response.
type TokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
}

// ErrorResponse is the OAuth 2.0 error response.
type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

// ServeHTTP handles the token exchange endpoint.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "method not allowed")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "failed to parse form")
		return
	}

	req, err := h.parseRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}

	// Validate the subject token via the authenticator router
	subjectInfo, err := h.router.Authenticate(r.Context(), req.SubjectToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid_token", err.Error())
		return
	}

	// Build the TxToken claims
	claims := token.Claims{
		Issuer:             h.issuer,
		Audience:           h.trustDomain,
		Subject:            subjectInfo.Subject,
		Scope:              req.Scope,
		RequestingWorkload: identifyWorkload(r),
		TransactionContext: req.RequestDetails,
		RequesterContext:   req.RequestContext,
	}

	// Sign the TxToken
	signingKey, kid := h.keyManager.SigningKey()
	txToken, err := token.New(claims, signingKey, kid, h.lifetime)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "server_error", "failed to create transaction token")
		return
	}

	// Return the RFC 8693 token exchange response
	resp := TokenExchangeResponse{
		AccessToken:     txToken,
		IssuedTokenType: token.RequestedTokenType,
		TokenType:       "N_A",
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// parseRequest extracts and validates the RFC 8693 token exchange parameters.
func (h *Handler) parseRequest(r *http.Request) (*TokenExchangeRequest, error) {
	grantType := r.FormValue("grant_type")
	if grantType != token.GrantType {
		return nil, fmt.Errorf("unsupported grant_type: %s", grantType)
	}

	subjectToken := r.FormValue("subject_token")
	if subjectToken == "" {
		return nil, fmt.Errorf("subject_token is required")
	}

	subjectTokenType := r.FormValue("subject_token_type")
	if subjectTokenType == "" {
		return nil, fmt.Errorf("subject_token_type is required")
	}

	requestedTokenType := r.FormValue("requested_token_type")
	if requestedTokenType != token.RequestedTokenType {
		return nil, fmt.Errorf("unsupported requested_token_type: %s", requestedTokenType)
	}

	scope := r.FormValue("scope")
	if scope == "" {
		return nil, fmt.Errorf("scope is required")
	}

	req := &TokenExchangeRequest{
		GrantType:          grantType,
		SubjectToken:       subjectToken,
		SubjectTokenType:   subjectTokenType,
		RequestedTokenType: requestedTokenType,
		Audience:           r.FormValue("audience"),
		Scope:              scope,
	}

	// Parse optional request_details → tctx
	if rd := r.FormValue("request_details"); rd != "" {
		var details map[string]any
		if err := json.Unmarshal([]byte(rd), &details); err != nil {
			return nil, fmt.Errorf("invalid request_details JSON: %w", err)
		}
		req.RequestDetails = details
	}

	// Parse optional request_context → rctx
	if rc := r.FormValue("request_context"); rc != "" {
		var ctx map[string]any
		if err := json.Unmarshal([]byte(rc), &ctx); err != nil {
			return nil, fmt.Errorf("invalid request_context JSON: %w", err)
		}
		req.RequestContext = ctx
	}

	return req, nil
}

// identifyWorkload extracts the requesting workload's identity.
// For now, uses a header-based approach. In production, this would use
// the WorkloadAuthenticator interface (SA token validation, SPIFFE, etc.).
func identifyWorkload(r *http.Request) string {
	// Check for an explicit workload identity header (used by ext auth adapter)
	if wl := r.Header.Get("X-Kontxt-Workload"); wl != "" {
		return wl
	}

	// Fall back to extracting from Authorization header (SA token subject)
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		// In a full implementation, we'd validate the SA token and extract the subject.
		// For the POC, we use the presence of the header as a placeholder.
		return "authenticated-workload"
	}

	return "unknown"
}

// writeError writes an OAuth 2.0 error response.
func writeError(w http.ResponseWriter, status int, errCode, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            errCode,
		ErrorDescription: description,
	})
}
