package tts

import (
	"fmt"
	"net/http"

	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
)

// Server is the Transaction Token Service HTTP server.
type Server struct {
	handler    *Handler
	keyManager *keys.Manager
	mux        *http.ServeMux

	// readyFn returns nil when the server has finished any optional bootstrap
	// (e.g. an initial issuance-rules snapshot from the controller). When nil,
	// /readyz reports ready immediately.
	readyFn func() error
}

// NewServer creates a new TTS server from configuration.
func NewServer(cfg *Config) (*Server, error) {
	// Initialize key manager
	keyMgr, err := keys.NewManager(cfg.DefaultKeySize(), cfg.DefaultTokenLifetime())
	if err != nil {
		return nil, fmt.Errorf("creating key manager: %w", err)
	}

	// Build authenticators from config
	authenticators := make([]authn.Authenticator, 0, len(cfg.SubjectTokens))
	for i, authCfg := range cfg.SubjectTokens {
		auth, err := authn.NewOIDCAuthenticator(authCfg)
		if err != nil {
			return nil, fmt.Errorf("creating authenticator %d (%s): %w", i, authCfg.Issuer.URL, err)
		}
		authenticators = append(authenticators, auth)
	}

	router := authn.NewRouter(authenticators)
	handler := NewHandler(router, keyMgr, cfg.Issuer, cfg.TrustDomain, cfg.DefaultTokenLifetime())

	// Wire an in-process self-verifier so token replacement
	// (subject_token_type=txn_token) works without the TTS having to reach
	// itself over HTTP. cfg.Issuer is the `iss` claim identifier (often an
	// https URL) and the TTS Service is plain HTTP, so a network-based
	// verifier would fail TLS or DNS depending on the deployment.
	handler.SetVerifier(newLocalVerifier(keyMgr, cfg.TrustDomain))

	mux := http.NewServeMux()
	mux.Handle("POST /token_endpoint", handler)
	mux.Handle("GET /.well-known/jwks.json", keyMgr.JWKSHandler())
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	srv := &Server{
		handler:    handler,
		keyManager: keyMgr,
		mux:        mux,
	}
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if srv.readyFn != nil {
			if err := srv.readyFn(); err != nil {
				http.Error(w, err.Error(), http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ready"))
	})

	return srv, nil
}

// Handler returns the HTTP handler for the TTS server.
func (s *Server) Handler() http.Handler {
	return s.mux
}

// KeyManager returns the key manager (for testing).
func (s *Server) KeyManager() *keys.Manager {
	return s.keyManager
}

// TokenHandler returns the token-exchange Handler so external wiring can call
// SetIssuanceRules / SetVerifier on it.
func (s *Server) TokenHandler() *Handler {
	return s.handler
}

// SetReadyCheck installs a readiness function. /readyz returns 503 with the
// returned error's message until it returns nil. Passing nil clears the check.
func (s *Server) SetReadyCheck(fn func() error) {
	s.readyFn = fn
}
