package authn

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
)

func TestRouter_RoutesToCorrectAuthenticator(t *testing.T) {
	keyMgr1, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)
	keyMgr2, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server1 := testOIDCServer(t, keyMgr1)
	server2 := testOIDCServer(t, keyMgr2)

	auth1, err := NewOIDCAuthenticator(AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server1.URL,
			Audiences: []string{"app-1"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "email"},
		},
	})
	require.NoError(t, err)
	auth1.SetJWKSURL(server1.URL + "/.well-known/jwks.json")

	auth2, err := NewOIDCAuthenticator(AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server2.URL,
			Audiences: []string{"app-2"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	})
	require.NoError(t, err)
	auth2.SetJWKSURL(server2.URL + "/.well-known/jwks.json")

	router := NewRouter([]Authenticator{auth1, auth2})

	// Token from issuer 1 → auth1 (maps email to subject)
	key1, kid1 := keyMgr1.SigningKey()
	token1 := signTestToken(t, key1, kid1, jwt.MapClaims{
		"iss":   server1.URL,
		"aud":   "app-1",
		"email": "alice@example.com",
		"sub":   "alice-sub",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	info1, err := router.Authenticate(context.Background(), token1)
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", info1.Subject) // mapped via email claim

	// Token from issuer 2 → auth2 (maps sub to subject)
	key2, kid2 := keyMgr2.SigningKey()
	token2 := signTestToken(t, key2, kid2, jwt.MapClaims{
		"iss":   server2.URL,
		"aud":   "app-2",
		"email": "bob@example.com",
		"sub":   "bob-sub",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	info2, err := router.Authenticate(context.Background(), token2)
	require.NoError(t, err)
	assert.Equal(t, "bob-sub", info2.Subject) // mapped via sub claim
}

func TestRouter_UnknownIssuer(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	auth, err := NewOIDCAuthenticator(AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	})
	require.NoError(t, err)

	router := NewRouter([]Authenticator{auth})

	// Token with a different issuer
	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss": "https://unknown-issuer.com",
		"aud": "my-app",
		"sub": "user123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err = router.Authenticate(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no authenticator found")
}

func TestRouter_InvalidToken(t *testing.T) {
	router := NewRouter(nil)

	_, err := router.Authenticate(context.Background(), "not-a-jwt")
	assert.Error(t, err)
}

func TestRouter_EmptyToken(t *testing.T) {
	router := NewRouter(nil)

	_, err := router.Authenticate(context.Background(), "")
	assert.Error(t, err)
}

func TestRouter_OIDCDiscovery(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	// Create a proper OIDC discovery server
	mux := http.NewServeMux()
	mux.Handle("/.well-known/jwks.json", keyMgr.JWKSHandler())
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	// Register discovery after we know the server URL
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"issuer":"` + server.URL + `","jwks_uri":"` + server.URL + `/.well-known/jwks.json"}`))
	})

	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)
	// Don't call SetJWKSURL — let it discover via OIDC

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"aud": "my-app",
		"sub": "user-via-discovery",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	router := NewRouter([]Authenticator{auth})
	info, err := router.Authenticate(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user-via-discovery", info.Subject)
}

func TestExtractIssuer(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		want    string
		wantErr bool
	}{
		{
			name:    "invalid JWT format",
			token:   "not.a.valid.jwt.too.many.parts",
			wantErr: true,
		},
		{
			name:    "empty string",
			token:   "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractIssuer(tt.token)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}
