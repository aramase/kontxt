package authn

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aramase/kontxt/pkg/keys"
)

// testOIDCServer sets up a test OIDC provider with discovery + JWKS endpoints.
func testOIDCServer(t *testing.T, keyMgr *keys.Manager) *httptest.Server {
	t.Helper()

	// Use a variable to hold the server URL, set after server starts
	var serverURL string

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, serverURL, serverURL+"/.well-known/jwks.json")
	})
	mux.Handle("/.well-known/jwks.json", keyMgr.JWKSHandler())

	server := httptest.NewServer(mux)
	serverURL = server.URL

	t.Cleanup(server.Close)
	return server
}

// signTestToken creates a signed JWT for testing.
func signTestToken(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	tokenString, err := token.SignedString(key)
	require.NoError(t, err)
	return tokenString
}

func TestOIDCAuthenticator_ValidToken(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "email"},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)

	// Bypass OIDC discovery by setting JWKS URL directly
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss":   server.URL,
		"aud":   "my-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	info, err := auth.Authenticate(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", info.Subject)
}

func TestOIDCAuthenticator_WrongAudience(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
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
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"aud": "wrong-app",
		"sub": "user123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err = auth.Authenticate(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "audience")
}

func TestOIDCAuthenticator_CELValidationRule_Pass(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimValidationRules: []ClaimValidationRule{
			{Expression: `claims.tenant == "acme"`, Message: "wrong tenant"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss":    server.URL,
		"aud":    "my-app",
		"sub":    "user123",
		"tenant": "acme",
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
	})

	info, err := auth.Authenticate(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user123", info.Subject)
}

func TestOIDCAuthenticator_CELValidationRule_Fail(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimValidationRules: []ClaimValidationRule{
			{Expression: `claims.tenant == "acme"`, Message: "wrong tenant"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss":    server.URL,
		"aud":    "my-app",
		"sub":    "user123",
		"tenant": "evil-corp",
		"exp":    time.Now().Add(5 * time.Minute).Unix(),
		"iat":    time.Now().Unix(),
	})

	_, err = auth.Authenticate(context.Background(), tokenString)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "wrong tenant")
}

func TestOIDCAuthenticator_CELSubjectExpression(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Expression: `claims.oid`},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"aud": "my-app",
		"oid": "guid-12345",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	info, err := auth.Authenticate(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "guid-12345", info.Subject)
}

func TestOIDCAuthenticator_ExtraMappings(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	signingKey, kid := keyMgr.SigningKey()

	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       server.URL,
			Audiences: []string{"my-app"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
			Extra: []ExtraMapping{
				{Key: "tenant", ValueExpression: `claims.tid`},
				{Key: "name", ValueExpression: `claims.name`},
			},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss":  server.URL,
		"aud":  "my-app",
		"sub":  "user123",
		"tid":  "tenant-abc",
		"name": "Jane Doe",
		"exp":  time.Now().Add(5 * time.Minute).Unix(),
		"iat":  time.Now().Unix(),
	})

	info, err := auth.Authenticate(context.Background(), tokenString)
	require.NoError(t, err)
	assert.Equal(t, "user123", info.Subject)
	assert.Equal(t, "tenant-abc", info.Extra["tenant"])
	assert.Equal(t, "Jane Doe", info.Extra["name"])
}

func TestOIDCAuthenticator_WrongSigningKey(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
	_, kid := keyMgr.SigningKey()

	// Sign with a different key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

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
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, wrongKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"aud": "my-app",
		"sub": "user123",
		"exp": time.Now().Add(5 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
	})

	_, err = auth.Authenticate(context.Background(), tokenString)
	assert.Error(t, err)
}

func TestOIDCAuthenticator_ExpiredToken(t *testing.T) {
	keyMgr, err := keys.NewManager(2048, 24*time.Hour)
	require.NoError(t, err)

	server := testOIDCServer(t, keyMgr)
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
	auth.SetJWKSURL(server.URL + "/.well-known/jwks.json")

	tokenString := signTestToken(t, signingKey, kid, jwt.MapClaims{
		"iss": server.URL,
		"aud": "my-app",
		"sub": "user123",
		"exp": time.Now().Add(-5 * time.Minute).Unix(), // expired
		"iat": time.Now().Add(-10 * time.Minute).Unix(),
	})

	_, err = auth.Authenticate(context.Background(), tokenString)
	assert.Error(t, err)
}

func TestOIDCAuthenticator_Matches(t *testing.T) {
	config := AuthenticatorConfig{
		Issuer: IssuerConfig{
			URL:       "https://login.microsoftonline.com/tenant-id/v2.0",
			Audiences: []string{"app-id"},
		},
		ClaimMappings: ClaimMappings{
			Subject: ClaimOrExpression{Claim: "sub"},
		},
	}

	auth, err := NewOIDCAuthenticator(config)
	require.NoError(t, err)

	assert.True(t, auth.Matches("https://login.microsoftonline.com/tenant-id/v2.0"))
	assert.False(t, auth.Matches("https://accounts.google.com"))
	assert.False(t, auth.Matches(""))
}
