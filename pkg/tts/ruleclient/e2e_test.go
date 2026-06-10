package ruleclient_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	rulesv1 "github.com/aramase/kontxt/gen/kontxt/rules/v1"
	"github.com/aramase/kontxt/internal/controller"
	"github.com/aramase/kontxt/internal/controller/ruleserver"
	"github.com/aramase/kontxt/pkg/authn"
	"github.com/aramase/kontxt/pkg/keys"
	"github.com/aramase/kontxt/pkg/token"
	"github.com/aramase/kontxt/pkg/tts"
	"github.com/aramase/kontxt/pkg/tts/ruleclient"
)

// TestE2E_IssuanceRuleDeniesExchange wires a real gRPC ruleserver to a real
// TTS Server through the production ruleclient and asserts that a denying CEL
// rule causes the next token exchange to be rejected with 403 policy_denied.
// This is the data-path validation for M1: TokenPolicy issuance rules reach
// the TTS handler and gate issuance.
func TestE2E_IssuanceRuleDeniesExchange(t *testing.T) {
	// 1. Controller-side gRPC server with a single deny-all issuance rule.
	rs := ruleserver.NewRuleServer()
	rs.UpdateIssuanceRules([]controller.IssuanceRule{
		{
			PolicyName: "default",
			RuleName:   "deny-all",
			CEL:        "false",
			Message:    "issuance denied for tests",
		},
	})

	grpcLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	gs := grpc.NewServer()
	rulesv1.RegisterRuleDiscoveryServiceServer(gs, rs)
	go gs.Serve(grpcLis)
	t.Cleanup(gs.Stop)

	// 2. IdP issuing subject tokens.
	idpKeyMgr, err := keys.NewManager(2048, time.Hour)
	require.NoError(t, err)

	var idpURL string
	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, idpURL, idpURL+"/.well-known/jwks.json")
	})
	idpMux.Handle("/.well-known/jwks.json", idpKeyMgr.JWKSHandler())
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()
	idpURL = idpServer.URL

	// 3. TTS server.
	ttsLis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	ttsURL := "http://" + ttsLis.Addr().String()

	srv, err := tts.NewServer(&tts.Config{
		TrustDomain: "trust-domain.example.com",
		Issuer:      ttsURL,
		SubjectTokens: []authn.AuthenticatorConfig{{
			Issuer: authn.IssuerConfig{
				URL:       idpServer.URL,
				Audiences: []string{"test-app"},
			},
			ClaimMappings: authn.ClaimMappings{
				Subject: authn.ClaimOrExpression{Claim: "email"},
			},
		}},
	})
	require.NoError(t, err)

	// 4. Production ruleclient feeding the server's handler.
	rc := ruleclient.NewRuleClient(grpcLis.Addr().String(),
		ruleclient.NewHandlerSetter(srv.TokenHandler()),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go rc.Run(ctx)

	hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: time.Second}
	go hs.Serve(ttsLis)
	t.Cleanup(func() {
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer shutdownCancel()
		_ = hs.Shutdown(shutdownCtx)
	})

	// 5. Wait for the ruleclient to apply the initial snapshot.
	require.Eventually(t, rc.Ready, 3*time.Second, 25*time.Millisecond,
		"ruleclient never became ready")

	// 6. Issue an IdP-signed subject token and attempt exchange.
	subjectToken := signSubjectToken(t, idpKeyMgr, idpServer.URL, jwt.MapClaims{
		"iss":   idpServer.URL,
		"aud":   "test-app",
		"email": "user@example.com",
		"exp":   time.Now().Add(5 * time.Minute).Unix(),
		"iat":   time.Now().Unix(),
	})

	resp, body := postExchange(t, ttsURL, url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {subjectToken},
		"subject_token_type":   {token.SubjectTokenTypeAccessToken},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {"read:data"},
	})

	assert.Equalf(t, http.StatusForbidden, resp.StatusCode,
		"exchange should be denied by issuance rule; body: %s", string(body))

	var er tts.ErrorResponse
	require.NoError(t, json.Unmarshal(body, &er))
	assert.Equal(t, "policy_denied", er.Error)
	assert.Contains(t, er.ErrorDescription, "issuance denied for tests")
}

func signSubjectToken(t *testing.T, km *keys.Manager, _ string, claims jwt.MapClaims) string {
	t.Helper()
	signingKey, kid := km.SigningKey()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(signingKey)
	require.NoError(t, err)
	return signed
}

var httpTestClient = &http.Client{Timeout: 5 * time.Second}

func postExchange(t *testing.T, ttsURL string, params url.Values) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ttsURL+"/token_endpoint",
		strings.NewReader(params.Encode()))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpTestClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "reading exchange response body")
	return resp, body
}
