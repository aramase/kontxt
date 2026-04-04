// Package tts provides a client SDK for the Transaction Token Service.
// It handles constructing RFC 8693 token exchange requests and parsing responses.
package tts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aramase/kontxt/pkg/token"
)

// Client is an SDK client for the Transaction Token Service.
type Client struct {
	endpoint string
	client   *http.Client
}

// NewClient creates a new TTS client.
// endpoint is the base URL of the TTS (e.g., "https://tts.example.com").
func NewClient(endpoint string) *Client {
	return &Client{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

// ExchangeRequest contains the parameters for a token exchange.
type ExchangeRequest struct {
	// SubjectToken is the token to exchange (OIDC access token, ID token, or TxToken for replacement).
	SubjectToken string
	// SubjectTokenType is the type of the subject token (e.g., token.SubjectTokenTypeAccessToken).
	SubjectTokenType string
	// Scope is the requested scope for the TxToken (space-delimited).
	Scope string
	// RequestDetails becomes the tctx claim in the TxToken (optional).
	RequestDetails map[string]any
	// RequestContext becomes the rctx claim in the TxToken (optional).
	RequestContext map[string]any
}

// exchangeResponse is the RFC 8693 token exchange response.
type exchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	Error           string `json:"error"`
	ErrorDesc       string `json:"error_description"`
}

// Exchange performs an RFC 8693 token exchange with the TTS.
// Returns the TxToken JWT string on success.
func (c *Client) Exchange(ctx context.Context, req *ExchangeRequest) (string, error) {
	if req.SubjectToken == "" {
		return "", fmt.Errorf("subject_token is required")
	}
	if req.Scope == "" {
		return "", fmt.Errorf("scope is required")
	}
	if req.SubjectTokenType == "" {
		req.SubjectTokenType = token.SubjectTokenTypeAccessToken
	}

	// Build form parameters
	form := url.Values{
		"grant_type":           {token.GrantType},
		"subject_token":        {req.SubjectToken},
		"subject_token_type":   {req.SubjectTokenType},
		"requested_token_type": {token.RequestedTokenType},
		"scope":                {req.Scope},
	}

	if req.RequestDetails != nil {
		details, err := json.Marshal(req.RequestDetails)
		if err != nil {
			return "", fmt.Errorf("marshaling request_details: %w", err)
		}
		form.Set("request_details", string(details))
	}

	if req.RequestContext != nil {
		rctx, err := json.Marshal(req.RequestContext)
		if err != nil {
			return "", fmt.Errorf("marshaling request_context: %w", err)
		}
		form.Set("request_context", string(rctx))
	}

	// Send the request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/token_endpoint", strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("sending token exchange request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errResp exchangeResponse
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return "", fmt.Errorf("token exchange failed (HTTP %d): %s: %s", resp.StatusCode, errResp.Error, errResp.ErrorDesc)
		}
		return "", fmt.Errorf("token exchange failed (HTTP %d): %s", resp.StatusCode, string(body))
	}

	var exchResp exchangeResponse
	if err := json.Unmarshal(body, &exchResp); err != nil {
		return "", fmt.Errorf("decoding token exchange response: %w", err)
	}

	if exchResp.AccessToken == "" {
		return "", fmt.Errorf("token exchange response has no access_token")
	}

	return exchResp.AccessToken, nil
}
