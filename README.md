# kontxt

**Transaction Tokens for Kubernetes** — seal identity, context, and authorization across multi-hop agent workflows.

kontxt implements [IETF Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) (draft-ietf-oauth-transaction-tokens-08) for Kubernetes, providing short-lived, immutable, cryptographically signed tokens that propagate user identity and authorization context through service call chains. Designed for AI agent workloads where an agent orchestrates calls across multiple services, tools, and APIs.

## Why

When Agent A calls Tool B which calls Service C, today's options are:

- **Forward the OAuth access token** → lateral movement risk (any compromised hop can replay it)
- **Each service authenticates independently** → delegation context lost (Service C doesn't know who initiated the transaction)
- **Custom headers/context propagation** → no cryptographic binding, no standard, no audit trail

Transaction Tokens solve all three: a TxToken is issued once at the entry point, carries the user's identity + transaction context (`tctx`) + scope, and propagates unmodified through the entire call chain. Each hop verifies the token independently. The token is short-lived (~15s), immutable, and scope can only shrink (never expand).

## Architecture

```
┌──────────┐     ┌────────────────┐     ┌──────────────┐     ┌──────────────┐
│  Client  │────▶│  AgentGateway  │────▶│  Service A   │────▶│  Service B   │
│          │     │  + ext_authz   │     │              │     │              │
└──────────┘     └───────┬────────┘     └──────────────┘     └──────────────┘
                         │                                          │
                    TxToken Ext Auth                          Verify TxToken
                    Adapter (gRPC)                            (same token,
                         │                                    unmodified)
                         ▼
                  ┌──────────────┐
                  │     TTS      │
                  │ (Transaction │
                  │ Token Service)│
                  └──────────────┘
```

kontxt works with **AgentGateway** as the data plane — either standalone (own Kubernetes controller) or managed by Istiod (`istio-agentgateway` GatewayClass). The TxToken Ext Auth Adapter implements the standard Envoy ext_authz v3 gRPC proto, making it portable across any Envoy-compatible proxy.

## Components

| Component | Description |
|-----------|-------------|
| **TTS** (`cmd/tts`) | Transaction Token Service — RFC 8693 token exchange endpoint. Validates subject tokens via pluggable JWT authenticators (KEP-3331 inspired), builds `tctx`/`rctx` claims, evaluates CEL issuance rules, signs TxToken JWTs. |
| **Ext Auth Adapter** (`cmd/extauth`) | Envoy ext_authz gRPC service with two modes: **generation** (exchange OAuth AT → TxToken at entry points) and **verification** (validate TxToken at downstream services). Resolves internal workload identity via SPIFFE principal or pod IP. |
| **Controller** (`cmd/controller`) | Reconciles 4 CRDs, validates against policies, pushes generation/verification rules to the TTS and ext auth adapter via ConfigMaps. |
| **SDK** (`sdk/`) | Go SDK for agents that interact with the TTS directly: `sdk/tts` (token exchange client), `sdk/verify` (TxToken verifier), `sdk/middleware` (HTTP verify + propagate middleware). |

## CRDs

Four persona-aligned CRDs, each scoped to the owner's RBAC boundary:

| CRD | Scope | Owner | Purpose |
|-----|-------|-------|---------|
| `TxTokenConfig` | Cluster | Platform Admin | Trust domain, issuer, pluggable IdPs, workload auth, defaults |
| `TransactionType` | Namespace | Transaction Owner | Endpoint → TxToken mapping: purpose, scope, `tctx` field extraction, enrichments |
| `ServiceTokenRequirement` | Namespace | Service Owner | Verification requirements: required scope, required `tctx` fields, CEL rules, excluded endpoints |
| `TokenPolicy` | Cluster | Security Admin | Guardrails: authorized namespaces, scope ceilings, mandatory fields, CEL issuance rules |

## TxToken Format

A TxToken is a JWT (`typ: txntoken+jwt`) with these claims:

```json
{
  "iss": "https://tts.kontxt-system.svc",
  "aud": "cluster.example.com",
  "sub": "user@example.com",
  "scope": "read:datasets",
  "txn": "550e8400-e29b-41d4-a716-446655440000",
  "req_wl": "system:serviceaccount:team-alpha:my-agent",
  "tctx": {
    "purpose": "dataset-analysis",
    "datasetId": "ds-1234",
    "classification": "public"
  },
  "rctx": {
    "req_ip": "10.0.0.42",
    "authn": "oidc"
  },
  "iat": 1711987200,
  "exp": 1711987215
}
```

## Quick Start

### SDK (standalone, no gateway needed)

```go
import (
    sdktts "github.com/aramase/kontxt/sdk/tts"
    "github.com/aramase/kontxt/sdk/middleware"
    "github.com/aramase/kontxt/sdk/verify"
)

// Exchange an OIDC access token for a TxToken
client := sdktts.NewClient("https://tts.kontxt-system.svc")
txToken, _ := client.Exchange(ctx, &sdktts.ExchangeRequest{
    SubjectToken:     oauthAccessToken,
    SubjectTokenType: "urn:ietf:params:oauth:token-type:access_token",
    Scope:            "read:datasets",
    RequestDetails:   map[string]any{"datasetId": "ds-1234"},
})

// Verify incoming TxTokens (server-side middleware)
verifier := verify.New("https://tts.kontxt-system.svc/.well-known/jwks.json", "cluster.example.com")
handler := middleware.VerifyTxToken(verifier)(yourHandler)

// Propagate TxTokens to downstream calls (client-side transport)
httpClient := &http.Client{
    Transport: middleware.NewPropagateTransport(http.DefaultTransport),
}
```

### Kubernetes (Helm)

```bash
helm install kontxt deploy/helm/kontxt \
  --set tts.config.trustDomain=cluster.example.com \
  --set tts.config.issuer=https://kontxt-tts.kontxt-system.svc
```

## Development

```bash
# Run all tests
make test

# Generate deepcopy + CRD manifests (after changing api/v1alpha1/types.go)
make generate manifests

# Verify generated files are up-to-date
make verify-codegen

# Build all binaries
make build

# Build Docker images
make docker

# Run E2E tests (requires Docker + kind)
make test-e2e

# Lint
make lint
```

## Deployment Models

| Model | Control Plane | Data Plane | When to Use |
|-------|--------------|------------|-------------|
| **Standalone** | AgentGateway built-in controller | AgentGateway | No Istio, simple setup |
| **Istio Ambient** | Istiod (`istio-agentgateway` GatewayClass) | AgentGateway + ztunnel (L4) | Full mesh with mTLS |
| **SDK** | N/A | Application calls TTS directly | Lightweight, maximum control |

## Specification

kontxt implements [draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) (IETF WG Last Call). Key spec concepts:

- **Token Exchange** (RFC 8693) — exchange OAuth AT for TxToken
- **Token Replacement** — exchange existing TxToken for narrower scope (preserves `txn`)
- **`tctx`** — immutable transaction context (authorization details, TTS-computed enrichments)
- **`rctx`** — requester context (environmental data: IP, auth method)
- **`txn`** — unique transaction ID for end-to-end audit correlation
- **`req_wl`** — requesting workload identity
- **Scope narrowing** — scope can only shrink through the chain, never expand

## License

Apache 2.0 — see [LICENSE](LICENSE).
