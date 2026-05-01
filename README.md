# kontxt

**Transaction Tokens for Kubernetes** — seal identity, context, and authorization across multi-hop agent workflows.

kontxt implements [IETF Transaction Tokens](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/) (draft-ietf-oauth-transaction-tokens-08) for Kubernetes, providing short-lived, immutable, cryptographically signed tokens that propagate user identity and authorization context through service call chains. Designed for AI agent workloads where an agent orchestrates calls across multiple services, tools, and APIs.

## What TxTokens Unlock

Transaction Tokens enable three capabilities that were **not possible** with any combination of existing tools:

### 1. Request-level authorization across service boundaries

Today, an OAuth scope like `read:datasets` tells a downstream service *who* is calling and *roughly* what they can do. With TxTokens, the `tctx` claim carries **fine-grained, request-specific authorization details** — sealed cryptographically at the entry point:

```
Without TxTokens:  "user X has scope read:datasets"
With TxTokens:     "user X is reading dataset-1234 (classified: public) via the csv-analyzer tool"
```

The TTS can enrich `tctx` with computed values (e.g., looking up that dataset-1234 is classified "public"), so downstream services don't each need to re-derive this — it's already in the token.

### 2. Immutable delegation chains with non-expandable scope

When you forward an OAuth access token, any compromised intermediate service can use that token to call *any* API the token has access to. TxTokens are fundamentally different:

- **Short-lived** (~15 seconds) — useless after expiry, no replay window
- **Scope can only shrink** — an intermediate service can request a narrower TxToken, never a broader one
- **Transaction-bound** — the `txn` claim ties the token to a specific transaction; it cannot be reused for a different purpose

### 3. End-to-end audit correlation without distributed tracing

Every TxToken carries a unique `txn` identifier that is preserved through the entire call chain — including through scope-narrowing replacements. Correlating a user's action across 5 service hops requires a single `grep` on the `txn` value, not stitching together disparate logs from different tracing systems.

## Why

When Agent A calls Tool B which calls Service C, today's options are:

| Approach | Problem |
|----------|---------|
| **Forward the OAuth access token** | Lateral movement risk — any compromised hop can replay it against any other service |
| **Each service authenticates independently** | Delegation context lost — Service C doesn't know who initiated the transaction or why |
| **Custom headers / context propagation** | No cryptographic binding, no standard, no audit trail |
| **OPA / policy engines** | Each service evaluates policy independently — no shared transaction context, no scope narrowing |

Transaction Tokens solve all of these: a TxToken is issued once at the entry point, carries the user's identity + transaction context (`tctx`) + scope, and propagates unmodified through the entire call chain. Each hop verifies the token independently. The token is short-lived (~15s), immutable, and scope can only shrink (never expand).

### Before and after

**Before** — forwarding an OAuth access token through the chain:

```
Client → Agent A → Tool B → Service C
         │          │         │
         │ AT ──────┘ AT ─────┘  Same long-lived token at every hop
         │                       Any hop can replay it
         │                       Service C has no idea why it was called
         └── No transaction context, no audit correlation
```

**After** — using kontxt Transaction Tokens:

```
Client → AgentGateway → Agent A → Tool B → Service C
         │                │         │         │
         │ OAuth AT       │ TxToken  │ TxToken  │ Same TxToken, verified
         │ exchanged      │ (15s,    │ (scope   │ independently at each hop
         │ for TxToken    │  scoped, │  can only│
         │ at entry       │  tctx:{  │  shrink) │
         │                │  purpose,│         │
         │                │  params})│         │
         └── txn=abc-123 links every hop for audit
```

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
helm install kontxt oci://ghcr.io/aramase/charts/kontxt --version 0.0.1 \
  --create-namespace --namespace kontxt-system \
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

## kontxt vs Alternatives

| Capability | Forward OAuth AT | Custom Headers | OPA | **kontxt (TxTokens)** |
|------------|:---:|:---:|:---:|:---:|
| User identity at every hop | ✅ | ⚠️ no crypto | ❌ | ✅ |
| Request-specific context (`tctx`) | ❌ | ⚠️ no crypto | ❌ | ✅ |
| Scope narrowing (can't escalate) | ❌ | ❌ | ❌ | ✅ |
| Short-lived (no replay) | ❌ | ❌ | N/A | ✅ (15s) |
| End-to-end audit correlation | ❌ | ❌ | ❌ | ✅ (`txn`) |
| Standard protocol | ✅ RFC 6749 | ❌ | ❌ | ✅ IETF draft |
| No code changes (gateway-enforced) | ✅ | ❌ | ✅ | ✅ |
| Proves *why* a service was called | ❌ | ❌ | ❌ | ✅ (`tctx.purpose`) |

> **Note:** kontxt complements mTLS — mTLS authenticates the *calling workload*, TxTokens carry the *initiating identity* (user or workload) and *transaction context*. In Istio ambient mode, ztunnel provides mTLS at L4 while kontxt handles authorization at L7.

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
