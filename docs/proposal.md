# POC: Transaction Tokens for Agent Workloads on AKS

**Author:** Anish Ramasekar
**Date:** 2026-04-02
**Status:** Proposal
**Goal:** Build an incremental, working proof-of-concept for Transaction Tokens (TxTokens) on AKS with a pluggable IdP model — not Entra-specific.

---

## Motivation

When an AI agent running on Kubernetes calls Tool A, which calls Service B, which calls Service C, every hop today uses the **same** long-lived OAuth access token — or worse, each hop independently authenticates with its own credentials and the original user's authorization context is lost.

This creates three problems:

1. **Lateral movement** — A compromised service can replay the access token against any other service in the cluster. The token doesn't know it was meant for a specific transaction.
2. **Lost delegation context** — By the time Service C processes the request, there's no cryptographic proof of _who_ initiated the transaction, _what_ the original intent was, or _which_ path the call took.
3. **Audit gap** — Correlating a single user action across 4-5 service hops requires stitching together disparate logs with no shared transaction identifier.

Transaction Tokens (TxTokens, [draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/), currently in IETF WG Last Call) solve all three by issuing short-lived (~15 seconds), immutable, transaction-bound JWTs that propagate through call chains. They **cannot** be used as access tokens, their scope can only shrink, and each carries a unique `txn` identifier for end-to-end correlation.

This POC builds a Transaction Token system for AKS in incremental steps, each delivering independently useful value. We use a **pluggable IdP model** so the system works with any OIDC-compliant identity provider (Entra, Keycloak, Dex, Auth0, etc.) rather than being locked to a single vendor.

---

## Reference Architecture

The IETF spec defines three roles. We implement them using **AgentGateway** as the unified data plane — a Rust-based, AI-native proxy that natively supports MCP, A2A, and HTTP routing, with the standard Envoy ext_authz gRPC proto for TxToken handling.

AgentGateway runs in two modes:
- **Standalone** — its own built-in Kubernetes controller (Gateway API conformant), no Istio required
- **Istio-managed** — Istiod acts as control plane via the `istio-agentgateway` GatewayClass ([istio/istio#59209](https://github.com/istio/istio/issues/59209), all PRs merged, targeting Istio 1.30). In ambient mode, ztunnel handles L4 mTLS and AgentGateway replaces the Envoy waypoint proxy at L7.

The **TTS** and **TxToken Ext Auth Adapter** are identical across both modes — they implement the ext_authz gRPC proto and don't know which control plane manages AgentGateway.

```
                    ┌─────────────────────────────────────────────────────────┐
                    │  Control Plane (either one)                             │
                    │  ┌──────────────────┐  ┌─────────────────────────────┐ │
                    │  │ AgentGateway's   │  │ Istiod                      │ │
                    │  │ built-in K8s     │  │ (GatewayClass:              │ │
                    │  │ controller       │  │  istio-agentgateway)        │ │
                    │  │ (standalone)     │  │ + ztunnel at L4             │ │
                    │  └────────┬─────────┘  └──────────┬──────────────────┘ │
                    │           │   xDS                  │  xDS               │
                    └───────────┼─────────────────────────┼───────────────────┘
                                └────────────┬────────────┘
                                             ▼
                                 ┌───────────────────────┐
                                 │  AgentGateway Proxy    │
                                 │  (Rust, per-namespace) │
                                 │  • MCP / A2A / HTTP    │
                                 │  • ext_authz → adapter │
                                 └───────────┬───────────┘
                                             │
                              ┌──────────────┼──────────────┐
                              ▼              ▼              ▼
                    ┌──────────────┐  ┌────────────┐  ┌────────────┐
                    │ TxToken Ext  │  │  Service A │  │  Service B │
                    │ Auth Adapter │  │  (no       │  │  (no       │
                    │ (gRPC)       │  │   sidecar) │  │   sidecar) │
                    │      │       │  └────────────┘  └────────────┘
                    │      ▼       │
                    │    TTS       │
                    └──────────────┘
```

**Key invariant:** The TxToken is created once at the entry point (by the ext auth adapter calling the TTS) and propagated **unmodified** through the entire call chain. Each downstream hop is verified by the ext auth adapter when traffic passes through the AgentGateway. No sidecars.

---

## Personas & Ownership Model

Before defining CRDs, we need to be clear about who configures what. In a multi-tenant AKS cluster, namespaces are trust boundaries — a developer in `team-alpha` has RBAC to their namespace but not `team-beta`'s. The CRD design must respect this.

### Cluster topology

```
Cluster
├── Namespace: platform-system            ← Platform admin owns
│   └── TTS, controller, TxToken Ext Auth Adapter
├── Namespace: team-alpha                  ← Team Alpha owns (agents)
│   ├── AgentGateway proxy (per-namespace) ← handles entry TxToken generation
│   ├── agent-orchestrator (pod)           ← entry point, initiates transactions
│   └── data-processor (pod)
├── Namespace: team-beta                   ← Team Beta owns (downstream services)
│   ├── AgentGateway proxy (per-namespace) ← handles TxToken verification
│   ├── storage-service (pod)              ← receives TxTokens, verified by gateway
│   └── audit-service (pod)
└── Namespace: security-policies           ← Security team owns
    └── cluster-wide policy resources
```

### The four personas

| Persona | Scope | What They Own | RBAC | Examples |
|---------|-------|---------------|------|----------|
| **Platform Admin** | Cluster-wide | TTS infrastructure, IdP config, trust domain, workload auth mechanism | `cluster-admin` or `txtoken-platform-admin` ClusterRole | "We trust Entra and Keycloak as IdPs. Workload auth uses projected SA tokens." |
| **Security Admin** | Cluster-wide | Authorization guardrails: who can request TxTokens, scope ceilings, max lifetimes, mandatory fields, external policy engine | `txtoken-security-admin` ClusterRole with access to policy CRDs | "Max token lifetime is 60s. All tokens must have `purpose` in tctx. Only namespaces labeled `entry-allowed` can generate tokens." |
| **Transaction Owner** | Own namespace | Transaction definitions: when my agent calls endpoint X, the TxToken should carry purpose Y with these tctx fields extracted from the request | Namespace-scoped RBAC (standard edit/create in own namespace) | "When my agent calls `/api/v1/datasets/{id}/analyze`, extract `datasetId` from the path and `analysisType` from the body." |
| **Service Owner** | Own namespace | Service verification requirements: my service requires these tctx fields, this minimum scope, and these endpoints are excluded | Namespace-scoped RBAC (standard edit/create in own namespace) | "My storage-service requires `datasetId` and `classification` in tctx, minimum scope `read:datasets`, and `/healthz` is excluded." |

### Why this factoring matters

The fundamental problem: **when Agent A in `team-alpha` calls `storage-service` in `team-beta`, who defines what the TxToken should look like?**

Neither team owns the full picture:
- Team Alpha knows _what_ the transaction is (purpose, parameters to extract)
- Team Beta knows _what_ their service expects (required tctx fields, minimum scope)
- The platform admin set up the IdPs and TTS
- The security team constrains all of it

A single CRD owned by one team can't represent both sides of this contract. If we put everything in one resource:
- Either the Transaction Owner in `team-alpha` needs write access to `team-beta`'s namespace to specify `team-beta`'s service expectations → **RBAC violation**
- Or the resource lives in `team-alpha` and contains assumptions about `team-beta`'s services that `team-beta` never agreed to → **contract violation**

The CRD design must split generation concerns (transaction owner) from verification concerns (service owner) along namespace boundaries.

---

## Steps

### Step 1: Minimal TTS — Issue TxTokens from OIDC Access Tokens

**What:** Build a standalone Transaction Token Service (TTS) that accepts an OIDC access token via the RFC 8693 token exchange endpoint and returns a signed TxToken JWT.

**Why this first:** The TTS is the core primitive. Everything else (verification, propagation, CRDs) depends on having a service that can issue well-formed TxTokens. By starting here, we validate the token format, the exchange protocol, and the pluggable IdP model before introducing any Kubernetes-specific machinery.

**Technical scope:**

1. **Token exchange endpoint** (`POST /token_endpoint`):
   - Accepts RFC 8693 parameters:
     ```
     grant_type=urn:ietf:params:oauth:grant-type:token-exchange
     subject_token=<OIDC access token or ID token>
     subject_token_type=urn:ietf:params:oauth:token-type:access_token
     requested_token_type=urn:ietf:params:oauth:token-type:txn_token
     audience=<trust domain identifier>
     scope=<requested scope, must be ≤ subject token scope>
     ```
   - **`request_details`** (JSON) — Request-specific parameters that become the `tctx` claim. The TTS extracts and optionally enriches these into immutable authorization details. Example: `{"action":"BUY","ticker":"MSFT","quantity":"100"}`.
   - **`request_context`** (JSON) — Environmental context that becomes the `rctx` claim. Example: `{"req_ip":"69.151.72.123","authn":"urn:ietf:rfc:6749"}`.

2. **Pluggable IdP validation** (inspired by [KEP-3331 Structured Authentication Configuration](https://github.com/kubernetes/enhancements/blob/master/keps/sig-auth/3331-structured-authentication-configuration/README.md), GA in K8s 1.34):
   - Configuration-driven, not code-driven. An ordered list of JWT authenticators, each with its own issuer, audiences, validation rules, and claim mappings:
     ```yaml
     subjectTokens:
       # Each entry is a JWT authenticator — first matching issuer wins
       - issuer:
           url: "https://login.microsoftonline.com/{tenant}/v2.0"
           audiences: ["{app-id}"]
           audienceMatchPolicy: MatchAny
         claimValidationRules:
           - expression: 'claims.tid == "{tenant-id}"'
             message: "token must be from the expected tenant"
         claimMappings:
           subject:
             expression: 'claims.oid'   # which claim becomes TxToken `sub`
           extra:
             - key: 'tenant'
               valueExpression: 'claims.tid'
             - key: 'name'
               valueExpression: 'claims.name'

       - issuer:
           url: "https://keycloak.example.com/realms/my-realm"
           audiences: ["my-client"]
         claimMappings:
           subject:
             claim: "email"             # simple claim reference (no CEL)

       - issuer:
           # Kubernetes SA tokens — for internal workloads
           url: "https://oidc.prod-aks.azure.com/{cluster-id}"
           discoveryURL: "https://oidc.prod-aks.azure.com/{cluster-id}/.well-known/openid-configuration"
           audiences: ["kontxt-tts"]
         claimMappings:
           subject:
             claim: "sub"               # system:serviceaccount:<ns>:<sa>
     ```
   - **Issuer matching:** When a subject token arrives, the TTS decodes the `iss` claim (without verification) and routes to the matching authenticator. Each authenticator then performs full validation (signature via OIDC discovery JWKS, expiration, audience, claim validation rules).
   - **CEL claim validation rules:** Evaluated against raw JWT claims before mapping. If any rule returns `false`, the token is rejected with the rule's message. Same CEL environment as KEP-3331 — `claims` variable as a dynamic map.
   - **CEL claim mappings:** The `claimMappings.subject` field determines which claim becomes the TxToken's `sub`. Supports either a simple `claim` name or a CEL `expression`. The `extra` mappings carry additional identity attributes from the IdP token into the TTS's context.
   - **Discovery URL override:** Separates the logical issuer identity (`url`, must match `iss` claim) from where to actually fetch OIDC metadata (`discoveryURL`). Supports scenarios where the issuer is not directly reachable from the TTS (e.g., in-cluster OIDC issuers).
   - New authenticator types can be added by implementing a `JWTAuthenticator` interface:
     ```go
     type JWTAuthenticator interface {
         // Matches returns true if this authenticator handles the given issuer
         Matches(issuer string) bool
         // Authenticate validates the token and returns the subject info
         Authenticate(ctx context.Context, token string) (*SubjectInfo, error)
     }
     ```

3. **TxToken JWT format** (all fields per draft-ietf-oauth-transaction-tokens-08):

   **Header:**
   ```json
   { "typ": "txntoken+jwt", "alg": "RS256", "kid": "<key-id>" }
   ```

   **Required claims:**
   ```json
   {
     "iss": "<TTS issuer URI>",
     "iat": 1711987200,
     "exp": 1711987215,                                          // +15 seconds
     "aud": "<trust domain>",                                    // identifies the trust domain; all workloads validate this
     "txn": "550e8400-e29b-41d4-a716-446655440000",              // UUID, unique per transaction, preserved in replacements
     "sub": "user@example.com",                                  // from subject token — the user/principal
     "scope": "read:data execute:analysis",                      // ≤ subject token scope; coarse-grained authorization
     "req_wl": "spiffe://cluster.local/ns/agents/sa/my-agent"   // requesting workload identity (SPIFFE ID or SA)
   }
   ```

   **Optional claims (both important — see below):**
   ```json
   {
     "tctx": {                           // Transaction Context — AUTHORIZATION DETAILS
       "action": "analyze",              //   extracted from request by TTS
       "datasetId": "ds-1234",           //   extracted from request by TTS
       "classification": "public",       //   ← COMPUTED by TTS (not in original request)
       "customer_tier": "enterprise"     //   ← COMPUTED by TTS (not in original request)
     },
     "rctx": {                           // Requester Context — ENVIRONMENTAL DATA
       "req_ip": "10.0.0.42",            //   where the request came from
       "authn": "urn:ietf:rfc:6749"      //   how the user authenticated
     }
   }
   ```

   **`tctx` vs `rctx` — why both matter:**

   | | `tctx` (Transaction Context) | `rctx` (Requester Context) |
   |---|---|---|
   | Spec name | `tctx` | `rctx` |
   | Populated from | `request_details` param + TTS computation | `request_context` param |
   | **Purpose** | **Fine-grained authorization details** — *what* is being authorized | Environmental metadata — *how* the request arrived |
   | Used for authz? | **Yes** — spec calls these "the actual authorization details determined by the TTS" | Supplementary (IP restrictions, audit) |
   | Immutable? | Yes — values remain unchanged through the entire call chain | Yes |
   | TTS can enrich? | **Yes** — TTS can compute values not in the original request (e.g., classify the dataset, look up user tier) | Typically pass-through from the entry point |
   | Agent example | `{"tool":"csv-analyzer","dataset":"ds-1234","classification":"public"}` | `{"req_ip":"10.0.0.42","authn":"oidc"}` |

   **Why `tctx` matters for agents:** Without `tctx`, a downstream service only knows "user X has scope read:datasets." With `tctx`, it knows "user X is reading dataset-123 which is classified public via the csv-analyzer tool." That's the difference between coarse RBAC and fine-grained, request-specific authorization. The TTS enrichment capability (computing `classification: public` by looking up the dataset) means downstream services don't each need to re-derive this — it's sealed in the token.

4. **Workload authentication to TTS:**
   - The TTS must know _which workload_ is requesting the token. This is separate from the subject token (which identifies the _user_).
   - **Primary caller: the TxToken Ext Auth Adapter.** In the full architecture (Step 4+), the ext auth adapter is the only component that calls the TTS. It authenticates with its own projected SA token. The adapter identifies the _originating_ workload from AgentGateway's `CheckRequest` metadata (source pod identity) and passes this as context to the TTS.
   - **For Step 1-2 (before AgentGateway):** During early POC steps, test clients call the TTS directly using a projected SA token in an `Authorization` header. The TTS validates it against the cluster's OIDC issuer.
   - Pluggable via a `WorkloadAuthenticator` interface:
     ```go
     type WorkloadAuthenticator interface {
         Authenticate(ctx context.Context, req *http.Request) (*WorkloadIdentity, error)
     }
     ```
   - **Optional: mTLS with SPIFFE SVIDs** — For environments that already run SPIRE, the TTS can accept X.509 SVIDs for workload authentication.

5. **Key management:**
   - The TTS generates an RSA key pair on startup, rotates on a configurable interval (default: 24h).
   - Publishes a JWKS endpoint (`GET /.well-known/jwks.json`) so verifiers can obtain the public key.
   - Keys are stored in-memory (for POC) with a Kubernetes Secret backend available for persistence.

**Deliverable:** A Go binary that runs as a single pod, accepts token exchange requests, validates subject tokens against any OIDC provider, and returns signed TxToken JWTs. Testable with `curl`.

**Validation:** Issue a TxToken using a Keycloak-issued access token as input. Verify the JWT structure, claims, signature, and that it expires in 15 seconds.

---

### Step 2: TxToken Verification Library + Manual Propagation

**What:** Build a Go library that verifies TxToken JWTs, and demonstrate manual propagation through a 3-service call chain.

**Why this step:** Before automating propagation with AgentGateway, we need to prove the end-to-end flow works at the application level. This step validates that (a) TxTokens can be verified at each hop, (b) the `Txn-Token` HTTP header convention works, and (c) the token's claims are sufficient for downstream services to make authorization decisions. Doing this without the gateway keeps the surface area small and makes debugging straightforward.

**Technical scope:**

1. **Verification library** (`pkg/txtoken`):
   ```go
   type Verifier struct {
       jwksURL    string                    // TTS JWKS endpoint
       audience   string                    // expected trust domain
       keyCache   *jwk.Cache               // auto-refreshing key cache
   }

   func (v *Verifier) Verify(ctx context.Context, tokenString string) (*TxTokenClaims, error) {
       // 1. Parse JWT, check typ == "txntoken+jwt"
       // 2. Validate signature against cached JWKS
       // 3. Check exp (reject expired)
       // 4. Check aud matches trust domain
       // 5. Extract and return all claims: sub, txn, scope, req_wl, tctx, rctx
   }
   ```

2. **Propagation middleware** (Go HTTP middleware):
   ```go
   // Server-side: verify incoming TxToken
   func VerifyTxToken(verifier *Verifier) func(http.Handler) http.Handler

   // Client-side: propagate TxToken to outbound requests
   func PropagateHeader(req *http.Request, incomingReq *http.Request) *http.Request
   ```
   - Reads `Txn-Token` header from incoming request
   - Verifies the token
   - Makes claims available via request context (`ctx.Value(txtoken.ClaimsKey)`)
   - Copies the `Txn-Token` header to outbound requests (unmodified)

3. **Demo: 3-service call chain:**
   ```
   Client → [Service A (entry)] → [Service B (processor)] → [Service C (storage)]
                 │                        │                        │
                 │ Exchange AT→TxToken    │ Verify TxToken        │ Verify TxToken
                 │ Set Txn-Token header   │ Forward Txn-Token     │ Log txn, sub, scope
                 │                        │                        │
                 ▼                        ▼                        ▼
              TTS                   (pass-through)           (terminal verify)
   ```
   - Service A: Receives OAuth access token from client. Calls TTS to exchange for TxToken. Sets `Txn-Token` header on call to Service B.
   - Service B: Verifies TxToken. Forwards `Txn-Token` header unchanged to Service C. Logs `txn` for audit.
   - Service C: Verifies TxToken. Logs `txn`, `sub`, `scope`. Returns response.
   - All three services use the verification middleware.

4. **Structured audit logging:**
   - Each service logs a JSON audit event on every verified TxToken:
     ```json
     {
       "event": "txtoken_verified",
       "txn": "550e8400-...",
       "sub": "user@example.com",
       "scope": "read:data",
       "req_wl": "spiffe://cluster.local/ns/agents/sa/my-agent",
       "tctx": {"action":"analyze","datasetId":"ds-1234","classification":"public"},
       "service": "service-c",
       "timestamp": "2026-04-02T10:00:00Z"
     }
     ```
   - Demonstrates end-to-end transaction correlation using the `txn` claim.
   - Demonstrates that `tctx` authorization details (including TTS-computed fields) are available at every hop for both authorization and audit.

**Deliverable:** A Go SDK (`github.com/aramase/kontxt/sdk`) with three packages:
- **`sdk/tts`** — TTS client for RFC 8693 token exchange (obtain TxTokens)
- **`sdk/verify`** — TxToken JWT verifier (signature, expiration, audience, claims)
- **`sdk/middleware`** — HTTP server middleware (verify incoming TxTokens) + HTTP client middleware (propagate `Txn-Token` header on outbound requests)

This SDK is the **standalone deployment model** — agents that don't use AgentGateway or Istio can `go get github.com/aramase/kontxt/sdk` and interact with the TTS directly. It's also the library that the ext auth adapter uses internally.

A 3-service demo app deployed on Kubernetes demonstrating the end-to-end flow.

**Validation:**
- Send a request to Service A with a valid OIDC access token. Verify that the same `txn` value appears in all three services' logs.
- Send a request with a stolen/expired TxToken. Verify it's rejected at Service B.
- Verify that the TxToken's `exp` claim causes rejection after 15 seconds.

---

### Step 3: CRDs + Controller — Persona-Aligned Declarative Configuration

**What:** Define four CRDs, each owned by a distinct persona, that together describe the full TxToken lifecycle. Build a controller that reconciles them, detects cross-namespace contract mismatches, and pushes computed rules to the TTS and the TxToken Ext Auth Adapter.

**Why this step:** Steps 1-2 hardcode everything — generation rules, IdP config, verification expectations — in code or static config files. This doesn't work in a multi-tenant cluster where different teams own different namespaces with different RBAC boundaries. We need a declarative configuration surface where each persona manages only what they own, in the namespace they control, and the controller joins the pieces together.

**Technical scope:**

#### CRD 1: `TxTokenConfig` — Platform Admin, cluster-scoped

```yaml
apiVersion: kontxt.io/v1alpha1
kind: TxTokenConfig
metadata:
  name: default                  # cluster singleton
spec:
  # Trust domain — all TxTokens carry this as the `aud` claim.
  # All verifiers in the cluster check for this value.
  trustDomain: "aks-cluster-1.contoso.com"
  issuer: "https://tts.platform-system.svc.cluster.local"

  # Pluggable IdP configuration (inspired by KEP-3331 Structured Authentication Configuration)
  # Ordered list of JWT authenticators — first matching issuer wins.
  subjectTokens:
    - issuer:
        url: "https://login.microsoftonline.com/{tenant}/v2.0"
        audiences: ["{app-id}"]
        audienceMatchPolicy: MatchAny
      claimValidationRules:
        - expression: 'claims.tid == "{tenant-id}"'
          message: "token must be from the expected tenant"
      claimMappings:
        subject:
          expression: 'claims.oid'
        extra:
          - key: 'tenant'
            valueExpression: 'claims.tid'

    - issuer:
        url: "https://keycloak.example.com/realms/agents"
        audiences: ["agent-client"]
      claimMappings:
        subject:
          claim: "email"

    - issuer:
        # Kubernetes SA tokens — for internal workloads
        url: "https://oidc.prod-aks.azure.com/{cluster-id}"
        audiences: ["kontxt-tts"]
      claimMappings:
        subject:
          claim: "sub"             # system:serviceaccount:<ns>:<sa>

  # How the TTS authenticates the requesting workload
  workloadAuth:
    type: "kubernetes-sa"           # or "spiffe"

  # Defaults (overridable by TransactionType, subject to TokenPolicy ceilings)
  defaults:
    tokenLifetime: "15s"
    signingAlgorithm: "RS256"
status:
  conditions:
    - type: Ready
      status: "True"
    - type: IdPsReachable
      status: "True"
```

**Who creates this:** Platform admin.
**RBAC:** `txtoken-platform-admin` ClusterRole.
**Change frequency:** Rare — when adding/removing IdPs or changing infrastructure.

---

#### CRD 2: `TransactionType` — Transaction Owner, namespace-scoped

```yaml
apiVersion: kontxt.io/v1alpha1
kind: TransactionType
metadata:
  name: analyze-dataset
  namespace: team-alpha               # agent owner's namespace
spec:
  # Which inbound endpoint triggers this transaction
  endpoint:
    path: "/api/v1/datasets/{datasetId}/analyze"
    method: "POST"

  # Purpose of this transaction (becomes a field in tctx)
  purpose: "dataset-analysis"

  # Requested scope for the TxToken (must be ≤ subject token scope,
  # and ≤ TokenPolicy ceiling)
  scope: "read:datasets execute:analysis"

  # How to build the `tctx` claim from the inbound request.
  # These are the AUTHORIZATION DETAILS sealed into the token.
  tctxMapping:
    # Extracted from the incoming HTTP request:
    datasetId:
      source: "path"
      field: "datasetId"
      required: true
    analysisType:
      source: "body"
      field: "type"
      required: true
    maxRows:
      source: "body"
      field: "maxRows"
      required: false

  # Values COMPUTED by the TTS — not in the original request.
  # The TTS calls pluggable enrichers to derive these.
  tctxEnrichments:
    - field: "classification"
      enricher: "dataset-classifier"
    - field: "customerTier"
      enricher: "user-tier-lookup"

  # Which rctx fields to populate (environmental context)
  rctxFields:
    - "req_ip"
    - "authn"

  # Lifetime override (subject to TokenPolicy ceiling)
  tokenLifetime: "30s"
status:
  conditions:
    - type: Ready
      status: "True"
    - type: PolicyCompliant              # controller checks against TokenPolicy
      status: "True"
  # Only self-contained status — no cross-namespace references
  producedTctxFields:
    - "datasetId"
    - "analysisType"
    - "maxRows"
    - "classification"
    - "customerTier"
    - "purpose"
  effectiveTokenLifetime: "30s"          # after TokenPolicy ceiling applied
```

**Who creates this:** The agent developer / entry-point team.
**RBAC:** Standard namespace-scoped edit/create — team-alpha devs can only create these in `team-alpha`.
**What this does NOT do:** It does not reference downstream services, their internal paths, or their verification expectations. The transaction owner defines _what_ the token carries, not _who_ consumes it. The status contains only self-referential information — no cross-namespace service names that would leak cluster topology.

---

#### CRD 3: `ServiceTokenRequirement` — Service Owner, namespace-scoped

```yaml
apiVersion: kontxt.io/v1alpha1
kind: ServiceTokenRequirement
metadata:
  name: storage-service-reqs
  namespace: team-beta                # service owner's namespace
spec:
  # Which service this applies to
  serviceRef:
    name: storage-service

  # What this service REQUIRES in incoming TxTokens
  verification:
    # Minimum scope — TxToken must have at least this scope
    requiredScope: "read:datasets"

    # Required tctx fields — TxToken must contain these for this service
    # to make authorization decisions
    requiredTctxFields:
      - "datasetId"
      - "classification"

    # CEL-based verification rules — evaluated by the ext auth adapter on each request.
    # Variables available: `txtoken` (all TxToken claims), `request` (inbound HTTP request)
    rules:
      - name: "public-or-internal-only"
        cel: >
          txtoken.tctx.classification in ['public', 'internal']
        message: "This service only handles public and internal datasets"

      - name: "require-valid-dataset-id"
        cel: >
          txtoken.tctx.datasetId.matches('^ds-[0-9]+$')
        message: "datasetId must match pattern ds-<number>"

  # Endpoints excluded from TxToken verification
  excludedEndpoints:
    - path: "/healthz"
      method: "GET"
    - path: "/readyz"
      method: "GET"
    - path: "/metrics"
      method: "GET"
status:
  conditions:
    - type: Ready
      status: "True"
    - type: VerificationConfigured
      status: "True"
  # Only self-contained status — no cross-namespace references
  activeVerificationRules: 3
  excludedEndpoints: 3
```

**Who creates this:** The service owner.
**RBAC:** Standard namespace-scoped edit/create — team-beta devs can only create these in `team-beta`.
**What this does:** Declares the verification side of the contract. The service owner knows their API — they declare what authorization context they need in the TxToken. The ext auth adapter at the AgentGateway enforces this when traffic enters the namespace. Status contains only self-referential information.

---

#### CRD 4: `TokenPolicy` — Security Admin, cluster-scoped

```yaml
apiVersion: kontxt.io/v1alpha1
kind: TokenPolicy
metadata:
  name: default-policy
spec:
  # Which namespaces can define TransactionTypes (generate TxTokens)
  authorizedTransactionNamespaces:
    matchLabels:
      kontxt.io/entry-allowed: "true"

  # Which service accounts can request TxTokens from the TTS
  authorizedRequesters:
    - namespaceSelector:
        matchLabels:
          kontxt.io/entry-allowed: "true"
      serviceAccountNames:
        - "agent-*"
        - "api-gateway"

  # Global constraints — ceilings that TransactionTypes cannot exceed
  constraints:
    maxTokenLifetime: "60s"

    # Mandatory tctx fields for ALL tokens (audit/compliance requirement)
    mandatoryTctxFields:
      - "purpose"

    # Mandatory rctx fields
    mandatoryRctxFields:
      - "req_ip"
      - "authn"

  # CEL-based issuance rules — evaluated by the TTS before issuing a TxToken.
  # Variables available: `subject` (sub claim), `scope` (requested scope),
  # `tctx` (transaction context), `rctx` (requester context),
  # `workload` (requesting workload identity), `namespace` (requester namespace)
  issuanceRules:
    - name: "block-pii-outside-business-hours"
      cel: >
        !(tctx.classification == 'pii' &&
          (timestamp(now).getHours() < 8 || timestamp(now).getHours() > 18))
      message: "PII access is only permitted during business hours (08:00-18:00)"

    - name: "restrict-write-scope-to-approved-agents"
      cel: >
        !scope.contains('write:') || workload.serviceAccount.startsWith('agent-approved-')
      message: "Write scope requires an approved agent service account"

    - name: "require-classification-for-dataset-access"
      cel: >
        !scope.contains('read:datasets') || has(tctx.classification)
      message: "Dataset access requires classification in tctx"

  # Optional: external webhook for policy decisions that CEL can't express
  # (e.g., external data lookups, complex organizational policy bundles)
  # This is the escape hatch, not the primary mechanism.
  accessEvaluationWebhook:
    enabled: false
    endpoint: "https://policy-engine.security-policies.svc/v1/evaluate"
    failurePolicy: "Deny"          # Deny or Allow on webhook failure
---
# Namespace-specific policy override (more restrictive than default)
apiVersion: kontxt.io/v1alpha1
kind: TokenPolicy
metadata:
  name: team-beta-strict
spec:
  # Applies only to tokens destined for services in team-beta
  targetNamespaces:
    matchNames: ["team-beta"]

  constraints:
    maxTokenLifetime: "15s"         # stricter for this namespace
    # Block certain enrichers (PII concern)
    disallowedEnrichers:
      - "user-tier-lookup"

  issuanceRules:
    - name: "team-beta-public-only"
      cel: >
        !has(tctx.classification) || tctx.classification in ['public', 'internal']
      message: "team-beta services only handle public and internal data"
```

**Who creates this:** Security admin.
**RBAC:** `txtoken-security-admin` ClusterRole.
**What this does:** Defines guardrails. No matter what individual teams configure in their `TransactionType` or `ServiceTokenRequirement`, the `TokenPolicy` constraints apply. The controller validates all resources against the applicable `TokenPolicy` and marks non-compliant resources with `PolicyCompliant: False`.

**Why CEL over OPA/Rego:**
- **Kubernetes-native** — CEL is already the policy language for ValidatingAdmissionPolicies, Gateway API, and CRD validation. Operators already know it.
- **In-process evaluation** — no network call to an external sidecar/service. Sub-millisecond latency. No availability dependency. This matters because the TTS evaluates issuance rules on every token exchange request.
- **Hermetic** — CEL can't do I/O, is deterministic, and is sandboxed. For token issuance, you don't want a policy engine that could make arbitrary network calls and add unpredictable latency.
- **Type-safe** — CEL expressions are compiled and type-checked against a declared variable schema (`subject`, `scope`, `tctx`, `rctx`, `workload`, `namespace`). Malformed policies fail at CRD creation time, not at runtime.
- **`accessEvaluationWebhook` is the escape hatch** — for cases where CEL isn't expressive enough (external data lookups, complex organizational policies, AuthZEN integration), the webhook provides an extension point. But it's opt-in, not the default.

---

#### Controller behavior

The controller reconciles all four CRD types and produces two outputs:

**1. Generation rules → TTS**

For each `TransactionType`, the controller:
- Validates against applicable `TokenPolicy` (lifetime ≤ ceiling, mandatory fields present, namespace authorized, enrichers allowed)
- Computes the full generation rule: endpoint match, tctxMapping, enrichments, rctx fields, scope, lifetime
- Pushes to TTS via ConfigMap (POC) or direct API (production)

**2. Verification rules → ext auth adapter**

For each `ServiceTokenRequirement`, the controller:
- Validates the service exists in the namespace
- Compiles CEL expressions and checks them for type errors
- Computes the verification rule: required scope, required tctx fields, compiled CEL rules, excluded endpoints
- Pushes to the TxToken Ext Auth Adapter via ConfigMap (POC) or direct API (production)

**3. CEL compilation and distribution**

CEL expressions from both `TokenPolicy` (issuance rules) and `ServiceTokenRequirement` (verification rules) are compiled at CRD creation/update time by the controller. If a CEL expression fails to compile, the controller rejects the update and sets a status condition with the compilation error. This means malformed policies fail fast — not at runtime when tokens are being issued or verified.

**No cross-namespace contract validation in CRD status.** The controller does NOT write cross-namespace compatibility information into any resource's status because:
1. It would leak cluster topology (team-alpha's status listing services from team-beta)
2. The list grows unboundedly as more services/transactions are added

Instead, contract enforcement happens at **runtime**: if a TxToken arrives at a service without the required tctx fields or with a failing CEL rule, the ext auth adapter at the AgentGateway rejects it with a clear error message. The service owner sees the rejection in ext auth adapter metrics and logs. This is the same model Kubernetes uses for NetworkPolicy — you define what you accept, and non-conforming traffic is dropped at the enforcement point.

**Key point:** Neither team needs write access to the other's namespace. The controller reads across namespaces (it has a ClusterRole) but individual devs only write to their own.

---

#### How the pieces fit together

```
            TokenPolicy (cluster-scoped, security admin)
            ┌──────────────────────────────────────────┐
            │ Constraints: max lifetime, scope ceiling, │
            │ mandatory fields, authorized namespaces,  │
            │ CEL issuance rules                        │
            └──────────────────┬───────────────────────┘
                               │ constrains
                               ▼
     TxTokenConfig (cluster-scoped, platform admin)
     ┌──────────────────────────────────────────┐
     │ Infrastructure: IdPs, trust domain,       │
     │ workload auth, defaults                   │
     └──────────────────┬───────────────────────┘
                        │ configures
                        ▼
                   ┌─────────┐
                   │   TTS   │
                   └────┬────┘
                        │
     ┌──────────────────┴──────────────────────┐
     │                                          │
TransactionType                    ServiceTokenRequirement
(ns: team-alpha,                   (ns: team-beta,
 transaction owner)                 service owner)
┌────────────────────┐            ┌────────────────────┐
│ "When my agent     │            │ "My service needs  │
│  hits this endpoint│            │  these tctx fields │
│  build tctx with   │            │  and this scope to │
│  these fields"     │            │  authorize requests│
└────────┬───────────┘            └────────┬───────────┘
         │ generation rules                │ verification rules
         ▼                                 ▼
  Entry-point pod               Downstream service pod
  (team-alpha)                  (team-beta)
  ┌──────────────┐              ┌──────────────────┐
  │ AgentGateway │  Txn-Token   │ AgentGateway     │
  │ + ext auth   │──── header ──►│ + ext auth       │
  │ (generates)  │              │ (verifies)       │
  └──────────────┘              └──────────────────┘
```

**Deliverable:** Four CRDs + controller + updated TTS. Each persona manages their own resources in their own namespace. The controller joins them and surfaces compatibility status.

**Validation:**
- Platform admin creates `TxTokenConfig` with Keycloak IdP. Verify TTS can validate Keycloak tokens.
- Transaction owner creates `TransactionType` in `team-alpha`. Verify TTS uses it to generate TxTokens with correct tctx.
- Service owner creates `ServiceTokenRequirement` in `team-beta`. Verify the ext auth adapter rejects TxTokens missing required tctx fields.
- Security admin creates `TokenPolicy` with `maxTokenLifetime: 10s`. Transaction owner creates a `TransactionType` with `tokenLifetime: 30s`. Verify the controller marks it `PolicyCompliant: False` and the TTS clamps to 10s.
- Verify cross-namespace compatibility status: TransactionType produces all fields that ServiceTokenRequirement requires → `compatible: true`.
- Remove a `tctxEnrichment` from the TransactionType so it no longer produces `classification`. Verify the controller updates both resources' status to `compatible: false` with a clear message.

---

### Step 4: AgentGateway + Ext Auth — Transparent TxToken Enforcement

**What:** Deploy AgentGateway as a per-namespace proxy that transparently handles TxToken verification (and generation at entry points) via the TxToken Ext Auth Adapter, requiring zero application code changes and no sidecars.

**Why this step:** Steps 1-3 require every service to integrate the verification library into their code. This is a nonstarter for polyglot environments and third-party services. Instead of building a custom sidecar (which adds per-pod overhead, requires init containers with `NET_ADMIN`, and conflicts with service meshes), we use **AgentGateway** — a Rust-based, AI-native proxy that:
- Runs per-namespace (not per-pod) via the Kubernetes Gateway API
- Uses the standard Envoy ext_authz gRPC proto for TxToken logic
- Works standalone (its own controller) OR managed by Istiod (`istio-agentgateway` GatewayClass, [istio/istio#59209](https://github.com/istio/istio/issues/59209), merged)
- Natively understands MCP, A2A, and HTTP — enabling protocol-aware TxToken handling in future steps
- In Istio ambient mode, ztunnel handles L4 mTLS while AgentGateway replaces the Envoy waypoint at L7

**Technical scope:**

1. **TxToken Ext Auth Adapter** — a gRPC service implementing the [Envoy ext_authz v3 proto](https://github.com/envoyproxy/envoy/blob/main/api/envoy/service/auth/v3/external_auth.proto):
   - **Generation mode** (for namespaces with `TransactionType` CRDs):
     1. Receives `CheckRequest` from AgentGateway with inbound request headers and source identity (pod SA from connection metadata)
     2. Matches path+method against `TransactionType` generation rules
     3. Determines the subject token:
        - **External traffic (has `Authorization` header):** Extracts OAuth access token as subject token
        - **Internal traffic (no `Authorization` header):** The adapter resolves the source workload's identity from the `CheckRequest` metadata — `source.principal` (SPIFFE URI from mTLS in Istio ambient mode) or `source.address` (pod IP → pod informer cache → SA in standalone mode). It passes this identity to the TTS as the subject token. Host network pods are out of scope (see Step 5).
     4. Calls TTS to exchange subject token → TxToken
     5. Returns `OkHttpResponse` with `Txn-Token` header injected (and `Authorization` optionally removed for external traffic)
   - **Verification mode** (for downstream service namespaces):
     1. Receives `CheckRequest` from AgentGateway
     2. Extracts `Txn-Token` header
     3. Verifies TxToken JWT (signature, expiration, audience)
     4. Checks `ServiceTokenRequirement` rules (required scope, required tctx fields, CEL rules)
     5. Returns `OkHttpResponse` (pass) or `DeniedHttpResponse` with 401 + error message
   - Mode is determined by which rules the controller pushes to the adapter for each namespace

2. **AgentGateway deployment** (standalone mode for POC):
   ```yaml
   # GatewayClass (cluster-scoped, installed with AgentGateway Helm chart)
   apiVersion: gateway.networking.k8s.io/v1
   kind: GatewayClass
   metadata:
     name: agentgateway
   spec:
     controllerName: agentgateway.dev/controller
   ---
   # Gateway per namespace
   apiVersion: gateway.networking.k8s.io/v1
   kind: Gateway
   metadata:
     name: team-beta-gateway
     namespace: team-beta
   spec:
     gatewayClassName: agentgateway
     listeners:
       - name: http
         port: 80
         protocol: HTTP
   ---
   # Attach ext auth policy
   apiVersion: agentgateway.dev/v1alpha1
   kind: AgentgatewayPolicy
   metadata:
     name: txtoken-verification
     namespace: team-beta
   spec:
     targetRefs:
       - group: gateway.networking.k8s.io
         kind: Gateway
         name: team-beta-gateway
     extAuth:
       backendRef:
         name: txtoken-ext-auth-adapter
         namespace: platform-system
         port: 9000
       grpc: {}
   ```

3. **Istio ambient mode** (alternative deployment):
   ```yaml
   # Same AgentGateway proxy, but managed by Istiod
   apiVersion: gateway.networking.k8s.io/v1
   kind: Gateway
   metadata:
     name: team-beta-gateway
     namespace: team-beta
   spec:
     gatewayClassName: istio-agentgateway    # Istiod manages this
     listeners:
       - name: http
         port: 80
         protocol: HTTP
   ---
   # Istio AuthorizationPolicy for ext auth
   apiVersion: security.istio.io/v1
   kind: AuthorizationPolicy
   metadata:
     name: txtoken-verification
     namespace: team-beta
   spec:
     targetRefs:
       - kind: Gateway
         group: gateway.networking.k8s.io
         name: team-beta-gateway
     action: CUSTOM
     provider:
       name: txtoken-ext-auth
     rules:
       - to:
         - operation:
             paths: ["/api/*"]
   ```
   In this mode, ztunnel handles L4 mTLS between pods, and AgentGateway (as `istio-agentgateway` waypoint) handles L7 + TxToken via ext_authz. Traffic flow: `Pod → ztunnel → HBONE → AgentGateway → ext_authz → TTS`.

4. **No sidecars, no init containers, no webhooks:**
   - AgentGateway is deployed as a regular Deployment per namespace (or shared across namespaces)
   - Traffic routing is handled by the Gateway API — services register via HTTPRoute
   - No pod modifications, no mutating webhooks, no `NET_ADMIN`, no iptables
   - Pods are completely unaware of TxTokens — the gateway handles everything

5. **Metrics and observability:**
   - Ext Auth Adapter exposes Prometheus metrics:
     - `txtoken_generation_total{result="issued|denied", namespace="...", endpoint="..."}`
     - `txtoken_verification_total{result="valid|invalid|missing|excluded", namespace="...", endpoint="..."}`
     - `txtoken_verification_latency_seconds{...}`
   - AgentGateway provides its own access logging, tracing, and metrics for all proxied traffic
   - Structured JSON logs with `txn`, `sub`, verification/generation result

**Deliverable:** TxToken Ext Auth Adapter (gRPC service) + AgentGateway deployment configs for both standalone and Istio-managed modes. Services behind the gateway automatically get TxToken generation/verification without code changes or sidecars.

**Validation:**
- **Standalone:** Deploy the 3-service demo with AgentGateway (standalone mode) + ext auth adapter. Send a request with an OIDC AT. Verify TxToken is generated at entry, verified at each downstream hop, with zero application code changes.
- **Istio ambient:** Deploy the same demo with `istio-agentgateway` GatewayClass. Verify the same ext auth adapter works unchanged under Istio's control plane.
- Send a request with a tampered TxToken. Verify the ext auth adapter rejects it with a 401.
- Check Prometheus metrics for generation/verification counts and latency.

---

### Step 5: Internal Workload Identity Resolution

**What:** Enable the ext auth adapter to handle internal workloads (CronJobs, event-driven agents, batch pipelines) that have no external user and no OAuth access token — by resolving the calling pod's identity from the `CheckRequest` metadata provided by AgentGateway.

**Why this step:** Step 4 handles external traffic that arrives with an OAuth access token. But internal workloads initiate transactions autonomously — they have no browser, no OAuth login, no `Authorization` header. These workloads still flow through AgentGateway (same as external traffic), but the ext auth adapter needs a mechanism to determine the caller's identity without an OAuth token. The identity is available in the `CheckRequest` — we just need to extract it.

**Technical scope:**

1. **Identity resolution from `CheckRequest`:**

   The Envoy ext_authz `CheckRequest.attributes.source` contains identity information that varies by deployment mode:

   **Istio ambient mode** — cryptographically authenticated identity:
   - `source.principal`: SPIFFE URI from mTLS peer certificate (e.g., `spiffe://cluster.local/ns/team-alpha/sa/nightly-sales-agent`)
   - ztunnel establishes per-pod mTLS with SPIFFE certs → AgentGateway terminates TLS → extracts URI SAN as principal
   - The adapter parses the SPIFFE URI to extract namespace and service account directly — no K8s API call needed
   - This is tamper-proof: the identity comes from the TLS certificate, verified during the handshake

   **Standalone mode** — network-level identity:
   - `source.principal`: empty (no mTLS between pods)
   - `source.address`: pod IP and port
   - The adapter resolves: pod IP → pod (via local informer cache) → `pod.spec.serviceAccountName`
   - No K8s API call on the hot path — the informer cache is populated at startup and kept in sync via watches
   - Trustworthy within the cluster: pod IPs are unique per pod in standard CNI configurations. Relies on network isolation, not cryptographic proof.

2. **Internal workload flow through AgentGateway:**
   - Internal workloads make normal HTTP calls to downstream services. Their traffic flows through the namespace's AgentGateway.
   - The ext auth adapter receives the `CheckRequest`, detects no `Authorization` header, and resolves the source identity using the mechanism above.
   - It passes the resolved identity (namespace + SA) to the TTS as both `sub` and `req_wl`. The TTS sets `rctx.authn: "kubernetes-sa"` to distinguish from user-delegated transactions.
   - The TTS issues a TxToken. The adapter returns `OkHttpResponse` with the `Txn-Token` header injected.
   - **The pod does nothing special** — it makes a normal HTTP call and gets a TxToken transparently.

3. **Agent controller orchestrating a multi-agent workflow:**

   A controller orchestrating a workflow is just another internal workload on the data path. It calls downstream agents, tools, and services over HTTP/MCP/A2A — all application-level traffic flowing through AgentGateway. Example:

   ```
   Controller Pod                Agent B Pod              MCP Tool Pod           Storage Service Pod
   (ns: orchestration)           (ns: team-alpha)         (ns: team-alpha)       (ns: team-beta)
        │                             │                        │                       │
        │  HTTP: /api/v1/analyze      │                        │                       │
        ├────── AgentGateway ────────►│                        │                       │
        │  (gen: TxToken injected)    │                        │                       │
        │  sub=controller-sa          │  MCP: tools/csv-parse  │                       │
        │  tctx={workflow:            │├──── AgentGateway ────►│                       │
        │    daily-analysis,          ││ (verify ✓, forward)   │                       │
        │    dataset: ds-1}           ││                       │  HTTP: /datasets/ds-1 │
        │                             ││                       ├──── AgentGateway ────►│
        │                             ││                       │  (verify ✓, forward)  │
        │                             ││                       │                       │
        │◄────────────────────────────┘│◄──────────────────────┘◄──────────────────────┘
                                 same TxToken propagated through entire chain
   ```

   - The controller makes a normal HTTP call to Agent B. AgentGateway intercepts, the ext auth adapter generates a TxToken (with the controller's SA as `sub` and workflow context in `tctx`), and injects the `Txn-Token` header.
   - Agent B receives the request with the TxToken. When it calls the MCP tool, it forwards the `Txn-Token` header. The tool's AgentGateway verifies it.
   - The MCP tool calls the storage service, forwarding the same `Txn-Token`. The storage service's AgentGateway verifies it.
   - **The TxToken propagates unmodified through the entire chain.** Every hop sees the same `txn`, `sub`, and `tctx`. The controller doesn't do anything special — it makes a normal HTTP call.
   - The `sub` accurately reflects who initiated the workflow (the controller). The `tctx` carries the workflow context (which dataset, what operation, which target agent).

4. **Host network pods — out of scope:**
   - Host network pods (CNI plugins, kube-proxy, GPU device plugins, CSI drivers, monitoring agents) are infrastructure components that talk to the K8s API, kubelet, or dedicated backends.
   - They don't participate in multi-hop application service chains (Agent → Tool → Service) and don't need TxTokens.
   - TxTokens are scoped to application workloads running in standard pod network namespaces.

5. **MCP/A2A protocol-aware TxToken generation (future-ready):**
   - AgentGateway natively understands MCP and A2A protocols. In future steps, the ext auth adapter can extract tctx fields from MCP tool calls (e.g., tool name, resource URI) or A2A task requests (e.g., task type, agent card) — not just from HTTP headers/body.
   - This is unique to AgentGateway and not possible with generic Envoy proxies, which treat MCP/A2A as opaque HTTP.

**Trust model:**
- **Ambient mode**: Identity is cryptographically authenticated via mTLS. The SPIFFE URI in `source.principal` is extracted from the peer certificate's URI SAN, verified during the TLS handshake. Tamper-proof.
- **Standalone mode**: Identity is derived from network-level source IP → pod mapping via informer cache. Trustworthy within the cluster network (pod IPs are unique per pod). Not cryptographically authenticated — relies on network isolation.
- **TTS trusts the adapter**: The adapter authenticates to the TTS with its own SA token. The TTS validates the adapter is a registered caller (via `TxTokenConfig`).
- The trust model follows the principle of bounded, auditable, least-privilege identity resolution — the adapter can only identify pods whose traffic routes through its AgentGateway (scoped by namespace/gateway routing), and every resolution is logged.

**Deliverable:** Identity resolution in the ext auth adapter (SPIFFE principal parsing + pod IP informer cache). TTS support for `kubernetes-sa` subject token type. Demo of internal CronJob agent getting TxTokens transparently via AgentGateway.

**Validation:**
- Deploy an internal CronJob agent with no external access token. Verify it makes a normal HTTP call, the traffic flows through AgentGateway, the ext auth adapter resolves its identity, and the TxToken has the agent's SA as `sub` with `rctx.authn: "kubernetes-sa"`.
- Verify the downstream service's AgentGateway ext auth adapter correctly verifies the TxToken.
- Deploy a controller that calls Agent B (HTTP), which calls an MCP tool, which calls a storage service. Verify the same TxToken (same `txn`, same `sub` = controller's SA) propagates through all hops across namespace boundaries.
- In standalone mode: verify source IP → pod → SA resolution works via informer cache.
- In Istio ambient mode: verify `source.principal` (SPIFFE URI) is parsed correctly.

---

### Step 6: Scope Narrowing + Authorization Policy Integration

**What:** Implement token replacement (re-exchange for a narrower-scoped TxToken at intermediate hops) and implement CEL-based issuance and verification policy evaluation.

**Why this step:** Steps 1-5 propagate the same TxToken unmodified through the chain. This works for simple chains but doesn't enforce **least privilege at each hop**. In a real agent workflow, the entry point may have `read:datasets write:reports execute:analysis` scope, but the storage service should only see `read:datasets`. This step adds the ability for intermediate services to request a **replacement TxToken** with narrower scope, and for the TTS to consult an external policy engine before issuing tokens.

**Technical scope:**

1. **Token replacement at intermediate hops:**
   - An intermediate service can call the TTS with the current TxToken as the `subject_token` (type `txn_token`) and request a new TxToken with narrower scope.
   - The TTS:
     1. Validates the incoming TxToken
     2. Verifies the requested scope is a **subset** of the current scope (never expands)
     3. **Preserves the `txn` claim** (same transaction ID)
     4. Issues a new TxToken with the narrower scope
   - The `req_wl` claim updates to the intermediate service's identity.

2. **Per-service scope policies via `ServiceTokenRequirement`:**

   The `ServiceTokenRequirement` CRD already supports `requiredScope` and CEL verification rules. In this step, the ext auth adapter uses these to trigger automatic scope narrowing:

   ```yaml
   # Service owner in team-beta defines:
   apiVersion: kontxt.io/v1alpha1
   kind: ServiceTokenRequirement
   metadata:
     name: storage-svc-reqs
     namespace: team-beta
   spec:
     serviceRef:
       name: storage-service
     verification:
       requiredScope: "read:datasets"          # only needs read
       requiredTctxFields: ["datasetId"]
       rules:
         - name: "public-only"
           cel: "txtoken.tctx.classification == 'public'"
           message: "Storage service only handles public data"
     # When inbound TxToken has broader scope, automatically narrow it
     autoNarrow: true
   ```

   - If `autoNarrow: true` and the inbound TxToken has `scope: "read:datasets execute:analysis"`, the ext auth adapter calls the TTS to exchange for a replacement token with `scope: "read:datasets"` before returning `OkHttpResponse` with the narrowed `Txn-Token` header.
   - The service owner controls what scope their service operates with — no coordination with the transaction owner needed.

3. **CEL issuance rules in `TokenPolicy`:**

   The `TokenPolicy` CRD's `issuanceRules` are evaluated by the TTS on every token exchange request. In Step 3, we defined the CRD schema; in this step, we implement the runtime evaluation:

   - The TTS compiles all applicable CEL issuance rules at startup and on `TokenPolicy` changes.
   - On each token exchange request, after building `tctx` and `rctx`, the TTS evaluates every applicable issuance rule.
   - If any rule evaluates to `false`, the TTS refuses to issue the TxToken (HTTP 403) with the rule's `message`.
   - CEL variables available to issuance rules: `subject`, `scope`, `tctx`, `rctx`, `workload`, `namespace`.

   **Example policies expressed as CEL:**

   ```yaml
   # "Only data-science agents can analyze PII datasets"
   - name: "pii-data-science-only"
     cel: >
       tctx.classification != 'pii' || workload.labels['team'] == 'data-science'

   # "PII access requires an approval ticket in tctx"
   - name: "pii-requires-approval"
     cel: >
       tctx.classification != 'pii' || has(tctx.approval_ticket)

   # "No tokens with write scope outside business hours"
   - name: "write-business-hours-only"
     cel: >
       !scope.contains('write:') ||
       (timestamp(now).getHours() >= 8 && timestamp(now).getHours() <= 18)
   ```

   **For cases CEL can't handle** (external data lookups, complex organizational policies), the `accessEvaluationWebhook` in `TokenPolicy` provides an escape hatch. The webhook receives the same variables as CEL and returns allow/deny. It's opt-in and configured with a `failurePolicy` (Deny or Allow on webhook failure).

**Deliverable:** Token replacement support in the TTS, auto-narrowing in the ext auth adapter (driven by `ServiceTokenRequirement`), CEL-based issuance policy evaluation (driven by `TokenPolicy`), optional webhook escape hatch.

**Validation:**
- Send a request through the chain where Service B requests a scope-narrowed TxToken before calling Service C. Verify Service C receives a token with only `read:datasets` scope while Service A had `read:datasets execute:analysis`.
- Verify the `txn` claim is preserved across the replacement.
- Add a CEL issuance rule blocking PII access. Send a request for a PII dataset. Verify the TTS refuses to issue a TxToken with the rule's message.
- Add a CEL verification rule on `ServiceTokenRequirement`. Send a TxToken that violates it. Verify the ext auth adapter rejects with the rule's message.

---

## Summary

| Step | What | Depends On | Key Outcome | Est. Effort |
|------|------|------------|-------------|-------------|
| 1 | Minimal TTS | — | Core token exchange with pluggable IdP | 1.5 weeks |
| 2 | Verification library + demo | Step 1 | End-to-end 3-service chain validation | 1 week |
| 3 | CRDs + controller (4 CRDs, persona-aligned) | Steps 1-2 | Declarative, multi-tenant-safe configuration | 2 weeks |
| 4 | AgentGateway + ext auth adapter | Steps 1-3 | Zero-code-change generation + verification, no sidecars | 2 weeks |
| 5 | Internal workload identity resolution | Steps 1-4 | Transparent identity for autonomous agents via SPIFFE/IP resolution | 1 week |
| 6 | Scope narrowing + CEL policy | Steps 1-5 | Least privilege + inline policy enforcement | 1.5 weeks |

**Total: ~9 weeks for 1-2 engineers, with each step independently demo-able.**

Each step produces a working system that's strictly more capable than the previous:

```
Step 1: "I can issue TxTokens"
Step 2: "I can verify TxTokens across a service chain"
Step 3: "Each persona manages their own config via CRDs in their own namespace"
Step 4: "AgentGateway handles generation + verification transparently — no sidecars"
Step 5: "Internal agents get TxTokens transparently via SPIFFE or IP identity resolution"
Step 6: "Each hop has least-privilege scope and external policy enforcement"
```

---

## Design Principles

1. **IdP-agnostic.** The TTS validates subject tokens via standard OIDC discovery. Any OIDC-compliant IdP works out of the box. Adding a new IdP type is implementing one Go interface.

2. **Multi-tenant by design.** CRDs are split by persona and scoped to namespace boundaries. A transaction owner in `team-alpha` cannot modify `team-beta`'s service requirements. Standard Kubernetes RBAC enforces this — no custom authorization layer needed.

3. **Separation of concerns.** Four CRDs, four personas, four RBAC boundaries. Platform admin configures infrastructure. Security admin sets guardrails. Transaction owner defines generation rules. Service owner defines verification requirements. The controller joins them and surfaces mismatches.

4. **Kubernetes-native.** Configuration is CRDs. Policy is CEL. Traffic routing is Gateway API. Rule distribution is ConfigMaps. Operators use `kubectl`, Helm, Kustomize, GitOps. Everything is auditable via the Kubernetes API.

5. **Incremental value.** Each step works independently. You can stop at Step 2 and have a useful library. You can stop at Step 4 and have transparent generation + verification. Each step is demo-able and pitch-able.

6. **Spec-compliant.** We implement draft-ietf-oauth-transaction-tokens-08 faithfully. When the spec reaches RFC, we're already aligned. No proprietary token formats.

7. **Composable with future work.** The TTS's `WorkloadAuthenticator` interface is where SPIFFE integration plugs in. The `TransactionType` CRD is where agent-specific metadata (purpose, capabilities) plugs in. The `TokenPolicy` CRD's `accessEvaluationWebhook` is where Entra Conditional Access could plug in. None of these are blocked by building the foundation IdP-agnostic.

8. **AgentGateway as unified data plane.** One data plane proxy across all deployment models — standalone (AgentGateway's built-in controller), Istio ambient (`istio-agentgateway` GatewayClass via [istio/istio#59209](https://github.com/istio/istio/issues/59209)), or Istio sidecar mode. The TxToken Ext Auth Adapter implements the standard Envoy ext_authz v3 gRPC proto and is portable across all modes. No sidecars, no init containers, no mutating webhooks for pod injection. AgentGateway's native MCP/A2A support enables protocol-aware TxToken handling that generic Envoy proxies cannot provide.

9. **Sidecar-less by default.** No per-pod sidecars anywhere. AgentGateway runs per-namespace (not per-pod). All traffic — external and internal — flows through AgentGateway. The ext auth adapter resolves internal workload identity from the `CheckRequest` metadata: SPIFFE principal (ambient mode) or source IP → pod informer cache (standalone mode). Pods make normal HTTP calls — they don't interact with the TTS or manage any token lifecycle. Host network pods are out of scope (infrastructure components, not application workloads).

---

## What This Doesn't Cover (Yet)

- **Agent identity** (distinct from workload identity) — covered in the broader design doc's POC 2/5.
- **Cross-trust-domain TxTokens** — the spec explicitly confines TxTokens to a single trust domain. Cross-domain requires a separate token exchange at the boundary.
- **Entra-specific features** — Conditional Access, Agent Registry, OBO flows. These are additive integrations, not foundations.
- **Protocol-aware tctx extraction from MCP/A2A** — AgentGateway natively understands MCP and A2A, enabling future extraction of tctx fields from tool calls and agent tasks. The ext auth adapter receives the full request context from AgentGateway, so this is an extension of the adapter, not a new component.
