# AI Research Assistant Demo (Istio Ambient + AgentGateway)

An end-to-end demo of kontxt Transaction Tokens with AgentGateway programmed by istiod, using **Istio ambient mode** and the **Gateway API `ExternalAuth` filter** (GEP-1494).

## Architecture

```
                            ┌─────────────────────────────────────────────────────┐
                            │  AgentGateway (programmed by istiod)                │
                            │                                                     │
  User ──── Bearer AT ────▶ │  /api/research ──ExternalAuth(generate)──▶ orchestr.│
                            │                                            │   │    │
                            │  /api/retrieve ──ExternalAuth(verify)──▶ retriever  │
                            │                                            │        │
                            │  /api/analyze  ──ExternalAuth(verify)──▶ analyzer   │
                            │                                                     │
                            │  /idp/*  ─────────────────────────▶  mock-idp       │
                            └─────────────────────────────────────────────────────┘

  Control plane: istiod (single control plane)
  Data plane: ztunnel (ambient mode — no sidecars)
  Ext auth attachment: HTTPRoute ExternalAuth filter (Gateway API v1.5.0+)
  Protocol: Envoy ext_authz v3 gRPC
```

**Key differences from standalone mode:**
- **Single control plane**: istiod programs the agentgateway proxy (no kgateway controller needed)
- **Ambient mode**: ztunnel provides L4 mTLS — no sidecar injection needed
- **No AgentgatewayPolicy CRDs**: ext auth is configured via inline `ExternalAuth` filters on HTTPRoute rules
- **Gateway API experimental CRDs**: required for the `ExternalAuth` filter type
- **ReferenceGrant**: required for cross-namespace ext auth service references

**Flow:**
1. Client obtains an OAuth access token from the mock IdP (`/idp/token`)
2. Client sends `POST /api/research` with the access token
3. istiod programs the ExternalAuth filter → agentgateway calls kontxt ext auth (generate mode)
4. Ext auth exchanges AT for a TxToken via the TTS, injects `Txn-Token` header
5. Orchestrator receives the request, calls retriever and analyzer
6. ExternalAuth filter on downstream routes calls kontxt ext auth (verify mode) → validates the TxToken
7. All services see the same `txn` (transaction ID), `sub` (user), and `tctx` (context)

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/)
- [kind](https://kind.sigs.k8s.io/docs/user/quick-start/#installation)
- `kubectl`, `helm`, `jq`
- `istioctl` 1.30+ ([download](https://istio.io/latest/docs/setup/getting-started/#download))

## Quick Start

```bash
./setup.sh
```

The script will:
1. Create a kind cluster (or reuse an existing one)
2. Build and load all kontxt images
3. Install Gateway API **experimental** CRDs (required for ExternalAuth filter)
4. Install Istio **ambient profile** with the `PILOT_ENABLE_AGENTGATEWAY=true` feature flag
5. Deploy the demo services (mock-idp, orchestrator, retriever, analyzer)
6. Install kontxt (TTS, ext auth, controller) with `istio.enabled=true`
7. Apply kontxt CRD instances
8. Deploy a second ext auth adapter in generate mode
9. Apply Gateway, HTTPRoutes with ExternalAuth filters, and ReferenceGrant
10. Print port-forward instructions and example curl commands

### Using an existing kind cluster

```bash
KIND_CLUSTER_NAME=my-cluster ./setup.sh
```

## Manual Walkthrough

Once `setup.sh` completes, port-forward to the gateway:

```bash
kubectl port-forward -n demo svc/demo-gateway 8080:80
```

Then in another terminal:

### Step 1: Get an access token

**bash:**
```bash
TOKEN=$(curl -s http://localhost:8080/idp/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","scope":"read:docs analyze:data"}' | jq -r .access_token)
```

**fish:**
```fish
set TOKEN (curl -s http://localhost:8080/idp/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","scope":"read:docs analyze:data"}' | jq -r .access_token)
```

### Step 2: Send a research request

**bash:**
```bash
curl -s http://localhost:8080/api/research \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"company":"ACME","period":"Q3-2024","question":"Summarize earnings"}' | jq .
```

**fish:**
```fish
curl -s http://localhost:8080/api/research \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"company":"ACME","period":"Q3-2024","question":"Summarize earnings"}' | jq .
```

### Step 3: Examine logs for TxToken propagation

```bash
kubectl logs -n demo -l app=retriever --tail=5
kubectl logs -n demo -l app=analyzer --tail=5
```

The `txn` value is identical across all services — that's the TxToken providing end-to-end transaction correlation.

## ExternalAuth Filter Configuration

The ext auth is configured directly on each HTTPRoute rule as a filter, rather than using separate `AgentgatewayPolicy` CRDs:

```yaml
rules:
  - matches:
      - path:
          type: Exact
          value: /api/research
        method: POST
    filters:
      - type: ExternalAuth
        externalAuth:
          protocol: GRPC
          grpc: {}
          backendRef:
            name: kontxt-extauth-generate
            namespace: kontxt-system
            port: 9000
          forwardBody:
            maxSize: 8192
    backendRefs:
      - name: orchestrator
        port: 8081
```

This is a standard Gateway API filter — istiod's agentgateway controller translates it to the appropriate xDS configuration.

## Cleanup

```bash
kind delete cluster --name kontxt-istio-demo
```
