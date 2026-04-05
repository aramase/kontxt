# AI Research Assistant Demo

An end-to-end demo of kontxt Transaction Tokens with AgentGateway, showing automated TxToken generation and verification across a 3-service agent pipeline.

## Architecture

```
                            ┌─────────────────────────────────────────────────────┐
                            │  AgentGateway                                       │
                            │                                                     │
  User ──── Bearer AT ────▶ │  /api/research ──ext_authz(generate)──▶ orchestrator│
                            │                                            │   │    │
                            │  /api/retrieve ──ext_authz(verify)───▶ retriever    │
                            │                                            │        │
                            │  /api/analyze  ──ext_authz(verify)───▶ analyzer     │
                            │                                                     │
                            │  /idp/*  ─────────────────────────▶  mock-idp       │
                            └─────────────────────────────────────────────────────┘
```

**Flow:**
1. Client obtains an OAuth access token from the mock IdP (`/idp/token`)
2. Client sends `POST /api/research` with the access token
3. AgentGateway calls kontxt ext auth (generate mode) → exchanges AT for a TxToken via the TTS
4. Orchestrator receives the request with a `Txn-Token` header, calls retriever and analyzer
5. AgentGateway calls kontxt ext auth (verify mode) on downstream routes → validates the TxToken
6. All services see the same `txn` (transaction ID), `sub` (user), and `tctx` (context)

## Prerequisites

- A Kubernetes cluster (AKS, GKE, EKS)
- `kubectl`, `helm`, `docker`, `jq`
- An Azure Container Registry (or modify `setup.sh` for your registry)

## Quick Start

```bash
export ACR_NAME=myregistry   # your ACR name (without .azurecr.io)
./setup.sh
```

The script will:
1. Build and push all images to your ACR
2. Install Gateway API CRDs and AgentGateway
3. Install kontxt (TTS, ext auth, controller)
4. Deploy a second ext auth adapter in generate mode
5. Deploy the demo services (mock-idp, orchestrator, retriever, analyzer)
6. Apply kontxt CRD instances (TxTokenConfig, TransactionType, ServiceTokenRequirements, TokenPolicy)
7. Create the Gateway, HTTPRoutes, and AgentgatewayPolicies
8. Print the gateway address and example curl commands

## Manual Walkthrough

Once `setup.sh` completes, get the gateway address:

```bash
export GW=$(kubectl get gateway demo-gateway -n demo -o jsonpath='{.status.addresses[0].value}')
```

### Step 1: Get an access token

```bash
TOKEN=$(curl -s http://$GW/idp/token \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","scope":"read:docs analyze:data"}' | jq -r .access_token)
```

### Step 2: Send a research request

```bash
curl -s http://$GW/api/research \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"company":"ACME","period":"Q3-2024","question":"Summarize earnings"}' | jq .
```

Expected response:

```json
{
  "company": "ACME",
  "period": "Q3-2024",
  "question": "Summarize earnings",
  "documents": [
    "ACME Annual Report 2024 - Revenue grew 15% YoY to $4.2B",
    "ACME Q3 Earnings Call Transcript - CEO highlighted strong cloud growth",
    "ACME SEC Filing 10-K - Operating margins expanded to 22%"
  ],
  "analysis": "Based on 3 documents for ACME (Q3-2024): Revenue grew 15% YoY driven by cloud expansion. Operating margins improved to 22%. Management guidance suggests continued momentum into next quarter with expected 12-15% growth."
}
```

### Step 3: Examine logs for TxToken propagation

```bash
# All three services should log the same txn (transaction ID)
kubectl logs -n demo -l app=retriever --tail=5
# [retriever] txn=abc-123 sub=alice@example.com scope=read:docs analyze:data tctx={"company":"ACME","period":"Q3-2024","purpose":"earnings-analysis"}

kubectl logs -n demo -l app=analyzer --tail=5
# [analyzer] txn=abc-123 sub=alice@example.com scope=read:docs analyze:data tctx={"company":"ACME","period":"Q3-2024","purpose":"earnings-analysis"}
```

The `txn` value is identical across all services — that's the TxToken providing end-to-end transaction correlation.

## Negative Test Cases

### Missing authorization

```bash
curl -s -w "\n%{http_code}\n" http://$GW/api/research \
  -H 'Content-Type: application/json' \
  -d '{"company":"ACME","period":"Q3-2024","question":"test"}'
# 401 — no access token, ext auth rejects
```

### Expired or invalid token

```bash
curl -s -w "\n%{http_code}\n" http://$GW/api/research \
  -H "Authorization: Bearer invalid-token" \
  -H 'Content-Type: application/json' \
  -d '{"company":"ACME","period":"Q3-2024","question":"test"}'
# 401 — invalid AT, TTS rejects the exchange
```

## What's Happening Under the Hood

| Component | CRD | Purpose |
|-----------|-----|---------|
| `TxTokenConfig` | `demo-config` | Configures TTS: trust domain, issuer, mock IdP as subject token authenticator |
| `TransactionType` | `earnings-research` | Maps `POST /api/research` → TxToken with purpose `earnings-analysis`, scope `read:docs analyze:data`, tctx fields `company`+`period` |
| `ServiceTokenRequirement` | `retriever` | Requires scope `read:docs` and tctx field `company` |
| `ServiceTokenRequirement` | `analyzer` | Requires scope `analyze:data` and tctx fields `company`+`period` |
| `TokenPolicy` | `demo-policy` | Enforces max lifetime 30s and mandatory tctx field `purpose` |

The kontxt controller reconciles these CRDs into ConfigMaps (`kontxt-generation-rules`, `kontxt-verification-rules`). The ext auth adapters watch these ConfigMaps via fsnotify and apply the rules automatically.

## Cleanup

```bash
# Remove demo resources
kubectl delete -f examples/agents/manifests/gateway.yaml
kubectl delete -f examples/agents/manifests/kontxt-platform.yaml
kubectl delete -f examples/agents/manifests/services.yaml
kubectl delete -f examples/agents/manifests/ext-auth-generate.yaml
kubectl delete -f examples/agents/manifests/namespace.yaml

# Uninstall kontxt
helm uninstall kontxt -n kontxt-system
kubectl delete -f deploy/helm/kontxt/crds/

# Uninstall AgentGateway
helm uninstall agentgateway agentgateway-crds -n agentgateway-system

# Remove Gateway API CRDs
kubectl delete -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml
```
