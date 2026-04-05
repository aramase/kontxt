# Quickstart: kontxt with Standalone AgentGateway

This guide walks through deploying kontxt with standalone AgentGateway on a Kubernetes cluster. By the end, you'll have automated TxToken generation at the gateway entry point and verification at downstream services — with zero code changes in your application.

For a complete working demo with sample agent services, see [examples/agents/](../examples/agents/).

---

## Prerequisites

- A Kubernetes cluster (AKS, GKE, EKS, or any conformant cluster)
- `kubectl` configured to access the cluster
- `helm` v3.x
- A container registry accessible from the cluster (for kontxt images)

## 1. Install Gateway API CRDs

AgentGateway uses the Kubernetes [Gateway API](https://gateway-api.sigs.k8s.io/). Install the CRDs first:

```bash
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml
```

## 2. Install AgentGateway

Deploy the AgentGateway control plane using Helm:

```bash
# Install AgentGateway CRDs
helm upgrade -i agentgateway-crds oci://cr.agentgateway.dev/charts/agentgateway-crds \
  --create-namespace --namespace agentgateway-system \
  --version v1.0.1

# Install AgentGateway control plane
helm upgrade -i agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --namespace agentgateway-system \
  --version v1.0.1 \
  --wait
```

Verify the control plane is running:

```bash
kubectl get pods -n agentgateway-system
# NAME                            READY   STATUS    AGE
# agentgateway-5495d98459-46dpk   1/1     Running   30s
```

## 3. Install kontxt

Install kontxt platform components (TTS, ext auth adapter, controller). Helm automatically installs the CRDs from the chart's `crds/` directory:

```bash
helm upgrade -i kontxt deploy/helm/kontxt \
  --create-namespace --namespace kontxt-system \
  --set tts.config.trustDomain=my-cluster.example.com \
  --set tts.config.issuer=https://kontxt-tts.kontxt-system.svc.cluster.local \
  --wait
```

Verify all components are running:

```bash
kubectl get pods -n kontxt-system
# NAME                                  READY   STATUS    AGE
# kontxt-tts-...                        1/1     Running   30s
# kontxt-extauth-...                    1/1     Running   30s
# kontxt-controller-...                 1/1     Running   30s
```

## 4. Create a Gateway

Create an AgentGateway proxy that routes traffic to your services:

```yaml
# gateway.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: agentgateway-proxy
  namespace: agentgateway-system
spec:
  gatewayClassName: agentgateway
  listeners:
    - protocol: HTTP
      port: 80
      name: http
      allowedRoutes:
        namespaces:
          from: All
```

```bash
kubectl apply -f gateway.yaml
```

Wait for the gateway to get an external address:

```bash
kubectl get gateway agentgateway-proxy -n agentgateway-system
# NAME                 CLASS          ADDRESS         PROGRAMMED   AGE
# agentgateway-proxy   agentgateway   <external-ip>   True         2m
```

## 5. Configure kontxt CRDs

### Platform configuration (TxTokenConfig)

Tell the TTS which identity providers to trust and how to map their claims:

```yaml
# txtoken-config.yaml
apiVersion: kontxt.io/v1alpha1
kind: TxTokenConfig
metadata:
  name: cluster-config
spec:
  trustDomain: my-cluster.example.com
  issuer: https://kontxt-tts.kontxt-system.svc.cluster.local
  subjectTokens:
    - issuer:
        url: "https://your-idp.example.com"
        audiences: ["your-app-id"]
      claimMappings:
        subject:
          claim: "email"
  defaults:
    tokenLifetime: "15s"
```

### Transaction definition (TransactionType)

Define what happens when a request hits your entry-point endpoint — what purpose, scope, and `tctx` fields the TxToken should carry:

```yaml
# transaction-type.yaml
apiVersion: kontxt.io/v1alpha1
kind: TransactionType
metadata:
  name: my-transaction
  namespace: my-app
spec:
  endpoint:
    path: "/api/my-endpoint"
    method: "POST"
  purpose: "my-operation"
  scope: "read:data write:data"
  tctxMapping:
    resourceId:
      source: body
      field: "resourceId"
      required: true
  tokenLifetime: "15s"
```

### Service verification (ServiceTokenRequirement)

Define what your downstream service requires from incoming TxTokens:

```yaml
# service-token-requirement.yaml
apiVersion: kontxt.io/v1alpha1
kind: ServiceTokenRequirement
metadata:
  name: my-downstream-service
  namespace: my-app
spec:
  serviceRef:
    name: my-downstream-service
  verification:
    requiredScope: "read:data"
    requiredTctxFields:
      - "resourceId"
  excludedEndpoints:
    - path: "/healthz"
      method: "GET"
```

### Security guardrails (TokenPolicy)

Set cluster-wide constraints on all TxTokens:

```yaml
# token-policy.yaml
apiVersion: kontxt.io/v1alpha1
kind: TokenPolicy
metadata:
  name: default-policy
spec:
  constraints:
    maxTokenLifetime: "30s"
    mandatoryTctxFields:
      - "purpose"
```

Apply all CRD instances:

```bash
kubectl apply -f txtoken-config.yaml
kubectl apply -f transaction-type.yaml
kubectl apply -f service-token-requirement.yaml
kubectl apply -f token-policy.yaml
```

The kontxt controller will reconcile these into ConfigMaps that the ext auth adapter picks up automatically.

## 6. Create HTTPRoutes and ext_authz policies

Route traffic through the gateway and attach kontxt ext auth:

```yaml
# routes.yaml
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: entry-route
  namespace: my-app
spec:
  parentRefs:
    - name: agentgateway-proxy
      namespace: agentgateway-system
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api/my-endpoint
      backendRefs:
        - name: my-entry-service
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: downstream-route
  namespace: my-app
spec:
  parentRefs:
    - name: agentgateway-proxy
      namespace: agentgateway-system
  rules:
    - matches:
        - path:
            type: PathPrefix
            value: /api/downstream
      backendRefs:
        - name: my-downstream-service
          port: 8080
```

Attach ext_authz policies — **generation** for the entry route, **verification** for downstream:

```yaml
# ext-auth-policies.yaml

# Generate TxToken at the entry point
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: txtoken-generate
  namespace: my-app
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: entry-route
  traffic:
    extAuth:
      backendRef:
        name: kontxt-extauth-generate
        namespace: kontxt-system
        port: 9000
      grpc: {}

---
# Verify TxToken at downstream services
apiVersion: agentgateway.dev/v1alpha1
kind: AgentgatewayPolicy
metadata:
  name: txtoken-verify
  namespace: my-app
spec:
  targetRefs:
    - group: gateway.networking.k8s.io
      kind: HTTPRoute
      name: downstream-route
  traffic:
    extAuth:
      backendRef:
        name: kontxt-extauth
        namespace: kontxt-system
        port: 9000
      grpc: {}
```

```bash
kubectl apply -f routes.yaml
kubectl apply -f ext-auth-policies.yaml
```

## 7. Test the flow

Get the gateway's external address:

```bash
export GW_ADDRESS=$(kubectl get gateway agentgateway-proxy -n agentgateway-system \
  -o jsonpath='{.status.addresses[0].value}')
```

Send a request with an OAuth access token:

```bash
curl -v -H "Authorization: Bearer $ACCESS_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"resourceId": "res-1234"}' \
     http://$GW_ADDRESS/api/my-endpoint
```

What happens:
1. AgentGateway matches the route and calls the **generation** ext auth adapter
2. The adapter exchanges the OAuth access token for a TxToken via the TTS
3. The TxToken is injected as a `Txn-Token` header into the request
4. Your entry service receives the request with the TxToken
5. When your service calls the downstream endpoint, AgentGateway calls the **verification** ext auth adapter
6. The adapter verifies the TxToken (signature, expiration, required scope, required `tctx` fields)
7. The downstream service receives the verified request

Check the ext auth adapter logs to see the flow:

```bash
# Generation logs
kubectl logs -n kontxt-system -l app.kubernetes.io/name=kontxt-extauth-generate

# Verification logs
kubectl logs -n kontxt-system -l app.kubernetes.io/name=kontxt-extauth
```

## Next steps

- **Run the full demo:** See [examples/agents/](../examples/agents/) for a deployable 3-service AI Research Assistant demo with mock IdP
- **Understand the concepts:** See [docs/concepts.md](concepts.md) for deep dives on `tctx`/`rctx`, persona ownership, scope narrowing, and pluggable IdPs
- **Review the spec:** kontxt implements [draft-ietf-oauth-transaction-tokens-08](https://datatracker.ietf.org/doc/draft-ietf-oauth-transaction-tokens/)

## Cleanup

```bash
# Remove ext auth policies and routes
kubectl delete -f ext-auth-policies.yaml
kubectl delete -f routes.yaml

# Remove CRD instances
kubectl delete -f token-policy.yaml
kubectl delete -f service-token-requirement.yaml
kubectl delete -f transaction-type.yaml
kubectl delete -f txtoken-config.yaml

# Uninstall kontxt (note: Helm does not delete CRDs on uninstall)
helm uninstall kontxt -n kontxt-system
kubectl delete -f deploy/helm/kontxt/crds/

# Uninstall AgentGateway
kubectl delete gateway agentgateway-proxy -n agentgateway-system
helm uninstall agentgateway agentgateway-crds -n agentgateway-system

# Remove Gateway API CRDs
kubectl delete -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml
```
