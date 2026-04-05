#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# setup.sh — Deploy the kontxt AI Research Assistant demo
# ============================================================
# Prerequisites: az, kubectl, helm, docker (or az acr build)
#
# Usage:
#   export ACR_NAME=myregistry        # Azure Container Registry name
#   ./setup.sh
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

: "${ACR_NAME:?Set ACR_NAME to your Azure Container Registry name (e.g. myregistry)}"
ACR_LOGIN_SERVER="${ACR_NAME}.azurecr.io"

KONTXT_NS="kontxt-system"
DEMO_NS="demo"

echo "==> ACR: ${ACR_LOGIN_SERVER}"
echo "==> Repo root: ${REPO_ROOT}"
echo ""

# ---- 1. Build and push images ----
echo "==> Logging in to ACR..."
az acr login --name "${ACR_NAME}"

IMAGES=(
  "kontxt-tts:cmd/tts/Dockerfile"
  "kontxt-extauth:cmd/extauth/Dockerfile"
  "kontxt-controller:cmd/controller/Dockerfile"
  "kontxt-mock-idp:examples/agents/mock-idp/Dockerfile"
  "kontxt-orchestrator:examples/agents/orchestrator/Dockerfile"
  "kontxt-retriever:examples/agents/retriever/Dockerfile"
  "kontxt-analyzer:examples/agents/analyzer/Dockerfile"
)

for entry in "${IMAGES[@]}"; do
  IMAGE_NAME="${entry%%:*}"
  DOCKERFILE="${entry##*:}"
  TAG="${ACR_LOGIN_SERVER}/${IMAGE_NAME}:latest"
  echo "==> Building ${IMAGE_NAME}..."
  docker build -t "${TAG}" -f "${REPO_ROOT}/${DOCKERFILE}" "${REPO_ROOT}"
  echo "==> Pushing ${TAG}..."
  docker push "${TAG}"
done

# ---- 2. Install Gateway API CRDs ----
echo "==> Installing Gateway API CRDs..."
kubectl apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml

# ---- 3. Install AgentGateway ----
echo "==> Installing AgentGateway..."
helm upgrade -i agentgateway-crds oci://cr.agentgateway.dev/charts/agentgateway-crds \
  --create-namespace --namespace agentgateway-system \
  --version v1.0.1

helm upgrade -i agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --namespace agentgateway-system \
  --version v1.0.1 \
  --wait

# ---- 4. Install kontxt ----
echo "==> Installing kontxt CRDs and platform..."
helm upgrade -i kontxt "${REPO_ROOT}/deploy/helm/kontxt" \
  --create-namespace --namespace "${KONTXT_NS}" \
  --set tts.config.trustDomain=demo.example.com \
  --set "tts.config.issuer=https://kontxt-tts.${KONTXT_NS}.svc.cluster.local" \
  --set "tts.image.repository=${ACR_LOGIN_SERVER}/kontxt-tts" \
  --set "extauth.image.repository=${ACR_LOGIN_SERVER}/kontxt-extauth" \
  --set "controller.image.repository=${ACR_LOGIN_SERVER}/kontxt-controller" \
  --wait

# ---- 5. Deploy ext auth generate adapter ----
echo "==> Deploying ext auth generate adapter..."
# Patch the image in the manifest to use ACR
sed "s|ghcr.io/aramase/kontxt-extauth:latest|${ACR_LOGIN_SERVER}/kontxt-extauth:latest|g" \
  "${SCRIPT_DIR}/manifests/ext-auth-generate.yaml" | kubectl apply -f -

# ---- 6. Deploy demo services ----
echo "==> Creating demo namespace and services..."
kubectl apply -f "${SCRIPT_DIR}/manifests/namespace.yaml"

# Patch demo service images to use ACR
for svc in mock-idp orchestrator retriever analyzer; do
  sed "s|ghcr.io/aramase/kontxt-${svc}:latest|${ACR_LOGIN_SERVER}/kontxt-${svc}:latest|g" \
    "${SCRIPT_DIR}/manifests/services.yaml"
done | sort -u | kubectl apply -f -

# ---- 7. Apply kontxt CRD instances ----
echo "==> Applying kontxt CRD instances..."
kubectl apply -f "${SCRIPT_DIR}/manifests/kontxt-platform.yaml"

# ---- 8. Apply gateway and routing ----
echo "==> Applying gateway, routes, and ext_authz policies..."
kubectl apply -f "${SCRIPT_DIR}/manifests/gateway.yaml"

# ---- 9. Wait for pods ----
echo "==> Waiting for kontxt-system pods..."
kubectl rollout status deployment/kontxt-tts -n "${KONTXT_NS}" --timeout=120s
kubectl rollout status deployment/kontxt-extauth -n "${KONTXT_NS}" --timeout=120s
kubectl rollout status deployment/kontxt-controller -n "${KONTXT_NS}" --timeout=120s
kubectl rollout status deployment/kontxt-extauth-generate -n "${KONTXT_NS}" --timeout=120s

echo "==> Waiting for demo pods..."
kubectl rollout status deployment/mock-idp -n "${DEMO_NS}" --timeout=120s
kubectl rollout status deployment/orchestrator -n "${DEMO_NS}" --timeout=120s
kubectl rollout status deployment/retriever -n "${DEMO_NS}" --timeout=120s
kubectl rollout status deployment/analyzer -n "${DEMO_NS}" --timeout=120s

# ---- 10. Print gateway address and curl examples ----
echo ""
echo "==> Waiting for gateway address..."
for i in $(seq 1 30); do
  GW_ADDRESS=$(kubectl get gateway demo-gateway -n "${DEMO_NS}" \
    -o jsonpath='{.status.addresses[0].value}' 2>/dev/null || true)
  if [ -n "${GW_ADDRESS}" ]; then
    break
  fi
  sleep 2
done

if [ -z "${GW_ADDRESS:-}" ]; then
  echo "WARNING: Gateway address not yet available. Check: kubectl get gateway demo-gateway -n demo"
  GW_ADDRESS="<pending>"
fi

echo ""
echo "============================================"
echo "  Demo deployed successfully!"
echo "============================================"
echo ""
echo "Gateway address: ${GW_ADDRESS}"
echo ""
echo "1. Get an access token from the mock IdP:"
echo ""
echo "   TOKEN=\$(curl -s http://${GW_ADDRESS}/idp/token \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"email\":\"alice@example.com\",\"scope\":\"read:docs analyze:data\"}' | jq -r .access_token)"
echo ""
echo "2. Send a research request:"
echo ""
echo "   curl -s http://${GW_ADDRESS}/api/research \\"
echo "     -H \"Authorization: Bearer \$TOKEN\" \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"company\":\"ACME\",\"period\":\"Q3-2024\",\"question\":\"Summarize earnings\"}' | jq ."
echo ""
echo "3. Check logs for TxToken propagation:"
echo ""
echo "   kubectl logs -n demo -l app=orchestrator --tail=10"
echo "   kubectl logs -n demo -l app=retriever --tail=10"
echo "   kubectl logs -n demo -l app=analyzer --tail=10"
echo ""
