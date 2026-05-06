#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# setup.sh — Deploy the kontxt AI Research Assistant demo
# ============================================================
# Prerequisites: docker, kind, kubectl, helm
#
# Usage:
#   ./setup.sh                          # creates a new kind cluster
#   KIND_CLUSTER_NAME=my-cluster ./setup.sh  # use an existing cluster
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kontxt-demo}"
KONTXT_NS="kontxt-system"
DEMO_NS="demo"

# Auto-detect Podman vs Docker. Podman stores locally-built images with a
# localhost/ prefix inside kind nodes; Docker does not.
if docker version 2>&1 | grep -ci podman >/dev/null; then
  IMAGE_PREFIX="localhost/"
else
  IMAGE_PREFIX=""
fi

echo "==> Kind cluster: ${KIND_CLUSTER_NAME}"
echo "==> Repo root: ${REPO_ROOT}"
echo "==> Image prefix: '${IMAGE_PREFIX}'"
echo ""

# ---- 1. Create kind cluster (if it doesn't exist) ----
if kind get clusters 2>/dev/null | grep -q "^${KIND_CLUSTER_NAME}$"; then
  echo "==> Kind cluster '${KIND_CLUSTER_NAME}' already exists, reusing"
else
  echo "==> Creating kind cluster '${KIND_CLUSTER_NAME}'..."
  kind create cluster --name "${KIND_CLUSTER_NAME}" --wait 60s
fi

KUBE_CONTEXT="kind-${KIND_CLUSTER_NAME}"

# ---- 2. Build and load images ----
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
  TAG="${IMAGE_NAME}:latest"
  echo "==> Building ${TAG}..."
  docker build -t "${TAG}" -f "${REPO_ROOT}/${DOCKERFILE}" "${REPO_ROOT}"
  echo "==> Loading ${TAG} into kind..."
  kind load docker-image "${TAG}" --name "${KIND_CLUSTER_NAME}"
done

# ---- 3. Install Gateway API CRDs ----
echo "==> Installing Gateway API CRDs..."
kubectl --context "${KUBE_CONTEXT}" apply --server-side --force-conflicts \
  -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.5.0/standard-install.yaml

# ---- 4. Install AgentGateway ----
echo "==> Installing AgentGateway..."
helm upgrade -i agentgateway-crds oci://cr.agentgateway.dev/charts/agentgateway-crds \
  --kube-context "${KUBE_CONTEXT}" \
  --create-namespace --namespace agentgateway-system \
  --version v1.0.1

helm upgrade -i agentgateway oci://cr.agentgateway.dev/charts/agentgateway \
  --kube-context "${KUBE_CONTEXT}" \
  --namespace agentgateway-system \
  --version v1.0.1 \
  --wait

# ---- 5. Deploy demo namespace and services ----
# The mock-idp Service must exist before kontxt installs, so TTS can
# resolve the IdP's OIDC discovery URL on first token exchange.
echo "==> Creating demo namespace and deploying services..."
kubectl --context "${KUBE_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/namespace.yaml"
kubectl --context "${KUBE_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/services.yaml"
if [ -n "${IMAGE_PREFIX}" ]; then
  for dep in mock-idp orchestrator retriever analyzer; do
    kubectl --context "${KUBE_CONTEXT}" -n "${DEMO_NS}" set image "deployment/${dep}" "${dep}=${IMAGE_PREFIX}kontxt-${dep}:latest"
  done
fi

# ---- 6. Install kontxt ----
echo "==> Installing kontxt CRDs and platform..."
helm upgrade -i kontxt "${REPO_ROOT}/deploy/helm/kontxt" \
  --kube-context "${KUBE_CONTEXT}" \
  --namespace "${KONTXT_NS}" \
  -f "${SCRIPT_DIR}/helm-values.yaml" \
  --set "tts.config.issuer=https://kontxt-tts.${KONTXT_NS}.svc.cluster.local" \
  --set "tts.image.repository=${IMAGE_PREFIX}kontxt-tts" \
  --set "tts.image.tag=latest" \
  --set "tts.image.pullPolicy=Never" \
  --set "extauth.image.repository=${IMAGE_PREFIX}kontxt-extauth" \
  --set "extauth.image.tag=latest" \
  --set "extauth.image.pullPolicy=Never" \
  --set "controller.image.repository=${IMAGE_PREFIX}kontxt-controller" \
  --set "controller.image.tag=latest" \
  --set "controller.image.pullPolicy=Never" \
  --wait

# ---- 7. Apply kontxt CRD instances ----
echo "==> Applying kontxt CRD instances..."
kubectl --context "${KUBE_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/kontxt-platform.yaml"

# ---- 8. Wait for controller to reconcile CRDs ----
echo "==> Waiting for controller to reconcile CRDs..."
kubectl --context "${KUBE_CONTEXT}" wait --for=condition=available deployment/kontxt-controller -n "${KONTXT_NS}" --timeout=60s
sleep 3
echo "    controller ready"

# ---- 9. Apply gateway and routing ----
echo "==> Applying gateway, routes, and ext_authz policies..."
kubectl --context "${KUBE_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/gateway.yaml"

# ---- 11. Wait for pods ----
echo "==> Waiting for kontxt-system pods..."
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/kontxt-tts -n "${KONTXT_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/kontxt-extauth -n "${KONTXT_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/kontxt-controller -n "${KONTXT_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/kontxt-extauth-generate -n "${KONTXT_NS}" --timeout=120s

echo "==> Waiting for demo pods..."
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/mock-idp -n "${DEMO_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/orchestrator -n "${DEMO_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/retriever -n "${DEMO_NS}" --timeout=120s
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/analyzer -n "${DEMO_NS}" --timeout=120s

# ---- 11. Print test instructions ----
echo ""
echo "============================================"
echo "  Demo deployed successfully!"
echo "============================================"
echo ""
echo "To test, port-forward to the gateway:"
echo ""
echo "  kubectl --context ${KUBE_CONTEXT} port-forward -n ${DEMO_NS} svc/demo-gateway 8080:80"
echo ""
echo "Then in another terminal:"
echo ""
echo "1. Get an access token from the mock IdP:"
echo ""
echo "   TOKEN=\$(curl -s http://localhost:8080/idp/token \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"email\":\"alice@example.com\",\"scope\":\"read:docs analyze:data\"}' | jq -r .access_token)"
echo ""
echo "2. Send a research request:"
echo ""
echo "   curl -s http://localhost:8080/api/research \\"
echo "     -H \"Authorization: Bearer \$TOKEN\" \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"company\":\"ACME\",\"period\":\"Q3-2024\",\"question\":\"Summarize earnings\"}' | jq ."
echo ""
echo "3. Check logs for TxToken propagation:"
echo ""
echo "   kubectl --context ${KUBE_CONTEXT} logs -n ${DEMO_NS} -l app=retriever --tail=10"
echo "   kubectl --context ${KUBE_CONTEXT} logs -n ${DEMO_NS} -l app=analyzer --tail=10"
echo ""
