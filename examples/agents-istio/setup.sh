#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# setup.sh — Deploy the kontxt AI Research Assistant demo
#             with Istio + AgentGateway (istiod as control plane)
# ============================================================
# Prerequisites: docker, kind, kubectl, helm, go (for building Istio from source)
#
# Usage:
#   ./setup.sh                              # creates a new kind cluster
#   KIND_CLUSTER_NAME=my-cluster ./setup.sh  # use an existing cluster
#   ISTIO_PATH=/path/to/istio ./setup.sh     # skip cloning istio/istio
# ============================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kontxt-istio-demo}"
KONTXT_NS="kontxt-system"
DEMO_NS="demo"
ISTIO_NS="istio-system"

# Allow user to provide an existing Istio checkout.
ISTIO_PATH="${ISTIO_PATH:-}"

# Gateway API version — must be experimental channel for ExternalAuth filter.
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.0}"

# Auto-detect Podman vs Docker.
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

# ---- 2. Build and load kontxt images ----
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

# ---- 3. Install Gateway API experimental CRDs ----
# ExternalAuth filter requires the experimental channel CRDs.
echo "==> Installing Gateway API experimental CRDs (${GATEWAY_API_VERSION})..."
kubectl --context "${KUBE_CONTEXT}" apply --server-side --force-conflicts \
  -f "https://github.com/kubernetes-sigs/gateway-api/releases/download/${GATEWAY_API_VERSION}/experimental-install.yaml"

# ---- 4. Install Istio with AGENTGATEWAY feature flag ----
# AgentGateway support requires Istio 1.30+ (currently alpha). The default
# istioctl hub for alpha builds points to registry.istio.io/testing which
# doesn't publish images publicly, so we default to docker.io/istio which
# mirrors the release images.
ISTIO_HUB="${ISTIO_HUB:-docker.io/istio}"

install_istio_from_release() {
  echo "==> Installing Istio (ambient profile) from hub=${ISTIO_HUB}..."
  istioctl install --context "${KUBE_CONTEXT}" -y \
    --set profile=ambient \
    --set hub="${ISTIO_HUB}" \
    --set values.pilot.env.PILOT_ENABLE_AGENTGATEWAY=true \
    --set meshConfig.accessLogFile=/dev/stdout
}

install_istio_from_source() {
  local istio_dir="$1"
  echo "==> Building Istio from source at ${istio_dir}..."

  pushd "${istio_dir}" > /dev/null

  # Build istioctl
  echo "    Building istioctl..."
  make build-istioctl

  # Build pilot (istiod) image
  echo "    Building pilot image..."
  make docker.pilot

  # Build ztunnel image (required for ambient mode)
  echo "    Building ztunnel image..."
  make docker.ztunnel || echo "    Warning: ztunnel build failed, using pre-built image if available"

  # Determine the built image tags.
  # Istio Makefile sets HUB and TAG; default HUB is localhost:5000 for local builds.
  local hub
  local tag
  hub=$(grep -m1 '^HUB ' Makefile.core.mk 2>/dev/null | awk '{print $NF}' || echo "")
  tag=$(grep -m1 '^TAG ' Makefile.core.mk 2>/dev/null | awk '{print $NF}' || echo "")

  # Use the output binary and image from the build
  local istioctl_bin="out/linux_$(go env GOARCH)/istioctl"
  if [ ! -f "${istioctl_bin}" ]; then
    istioctl_bin="out/$(go env GOOS)_$(go env GOARCH)/istioctl"
  fi

  if [ ! -f "${istioctl_bin}" ]; then
    echo "ERROR: istioctl binary not found after build"
    popd > /dev/null
    return 1
  fi

  # Load the pilot image into kind
  echo "    Loading pilot and ztunnel images into kind..."
  local pilot_image
  if [ -n "${hub}" ] && [ -n "${tag}" ]; then
    pilot_image="${hub}/pilot:${tag}"
  else
    # Try common default
    pilot_image="istio/pilot:latest"
  fi

  # Try to load, but the image may be named differently depending on build mode.
  # Use docker images to find the actual tag.
  local actual_image
  actual_image=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep 'pilot' | head -1 || echo "")
  if [ -n "${actual_image}" ]; then
    pilot_image="${actual_image}"
  fi

  kind load docker-image "${pilot_image}" --name "${KIND_CLUSTER_NAME}" 2>/dev/null || true

  # Load ztunnel image
  local ztunnel_image
  ztunnel_image=$(docker images --format '{{.Repository}}:{{.Tag}}' | grep 'ztunnel' | head -1 || echo "")
  if [ -n "${ztunnel_image}" ]; then
    kind load docker-image "${ztunnel_image}" --name "${KIND_CLUSTER_NAME}" 2>/dev/null || true
  fi

  echo "    Installing Istio (ambient profile) with istioctl..."
  "${istioctl_bin}" install --context "${KUBE_CONTEXT}" -y \
    --set profile=ambient \
    --set values.pilot.env.PILOT_ENABLE_AGENTGATEWAY=true \
    --set meshConfig.accessLogFile=/dev/stdout \
    --set hub="${hub}" \
    --set tag="${tag}"

  popd > /dev/null
}

# Determine Istio install method.
if command -v istioctl &>/dev/null; then
  ISTIO_VERSION=$(istioctl version --remote=false 2>/dev/null || echo "unknown")
  echo "==> Found istioctl version: ${ISTIO_VERSION}"
  # If istioctl is 1.30+ or a dev build, use it directly.
  install_istio_from_release
elif [ -n "${ISTIO_PATH}" ] && [ -d "${ISTIO_PATH}" ]; then
  # User provided an Istio source checkout.
  install_istio_from_source "${ISTIO_PATH}"
else
  # Clone and build Istio from master.
  echo "==> istioctl not found and ISTIO_PATH not set."
  echo "    Cloning istio/istio master to build from source..."
  ISTIO_TMP="$(mktemp -d)"
  trap "rm -rf '${ISTIO_TMP}'" EXIT
  git clone --depth 1 https://github.com/istio/istio.git "${ISTIO_TMP}/istio"
  ISTIO_PATH="${ISTIO_TMP}/istio"
  install_istio_from_source "${ISTIO_PATH}"
fi

# Wait for istiod to be ready
echo "==> Waiting for istiod..."
kubectl --context "${KUBE_CONTEXT}" rollout status deployment/istiod -n "${ISTIO_NS}" --timeout=120s

# ---- 5. Deploy demo namespace and services ----
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
  --set "istio.enabled=true" \
  --wait

# ---- 7. Apply kontxt CRD instances ----
echo "==> Applying kontxt CRD instances..."
kubectl --context "${KUBE_CONTEXT}" apply -f "${SCRIPT_DIR}/manifests/kontxt-platform.yaml"

# ---- 8. Wait for controller to reconcile CRDs ----
echo "==> Waiting for controller to reconcile CRDs..."
kubectl --context "${KUBE_CONTEXT}" wait --for=condition=available deployment/kontxt-controller -n "${KONTXT_NS}" --timeout=60s
sleep 3
echo "    controller ready"

# ---- 9. Apply gateway and routing with ExternalAuth filters ----
echo "==> Applying gateway, routes with ExternalAuth filters..."
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

# ---- 12. Print test instructions ----
echo ""
echo "============================================"
echo "  Demo deployed successfully!"
echo "  Mode: Istio Ambient + AgentGateway (istiod control plane)"
echo "  Ext Auth: Gateway API ExternalAuth filter"
echo "============================================"
echo ""
echo "To test, port-forward to the gateway:"
echo ""
echo "  kubectl --context ${KUBE_CONTEXT} port-forward -n ${DEMO_NS} svc/demo-gateway-istio-agentgateway 8080:80"
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
