.PHONY: all build test test-e2e test-agents-e2e test-agents-istio-e2e lint clean docker helm generate generate-proto manifests verify-codegen helm-package helm-push protoc-gen-go protoc-gen-go-grpc

CONTROLLER_GEN ?= $(shell which controller-gen)

LOCALBIN ?= $(CURDIR)/bin
PROTOC_GEN_GO ?= $(LOCALBIN)/protoc-gen-go
PROTOC_GEN_GO_GRPC ?= $(LOCALBIN)/protoc-gen-go-grpc

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X github.com/aramase/kontxt/internal/version.Version=$(VERSION) \
           -X github.com/aramase/kontxt/internal/version.GitCommit=$(GIT_COMMIT) \
           -X github.com/aramase/kontxt/internal/version.BuildDate=$(BUILD_DATE)

all: generate manifests test build

# Build
build:
	go build ./...

build-tts:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/tts ./cmd/tts/

build-extauth:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/extauth ./cmd/extauth/

build-controller:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o bin/controller ./cmd/controller/

# Test
test:
	go test ./... -count=1 -race

test-verbose:
	go test ./... -count=1 -race -v

test-coverage:
	go test ./... -count=1 -race -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# E2E tests (requires Docker + kind)
test-e2e:
	KONTXT_E2E=1 go test -tags e2e ./test/e2e/ -v -count=1 -timeout 10m

test-e2e-keep:
	KONTXT_E2E=1 KONTXT_E2E_KEEP_CLUSTER=1 go test -tags e2e ./test/e2e/ -v -count=1 -timeout 10m

# Agents E2E tests (requires Docker/Podman + kind + helm)
test-agents-e2e:
	KONTXT_AGENTS_E2E=1 go test -tags agents_e2e ./test/e2e/ -v -count=1 -timeout 15m

test-agents-e2e-keep:
	KONTXT_AGENTS_E2E=1 KONTXT_E2E_KEEP_CLUSTER=1 go test -tags agents_e2e ./test/e2e/ -v -count=1 -timeout 15m

# Agents Istio E2E tests (requires Docker/Podman + kind + helm + istioctl)
test-agents-istio-e2e:
	KONTXT_ISTIO_E2E=1 go test -tags agents_istio_e2e ./test/e2e/ -v -count=1 -timeout 20m

test-agents-istio-e2e-keep:
	KONTXT_ISTIO_E2E=1 KONTXT_E2E_KEEP_CLUSTER=1 go test -tags agents_istio_e2e ./test/e2e/ -v -count=1 -timeout 20m

# Lint
lint:
	go vet ./...

# Code generation
generate: ## Generate DeepCopy methods
	$(CONTROLLER_GEN) object paths=./api/...

generate-proto: protoc-gen-go protoc-gen-go-grpc ## Generate Go code from proto definitions
	PATH="$(LOCALBIN):$$PATH" buf generate
	PATH="$(LOCALBIN):$$PATH" buf lint

# Install the protoc-gen-go and protoc-gen-go-grpc binaries pinned in go.mod
# into $(LOCALBIN). hack/tools.go blank-imports both packages so `go install`
# resolves them at the module's pinned versions, giving deterministic
# regeneration regardless of what's on the developer's PATH.
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

protoc-gen-go: $(PROTOC_GEN_GO) ## Install pinned protoc-gen-go into ./bin
$(PROTOC_GEN_GO): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install google.golang.org/protobuf/cmd/protoc-gen-go

protoc-gen-go-grpc: $(PROTOC_GEN_GO_GRPC) ## Install pinned protoc-gen-go-grpc into ./bin
$(PROTOC_GEN_GO_GRPC): | $(LOCALBIN)
	GOBIN=$(LOCALBIN) go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

manifests: ## Generate CRD and RBAC manifests
	$(CONTROLLER_GEN) crd paths=./api/... output:crd:dir=config/crd/bases
	$(CONTROLLER_GEN) rbac:roleName=kontxt-controller paths=./internal/... output:rbac:dir=config/rbac
	cp config/crd/bases/*.yaml deploy/helm/kontxt/crds/
	cp config/crd/bases/*.yaml test/e2e/testdata/

verify-codegen: generate manifests ## Verify generated files are up-to-date
	@if [ -n "$$(git diff --name-only)" ]; then \
		echo "ERROR: Generated files are out of date. Run 'make generate manifests' and commit."; \
		git diff --name-only; \
		exit 1; \
	fi
	@echo "Generated files are up-to-date."

# Docker
docker-tts:
	docker build -t ghcr.io/aramase/kontxt/tts:latest -f cmd/tts/Dockerfile .

docker-extauth:
	docker build -t ghcr.io/aramase/kontxt/extauth:latest -f cmd/extauth/Dockerfile .

docker-controller:
	docker build -t ghcr.io/aramase/kontxt/controller:latest -f cmd/controller/Dockerfile .

docker: docker-tts docker-extauth docker-controller

# Helm
helm-lint:
	helm lint deploy/helm/kontxt

helm-template:
	helm template kontxt deploy/helm/kontxt

helm-package:
	helm package deploy/helm/kontxt --version $(VERSION) --app-version $(VERSION) -d .cr-release-packages/

helm-push:
	helm push .cr-release-packages/kontxt-$(VERSION).tgz oci://ghcr.io/aramase/charts

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html .cr-release-packages/
