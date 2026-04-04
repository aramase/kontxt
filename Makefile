.PHONY: all build test lint clean docker helm

all: test build

# Build
build:
	go build ./...

build-tts:
	CGO_ENABLED=0 go build -o bin/tts ./cmd/tts/

build-extauth:
	CGO_ENABLED=0 go build -o bin/extauth ./cmd/extauth/

build-controller:
	CGO_ENABLED=0 go build -o bin/controller ./cmd/controller/

# Test
test:
	go test ./... -count=1 -race

test-verbose:
	go test ./... -count=1 -race -v

test-coverage:
	go test ./... -count=1 -race -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html

# Lint
lint:
	go vet ./...

# Docker
docker-tts:
	docker build -t ghcr.io/aramase/kontxt-tts:latest -f cmd/tts/Dockerfile .

docker-extauth:
	docker build -t ghcr.io/aramase/kontxt-extauth:latest -f cmd/extauth/Dockerfile .

docker-controller:
	docker build -t ghcr.io/aramase/kontxt-controller:latest -f cmd/controller/Dockerfile .

docker: docker-tts docker-extauth docker-controller

# Helm
helm-lint:
	helm lint deploy/helm/kontxt

helm-template:
	helm template kontxt deploy/helm/kontxt

# Clean
clean:
	rm -rf bin/ coverage.out coverage.html
