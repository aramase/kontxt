FROM golang:1.26-alpine AS builder
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_DATE=unknown
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags "-X github.com/aramase/kontxt/internal/version.Version=${VERSION} -X github.com/aramase/kontxt/internal/version.GitCommit=${GIT_COMMIT} -X github.com/aramase/kontxt/internal/version.BuildDate=${BUILD_DATE}" \
    -o extauth ./cmd/extauth/

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/extauth /extauth
USER 65532:65532
ENTRYPOINT ["/extauth"]
