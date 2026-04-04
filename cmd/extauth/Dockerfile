FROM golang:1.26-alpine AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o extauth ./cmd/extauth/

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /workspace/extauth /extauth
USER 65532:65532
ENTRYPOINT ["/extauth"]
