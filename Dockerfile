# BUILDER STAGE
FROM golang:1.22-alpine AS builder

# Install protoc and dependencies
RUN apk add --no-cache protobuf-dev protoc

# Install Go gRPC plugins
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest && \
    go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code and proto definitions
COPY . .

# Generate Go bindings
RUN mkdir -p generated/go && \
    protoc --proto_path=proto \
           --go_out=generated/go --go_opt=paths=source_relative \
           --go-grpc_out=generated/go --go-grpc_opt=paths=source_relative \
           proto/kaaladrishti/v1/platform.proto

# Clean up dependencies
RUN go mod tidy

# Build the engine
RUN CGO_ENABLED=0 GOOS=linux go build -o /engine ./cmd/engine

# FINAL STAGE
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary and embedded web assets
COPY --from=builder /engine /usr/local/bin/engine
COPY internal/api/static /app/internal/api/static

# Create data directory for BoltDB and Audit log
RUN mkdir -p /data

EXPOSE 8080

ENTRYPOINT ["engine"]
