# BUILDER STAGE
FROM rust:1.75-bullseye AS builder

# Install protoc
RUN apt-get update && apt-get install -y protobuf-compiler

WORKDIR /app

# Copy workspace manifest and source trees
COPY Cargo.toml .
COPY Cargo.lock .
COPY crates/ crates/
COPY proto/ proto/

# Build the kaalform binary
RUN cargo build --release -p kaalform --bin kaalform

# FINAL RUNTIME STAGE
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /app/target/release/kaalform /usr/local/bin/kaalform

# Default port for MCP Gateway
EXPOSE 7070

ENTRYPOINT ["kaalform"]
