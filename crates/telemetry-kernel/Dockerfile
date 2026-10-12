# BUILDER STAGE
FROM rust:1.75-bullseye AS builder

# Install protoc
RUN apt-get update && apt-get install -y protobuf-compiler

WORKDIR /app

# Copy the entire workspace
COPY Cargo.toml .
COPY crates/ crates/
COPY proto/ proto/

# Build the telemetry kernel
RUN cargo build --release -p telemetry-kernel

# FINAL STAGE
FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the compiled binary
COPY --from=builder /app/target/release/telemetry-kernel /usr/local/bin/telemetry-kernel

# Ensure IPC directory exists (mounted via volume)
RUN mkdir -p /tmp/kaaladrishti_ipc

ENTRYPOINT ["telemetry-kernel"]
